# NetGet complete codebase review and follow-up implementation

## Publication and continued audit — 2 October 2026

The user authorized direct commits and pushes to `master` and selected the remaining audit backlog for the next pass. The initial review commit includes 238 validated implementation/test/build/documentation paths plus this report and audit evidence. `PROTOCOL_ROADMAP.md` was changed concurrently by the separate protocol-expansion programme; it appeared in the working-tree inventory but is excluded from this audit commit. Its recorded hash and counts below describe the earlier inventory, not authorship or this commit's scope. The programme's worktrees and pre-existing scratch files are preserved.

The following chapters retain their verification-time statements (including the then-uncommitted state). Publication and subsequent audit results are recorded in this section as work lands.


## Latest audit closure — 2 October 2026

The selected remaining audit backlog is implemented and locally validated. This pass closes all twelve recursive-decoder exceptions, corrects the two stale wrapper exceptions, fixes cancellation/reaping and unpolled peer-task ownership, adds real Windows Job Object fixtures and portable test dependencies, and narrows build-script invalidation. The separate protocol-expansion programme remains outside this audit scope.

**Final validation: 376 successful test executions**, comprising 324 merged-tree regressions, 38 focused audit checks and 14 Node fixtures. The rebuilt WASM package additionally passed **43 synthetic requests**. Strict correctness/suspicious Clippy, formatting, workflow YAML parsing and reachability of 2,371 source/test files passed. No GPUs, GPU probes, real model calls, model downloads or device access were used. The Windows fixtures cross-compile; native Windows execution remains a CI boundary.

The integration preserves the published protocol work at `cf3f6a74` and the signed initial review snapshot `5e3bfa0b`. Publication is authorized to `master`; the final commit and push result is reported separately. The comprehensive implementation chapter is appended below. Exact commands, logs, failure corrections and source hashes are under [audit/2026-10-02](../../audit/2026-10-02/verification-results.json). Earlier chapters retain their historical counts and verification-time publication statements.

Date: 2026-10-01. Base commit: `d34d91c09ee1731ec13eb3977c17344aeda95497`.

## Current result

Implemented the concrete remaining issues and optional improvements identified by the first review. The work includes runtime ownership, protocol correctness, memory/time bounds, configuration migration, full configuration relationships in saved sessions, subprocess cleanup, CPU-only browser validation, packaging checksums, build cancellation, and test infrastructure. Findings that described platform execution gaps or intentional trust boundaries are explicitly resolved as evidence boundaries rather than represented as implemented features or passing tests.

The final local diff contains **239 implementation, test, build and documentation files**, including deletions. **180 of those changed during this follow-up** relative to the recorded first-pass hashes or base commit. Audit documents, generated bundles/build outputs and pre-existing user scratch files are excluded from this count. Changes are local and uncommitted.

**No GPUs, GPU capability probes, real inference, model downloads, production services, deployments or publication were run.** Four agent slots were used: one coordinator and three parallel section owners, with independent cross-review and serialized main-target Cargo builds. Isolated WASM/Windows checks ran independently. Tests used CPU, loopback fixtures, synthetic model responses and owned subprocesses.

**Validation: 424 successful final test executions**, plus **12 CPU-only browser scenarios** and a **43-request synthetic WASM smoke run**. The native result is **324 passed across 41 targets**, with zero outstanding failures. The focused server tests, source/documentation ratchets, virtual-network tests, Node fixtures and build-wrapper tests are included in the total below. This counts executions, not unique newly added tests; earlier reruns are not added again.

The first review inventoried 3,342 tracked files and scanned 811 Rust source files. Its full per-file coverage ledger remains in the historical appendix. Inventory and heuristic review do not prove every branch or protocol correct. The follow-up chapters map every earlier remaining item to its implementation, verification or explicit environment/contract boundary.

## Reading this report

1. Current outcomes, compatibility changes and validation are immediately below.
2. Four complete follow-up chapters explain each implementation and map all earlier remaining/optional items.
3. The current file ledger identifies every changed file and whether it changed in this follow-up.
4. The full first-pass report is retained as a historical appendix. Its old “remaining/deferred” statements are superseded by the current chapters, and its old test totals describe that earlier snapshot.

Structured evidence: [final verification manifest](../../audit/2026-10-01/followup-verification-results.json), [native target results](../../audit/2026-10-01/followup-native-test-results.json), [file hashes and dispositions](../../audit/2026-10-01/followup-changed-files.json), [WASM source/artifact verification](../../audit/2026-10-01/wasm-final-verification.json), and [preserved logs](../../audit/2026-10-01/followup/logs). The exact original summary is also preserved at [first-pass-consolidated.md](../../audit/2026-10-01/first-pass-consolidated.md).

## Principal completed changes

- **Concurrency and ownership:** generation-bearing circuit-breaker permits; resizable FIFO request concurrency; cancelled waiter accounting; scheduled-task execution handles; per-peer cancellation; MCP service lifecycle; startup and restore cleanup scoped to the newly created resources.
- **Persistent configuration:** safe legacy settings migration with exact backup and recovery; bounded regular-file reads; atomic writes; versioned restoration of resources, pipes, easy wrappers and pending schedules with fresh IDs and validated references.
- **Network clients:** bounded buffered HTTP bodies and deadlines; POP3 command/response correlation; VNC challenge authentication; checked wire integers; SMB blocking isolation and native-session ownership; WebRTC cleanup and bounded queues; SSH frame writes that close on interruption and cannot be reused after a partial packet.
- **Servers and runtime:** checked task arithmetic before mutation; validation before restart; shared QUIC/TLS certificate parameter handling; SQLite statement-aware classification and work/output limits; fallible VNC display rendering; global-task-only headless execution.
- **Scripts and eval:** concurrent bounded pipes, whole-operation deadlines, owned process groups/Windows jobs, private RAII Go source directories, bounded async file-backed scripts, bounded interpolation, language-aware entry detection, and distinct harness-error classification for truncated/invalid probe evidence.
- **UI and browser:** render-scoped fonts, bounded glyph/cache/canvas resources and iterative nested windows; stable activity selection/scroll anchors; fold-state pruning; obsolete inactive UI removal; bounded virtual TCP/UDP queues and coherent UDP peek/filter behavior; rebuilt WASM and GPU-disabled synthetic browser coverage.
- **Tooling and distribution:** authenticated archive bytes relative to release SHA256SUMS, streaming download bounds and cleanup; matching release manifest generation/verification; session-owned build cancellation; port-zero discovery; broader CPU and Windows CI; source reachability that handles both new files and working-tree deletions.

## Compatibility changes and operational limits

Settings now live in `~/.netget/settings.json`, alongside `config.toml`. Reading legacy settings does not migrate them. A later write preserves the exact old bytes in `~/.netget-legacy.json`; conflicting backups fail without replacing old settings. This migration was exercised only in temporary homes.

Configured budgets now reject inputs that previously could wrap, allocate indefinitely or hang: oversized bodies/scripts/interpolation/canvas trees, malformed numeric fields, overflowing schedules and excessive SQL work/results. Defaults and precise caps are documented in each chapter. Streaming HTTP chunk access remains streaming; the buffered-response cap applies to aggregate reads.

Saved sessions recreate durable configuration and pending schedules. They do not resume live sockets, peer-specific execution, negotiations or in-flight responses. Script execution remains trusted local execution; process cleanup and output bounds are not a hostile-code sandbox. Checksums verify downloaded bytes against the trusted release/mirror manifest, not an independent publisher signature.

Windows Job Object API/type compilation passed in an isolated crate using the exact source. Full application cross-compilation stopped in `ring` because the host lacks the MinGW C compiler; the NetGet Windows application was not thereby validated. A Windows CI job is implemented but has not run in this workspace. Real GPU/model/hardware, production load, privileged networking, external compatibility and publishing remain unexecuted by design.

## Final validation

| Check | Final result | Evidence |
|---|---|---|
| Native selected regression targets | 324 passed; 41 targets; 0 outstanding failures | Native result manifest and native-final/non-interactive-final logs |
| Focused server filters | 10 passed | TLS/QUIC, DoT, PTY, peer teardown/individual close, proxy certificate cache |
| Source/documentation ratchets | 51 passed; 18 targets | source-ratchets.log plus recursive-decoder-final.log |
| Virtual networking/timer shim | 18 passed | Section report; native in-memory shim tests |
| Node package/composer/Telnet fixtures | 14 passed | npm-tests.log; browser-model-tests.log |
| Python build-wrapper fixtures | 7 passed | Runtime/server report and fixture log |
| Clippy correctness/suspicious gate | Passed across all targets with selected CPU features | clippy.log; pre-existing style warnings remain |
| Broader native feature check | Passed across 46 selected feature gates | check-wide-final.log; compile only for optional device/native protocols |
| WASM build | Passed; 839 input hashes stable through build/smoke | wasm-final-verification.json |
| WASM Node smoke | Passed, 43 synthetic requests | wasm-smoke-final-snapshot.log |
| GPU-disabled Chromium fixtures | Passed, 12 scenarios | browser-cpu-final.log; DOM/xterm fixtures, no real model/GPU or screenshots |
| Exact Windows ProcessGroup source | Cross-compiled successfully | windows-process-fixture.log; runtime execution not claimed |
| Full Windows application | Blocked before app compilation by missing MinGW GCC | windows-rustup-check.log; Windows CI job added |
| Formatting, reachability, syntax, workflow YAML and diff checks | Passed | final-repository-checks.json/log |

The native feature selection was `tcp,http,dns,udp,redis,mcp-stdio,mcp-http,finger,tls,dot,pty,vnc,torrent-peer,proxy,ssh-agent,webrtc,ftp,nntp,pop3,http_proxy,sqlite,quic,smb-client`. Cargo used locked/offline dependency resolution, disabled defaults, four compile jobs and no GPU/embedded-inference features. Test binaries used 32 test threads where selected. Main-target Cargo invocations were serialized; isolated WASM and minimal Windows builds used separate output directories.

## Failed intermediate attempts and corrections

Intermediate compile attempts caught edits arriving during the parallel work: SQLite feature declarations, a dashboard sequence-ID type mismatch and a removed port-helper reexport. Those were fixed before successful test execution. The first rebuilt WASM smoke also exposed a stack-related memory fault; moving 8 KiB async scratch buffers to heap storage removed it, and multiple rebuilt full smoke passes confirmed the fix.

The expanded native run passed 323 tests and failed one pre-existing `--run-for` timing fixture at 4.0318 seconds. The fixture included initialization time in a bound intended for the active run interval. The final correction and targeted rerun are recorded with their exact evidence; the initial result remains preserved. No failing implementation result is counted as passed merely because another unrelated test passed.

The recursion ratchet required removal of three obsolete scripting exceptions because those functions now have explicit bounds. Its remaining exceptions were not widened. Clippy identified a duplicated child-guard module; the test now imports the shared registry once. The affected ratchet and full lint gate passed after correction.

The reachability script initially handled deleted files during graph comparison but still sent them to the final rustfmt sweep. Both phases now inspect actual existing working-tree files, including new untracked source files. The final full check passed without reintroducing dead-module allowlist entries.


---

# Follow-up chapter: Shared core and test infrastructure

# Shared core and test infrastructure follow-up — 2026-10-01

This chapter implements the remaining concrete findings from `core-review.md` and `test-infrastructure-review.md`. Their inventories and first-pass results remain historical evidence. The current disposition is recorded here and in the consolidated report. Work used local CPU builds, fixture processes, loopback services and synthetic model responses. No GPU, GPU capability probe, inference runtime, model download, production endpoint, package publication, commit or push was run.

## Original shared-core findings

| Original finding | Implementation and resulting behavior | Verification |
|---|---|---|
| 1. Concurrent/cancelled circuit-breaker probes | `acquire` returns a borrowed RAII permit. Only one half-open probe can exist. Dropping a probe releases its ownership and restarts cooldown. Outcomes carry a generation, so an old request cannot reverse a later trip or reset. Ollama request paths keep the permit through the operation and report its outcome. Counters saturate; retained diagnostic text has a UTF-8-safe byte cap. | Concurrent 16-contender probe test, cancellation/reacquire, stale success/failure generations, existing circuit-breaker and configuration tests. |
| 2. Replacing the limiter semaphore creates overlapping permit pools | One adjustable FIFO concurrency gate retains all outstanding permits across configuration changes. Shrinking waits for old permits to leave; growing wakes the queue. Queued futures remove themselves on cancellation. User wait accounting also uses an RAII slot. Existing token budget recheck remains after permit acquisition. | Hold two permits, shrink to one, queue and cancel, then grow to two; verify capacity and queue progress without discarding existing ownership. Existing queue/token/window tests remain. |
| 3. Conversation metadata exceeds content caps | Limit message count, serialized action metadata, tree depth/node count, tool name size, and protocol-documentation identifiers/count. Shared iterative JSON preflight rejects oversized/deep metadata before expensive serialization, and iterative destruction avoids recursive-drop overflow. All shared-state documentation-marking paths use the same bounds. | Huge action value, 2,000-level constructed value, oversized tool names, malformed identifiers, and protocol count regressions. |
| 4. HTTP responses and racing file growth allocate without a consistent bound | Reused native FetchClient streaming body collectors with aggregate byte limit and whole-body deadline for tools, model selection, model responses, and errors. File reads open a descriptor, verify regular-file metadata, then read at most limit+1 bytes and reject growth. Unix opens are nonblocking to reject FIFOs without a writer; async callers use the blocking pool under a deadline. | Client body-size/trickle/deadline regressions and file exact-limit/over-limit tests. No remote model/search endpoint is needed. |
| 5. Legacy settings file conflicts with the configuration directory | Settings now write `~/.netget/settings.json`; NetGetConfig retains `~/.netget/config.toml`. Legacy settings remain readable without mutation. The first explicit save/migration uses a cross-process lock, private staging directory, exact backup `~/.netget-legacy.json`, fsync and rename. Conflicting backups fail without replacing data; interrupted installation can recover from the backup. | Temporary-home migration, exact backup, coexistence, eight concurrent migrators, conflicting backup, and recovery fixtures. Real user home configuration was not migrated. |
| 6. Saves are non-atomic and omit pipes, easy wrappers and tasks | Atomic sibling staging replaces complete files. Versioned restore records retain old resource keys, validate all shapes/references first, create fresh runtime IDs and remap pipe/wrapper/task ownership. Server/client scoped tasks and global pending tasks are preserved with remaining recurring count and relative delay. Simple legacy action arrays remain accepted. | Existing save/load round trips plus versioned resource/pipe/task reconstruction and malformed-reference/action rejection. Failed handshakes clean their registration before returning; cancellation while a handshake has not returned its ID also removes only that newly owned client/task, retaining unrelated resources. |
| 7. Isolated-kill targets obsolete per-session target directories | Build wrappers now register a session-owned supervisor and exact process identity while preserving shared artifact caching. Cancellation validates the owned session/nonce/start identity and addresses its process group instead of matching all Cargo processes or the shared target path. | Seven Python fixture tests use harmless fake builds only. Implementation and complete protocol are described in `followup-runtime-server.md`. |
| 8. GPU, hardware, Windows, browsers and live-service execution gaps | Added CPU-only browser mode, rebuilt WASM, synthetic browser/Node tests, broad native feature compilation, targeted Windows CI and a separate Windows API type check where possible. | Final results distinguish compilation, local execution, CI definitions and unavailable platform execution. No real GPU/model/device or production test is implied. |
| 9. Historical docs/dependency currentness is not established | Updated documentation for changed local behavior and retained original evidence. Only dependencies needed by concrete implementations changed: existing cached DES becomes a direct optional VNC dependency, SQLite enables its existing limits/hooks, and Windows enables Job Object APIs. | Locked/offline builds validate the resulting dependency graph; no speculative dependency upgrade or invented current external claim. |

## Test infrastructure findings

| Original finding | Implementation and resulting behavior | Verification |
|---|---|---|
| 1. Eval stdin could deadlock before the timeout/read loop | Drive stdin writes, stdout/stderr reads and child wait concurrently under one overall deadline. Preserve `hold_stdin`; normal input closes when sent. Child exit, idle completion, timeout and error terminate the owned process group and drain only within the original budget. | A child fills both output pipes before reading a large input; another never reads stdin. Both finish under the harness deadline. A held-input fixture still receives EOF only at cleanup. |
| 2. Probe output retention was unbounded and truncation could corrupt scoring | Retain at most 1 MiB per stream. Set explicit `output_truncated`, append a harness diagnostic and classify the result as harness failure before normal expectation/model scoring. | An excessive-output fixture checks byte caps, truncation flag, deadline and harness classification. |
| 3. Binary discovery assumed colon-separated PATH and ignored executable mode | Use `split_paths`, Windows PATHEXT candidates and regular-file checks; on Unix require executable permission bits. | A file that exists but lacks execution permissions is unavailable. Platform-specific behavior is kept explicit. |
| 4. Live model tests are not ordinary CPU regressions | Preserve affirmative opt-in and all ignored/gated live suites. | Live-model gate regression remains; no live evaluation is claimed. |
| 5. Bind-then-drop port reservations race process startup | Removed `get_available_port`. Use port zero plus actual bound-address discovery, or retain a socket where the protocol fixture needs one. Parse startup messages by server ID and preserve an earlier real port when a later placeholder row arrives; support IPv6. | Pure startup-port parser fixtures plus migrated loopback integration targets. Detailed call-site inventory is in `followup-runtime-server.md`. |
| 6. Timing heuristics and historical helper docs need revalidation | Existing retry deadline and child ownership fixtures remain, startup readiness uses actual bound confirmation, and affected helper/docs paths were updated. | Combined regression and source/documentation ratchets validate the selected changes. No universal timing claim is made for privileged or live suites. |
| 7. Vendor scope does not establish security currency | Preserve documented local Hyper patch scope. | Existing vendor ratchet; no unsupported upstream security assessment. |
| 8. Proto/live peer compatibility was not exercised | Changed generated-code consumers compile under the broader feature check. | No live etcd peer or full external compatibility matrix was run; this is an execution boundary. |
| 9. Prompt definition review cannot establish model quality | Preserve the distinction between static/mock regression evidence and live evaluation. | No model-quality inference from CPU-only tests. |

## API and compatibility details

### Circuit breaker

The permit is tied to its breaker and is consumed by `record_success` or `record_failure`. Administrative breaker methods remain for explicit state management and existing callers, while request code uses the generation-bearing permit. A stale operation may finish normally but cannot overwrite a newer breaker state. Cancellation of a half-open probe returns it to an open cooldown rather than granting simultaneous replacement probes.

### Rate limiter

The concurrency gate owns one `active` count and a FIFO deque of waiter IDs/wakers. Reconfiguration updates its limit without recreating ownership. A queued cancelled future removes only its own entry; a released permit wakes the current head. Token-window limits and the maximum network queue retain their prior semantics. Configuration is applied to subsequent acquisition decisions; already admitted work is allowed to finish, including when the new limit is smaller than the active count.

### File persistence

Temporary files use random exclusive creation and Unix 0600 mode. A failed open never arms a cleanup guard for a file this operation does not own. Atomic writes complete content and sync the file before replacement, then sync the parent on Unix. A pre-rename failure preserves the old destination; an fsync failure after rename may report failure even though the new complete file is installed. Async write workers finish an already-started replace if their caller is cancelled. Regular-file read checks operate on the opened descriptor and reject a growing file after reading at most one extra byte.

Migration is cooperative across NetGet processes using an OS file lock. It rejects malformed legacy JSON, non-object values, non-regular legacy paths and differing existing backups. It retains the exact pre-migration bytes before removing the old file path. This is not a claim to serialize unrelated external programs rewriting the same paths, authenticate hostile parent directories, or interrupt kernel filesystem calls already running on a blocking worker.

### Saved configuration representation

A richer save contains an internal `restore_session` action with version 2, resource records, pipe definitions, easy-wrapper references and global task definitions. Server/client creation uses the same typed management forms as ordinary startup. Resource keys are unique; action values must be objects; pipe endpoints and cycles are validated; easy wrappers must reference exactly one resource of the matching protocol, with one wrapper per resource. Global and scoped schedules are prepared before any startup mutation. The internal restore action is handled before ordinary action parsing and is not added to the model's public action vocabulary.

Restoration recreates configuration and pending schedules. It does not resume live sockets, peer-specific tasks, protocol negotiations, in-flight responses or completed/failed task executions. Those are transient runtime state, not durable configuration. Relative delays are rounded up to avoid executing earlier through serialization; recurring limits retain only their remaining executions. A global-task-only headless restore now keeps the CLI running and ticks until work completes or run limits stop it.

### Eval subprocess ownership

The eval probe shares the scripting process-group helper. Outputs are drained concurrently so a full pipe cannot prevent the input deadline from starting. Owned descendants are terminated during cleanup; Unix code that deliberately creates a separate session can escape a process group, and Windows job assignment happens immediately after spawn. Script processes remain trusted local code. Retained-output limits are parent memory bounds, not an OS sandbox for arbitrary child allocations.

## Independent integration review

A second reviewer inspected the breaker, concurrency gate, restoration and file helpers. Three concrete findings were corrected: scalar saved actions could panic when indexed; an easy wrapper could point at a different protocol; and a staging cleanup guard could be armed before exclusive creation succeeded. Existing versioned restore validation now rejects the first two before startup, and atomic file cleanup begins only after a successful open.

Final native/feature/platform results and exact command arrays are recorded by the consolidated verification manifest. Intermediate failing builds and the initial WASM smoke fault are retained as history and are not passed checks.

## Final integration additions

- Startup now owns new server/client registrations through an RAII guard until it returns the ID; session cancellation cannot lose ownership in the gap between registration and form completion. Explicit failed client startup also removes its registration and scoped tasks before returning an error.
- Eval classification is shared through a pure scorer. Truncated captures receive verdict `error` and failure mode `probe_output_limit`, before matching expectations or diagnosing a model failure. The CPU regression also rejects false execution evidence from malformed output. Existing report totals still count attempted runs, including harness errors; the error verdict remains separately identified.
- The remaining presence-only live-model opt-in in `ollama_model_test` now uses the same affirmative parser as the other helpers. Those live cases were not executed.
- The module reachability check now includes new untracked source files and excludes deleted working-tree files, so local checks see the same eventual module graph without requiring a commit.

- Final lint integration now imports the single shared child-process guard registry in the tool-call test target. The recursion ratchet shrank its exception list by three scripting walkers that now have explicit budgets; no new exception was added.
- The run-limit fixture separates initialization from the active run interval. Its total-duration lower bound remains two seconds, the serving-time upper bound remains four seconds, and the exit wait itself is tightened to four seconds after readiness. The rebuilt five-test target passed; final timing was about 1.907 seconds startup plus 2.233 seconds serving.

---

# Follow-up chapter: Runtime, servers and build ownership

# Runtime and server follow-up — 2026-10-01

## Scope and authorization

This follows the user's request to implement the remaining findings, including optional ones, from [server-review.md](../../audit/2026-10-01/server-review.md) and [runtime-review.md](../../audit/2026-10-01/runtime-review.md). Those reports preserve the original inventory and the distinction between full-tree scans and focused manual review. Their sections describing unfixed issues are historical; the disposition table below supersedes them.

Owned source areas: `src/server/**`, `src/state/**`, `src/cli/**`, and `src/protocol/**`, with focused changes to scheduler call sites in `src/events/handler.rs` and `src/llm/actions/task_actions.rs`. The root agent owns session serialization and documentation-state bounds. The surfaces agent owns the additional scheduler execution-owner token integration with MCP. Source ownership was explicitly transferred at those boundaries to avoid conflicting edits.

A later handoff also assigned the shared Cargo wrappers and the released-port test helper. This report includes that work. No actual Cargo process was cancelled during validation. No GPU, embedded model, real inference service, public network service, raw socket, hardware device, deployment, or commit was used by this work. The wrapper tests cancel only fake Cargo scripts created by their own temporary fixture. Rust validation is centralized by the root agent; this report does not turn an unexecuted test into a passing result.

## Complete original-finding disposition

| Original finding or boundary | Final disposition | Implementation and evidence |
|---|---|---|
| Server S1: SAN/lifetime panics and silent malformed SAN filtering | Implemented in first pass; retained and extended | Shared fallible certificate conversion, checked validity arithmetic, strict SAN arrays. Initial TLS certificate regressions retained; QUIC now uses the same extractor. |
| Server S2: DoT partial-body wait could retain a connection indefinitely | Implemented in first pass; retained | Finite body deadline; incomplete DNS-body local TLS regression. |
| Server S3: PTY failure before ownership conversion leaked descriptors | Implemented in first pass; retained | Immediate RAII ownership; invalid-link-path descriptor regression. |
| Server S4: detached shared peer command workers survived server removal | Implemented and extended | Workers now belong to individual peer IDs and are aborted on peer close or server removal. Both cancellation paths have a blocked-write regression. |
| Server S5: MITM certificate cache had no cardinality bound | Implemented in first pass; retained | Existing expiry/eviction behavior plus maximum 1,024 leaf certificates; cache-bound regression. |
| Server remaining 1: every E2E, device and real-model mode not executed | Concrete execution boundary | Exact CPU-safe targets were selected. Real-model, hardware, privileged packets and production-load/fuzz campaigns cannot be represented by these local regressions and were not run under the user's CPU-only constraint. No runtime completeness claim is made. |
| Server remaining 2: QUIC filtered invalid SAN entries | Implemented | QUIC calls the mandatory shared TLS parameter extractor; direct spawn rejects mixed, numeric and null SAN array entries before binding. |
| Server remaining 3: closing one peer did not cancel a blocked write | Implemented | Per-peer task registry plus central close/remove integration, including registration/removal race handling. |
| Server remaining 4: contradictory historical documentation | Implemented for identified stale claims and affected paths | TLS/proxy connection-limit descriptions, proxy cache bound, DoT test coverage, QUIC SAN contract, TCP peer ownership and test-port guidance updated. Historical protocol narratives are not recast as proof of runtime correctness. |
| Server remaining 5: source scans cannot prove absence of all bugs | Evidence boundary, not an unimplemented defect | Full original coverage ledger retained. No protocol maturity rating raised and no claim of exhaustive functional verification. |
| Runtime R1: malformed parameter containers bypassed validation | Implemented in first pass; extended | Object-only container/overlay validation plus schema type/required-field preflight and shared TLS material validation before restart. |
| Runtime R2: stored scheduled-task ID differed from map key | Implemented in first pass; retained | Allocation writes the ID into the stored task; lookup/status/removal regression retained. |
| Runtime R3: concurrent timer ticks could select the same task | Implemented in first pass; extended | Atomic claim plus atomic spawn/ownership registration; active runners cannot be reclaimed during final bookkeeping. |
| Runtime R4: max-executions one ran twice | Implemented in first pass; retained | Completion includes the just-finished run; existing deterministic mock regression retained. |
| Runtime R5: log-template values were interpreted again | Implemented in first pass; retained | One-pass regex replacement with literal data and existing control-character sanitization. |
| Runtime R6: legal SQL identifiers broke metadata refresh | Implemented in first pass; retained | Double-quoted identifiers with escaped embedded quotes; in-memory punctuation/Unicode regression retained. |
| Runtime remaining: extreme scheduler delay overflow | Implemented | Fallible checked constructors; all startup/action/update callers validate before mutation; recurring/backoff arithmetic checked. |
| Runtime remaining: running scheduled futures lacked cancellation ownership | Implemented | Handles registered atomically under task ID; task removal and all scope teardown paths abort them. MCP and headless run loops additionally cancel their own executions on owner closure. |
| Runtime remaining: protocol value validation could happen after restart | Implemented where validation is deterministic before resource acquisition | Declared JSON shape, required fields, task definitions, event handlers and shared TLS material checked first. Actual listener/device acquisition remains a spawn-time operation; availability can change after preflight. |
| Runtime remaining: optional native libraries, hardware and all feature permutations | Concrete execution boundary | No optional device or privileged library probe was invoked merely for review. Native CPU and wasm checks are coordinated by root; the final validation report records exactly what compiled and ran. |
| Runtime remaining: SQL prefix classification and unbounded results | Implemented | Prepared-statement metadata, one-statement enforcement, row/value/SQL/result/work/time limits and cleanup of the progress handler. |
| Runtime remaining: optional easy-client implementation and trusted JSON fields | Implemented | Both client and server generated actions use typed normal management forms; typed IDs link the wrapper. Static local client/server regressions cover the dispatch path. |

## Scheduler validation and ownership

`ScheduledTask::new_one_shot`, `new_recurring`, and their connection-scoped constructors now return `anyhow::Result<Self>`. `checked_task_deadline` uses checked addition against the repository clock. A request such as `u64::MAX` seconds is rejected with an error instead of panicking, clamping, or running immediately. Recurring interval zero and execution limit zero are rejected.

`ScheduledTask::from_definition` and `prepare_tasks` provide one conversion for nested definitions. Explicit initial delay is honored for recurring tasks, including task actions that previously ignored it. Nested recurring definitions with no initial delay retain immediate-first-run behavior; their default interval remains 60 seconds.

Server/client startup prepares the complete task batch before allocating the instance. Management update prepares the batch before replacing tasks or restarting an instance. Legacy event-handler startup and standalone task actions propagate constructor errors. Recurring and failure-backoff scheduling also use checked deadlines. Counters saturate rather than overflowing.

`AppState` owns a `scheduled_executions` map separate from serializable task definitions. `spawn_scheduled_task` takes the same state write lock that task removal uses, checks the task is still claimed, and registers its handle atomically with spawning. Removing a previously claimed task prevents it from starting. Removing a running task aborts its future. Server, client, and connection teardown use the same removal helper. Name cleanup checks the alias still belongs to that ID before deleting it, preserving a newer same-name task.

Claiming excludes any still-running handle even if its final bookkeeping already set the definition back to `Scheduled`. This closes the window in which another tick could claim an active runner and leave a claim stranded when registration rejects it. Finished handles are pruned at the next claim.

The surfaces agent added `execute_due_tasks_owned_public`, which applies a cancellation token only to executions launched by that service. MCP teardown preserves configuration and unrelated executions while cancelling its own in-flight work. The headless client/global-task and server loops now use that same owned execution path; exiting the run cancels the token.

The headless path previously returned immediately when a saved configuration contained global tasks and no client/server. It now remains live for `Scheduled` or `Executing` tasks, runs the one-second scheduler ticker, honors run limits, drains task status messages before returning, and also tracks any server/client created by a task. Completed or failed tasks do not by themselves keep the run alive. A restored-global-only binary fixture proves both lifetime and ticker dispatch with an unavailable loopback endpoint, without contacting an actual model.

Regression files:

- `tests/scheduled_task_lifecycle_test.rs`: invalid/extreme delay and zero recurrence; explicit initial delay; removal at task/server/client/connection scope; removed-claim and final-bookkeeping races.
- `tests/scheduled_task_claim_test.rs`: earlier task identity, concurrent claim and one-run mock regressions retained.
- `tests/non_interactive_run_limits_test.rs`: restored global-only configuration remains alive until dispatch, then exits under normal failure/run-limit handling.
- Existing scheduler tests were migrated to the fallible constructor API without changing their assertions: scheduled action vocabulary, server removal, MCP removal and Kafka connection task cleanup.

## Startup validation and easy protocols

`StartupParams::new_validated` supplements the existing accessor-oriented constructor. It validates required parameters and documented JSON types before mutation: strings, booleans, numbers, integers, arrays, objects, supported typed arrays, and unions written with `|` or ` or `. Optional null retains existing absent-value behavior. Descriptive unknown type hints remain subject to protocol-specific parsing instead of inventing a new interpretation.

Server startup and management reuse `validate_server_startup_params`. Where the complete shared TLS parameter schema is present, preflight invokes the common extractor, checking SANs, validity, paired certificate/key paths and parseable material. QUIC uses the required-TLS extractor directly. Malformed parameters no longer stop a working static HTTP instance before failing.

Preflight cannot guarantee that an OS bind will later succeed, that a device remains present, or that a certificate file is unchanged between two reads. Those are actual resource-acquisition boundaries, not skipped deterministic checks. The existing startup rollback still removes failed new resources. No broad guarantee of transactionally atomic protocol restart is claimed.

`execute_easy_startup_action` now handles both `open_server` and `open_client` through `ServerForm`/`ClientForm`. It retains normal handler, initial memory, startup parameter, feedback and scheduled-task behavior. An out-of-range port is rejected by typed deserialization instead of narrowed with `as u16`. `EasyUnderlyingId` returns either a real `ServerId` or `ClientId`, eliminating JSON number casts when linking the easy wrapper. Action-generation failures set the wrapper's error status instead of leaving it in startup.

The client agent confirmed that the currently registered easy implementation generates HTTP server actions; the common metadata/trait contract permits client actions, and the shared executor now supports them. No fictional new easy protocol registration was added.

Regressions:

- `startup_params_result_test::preflight_checks_required_types_typed_arrays_and_unions`.
- `management_test::invalid_types_tls_material_and_task_delays_preserve_running_server` verifies the original static server and ID remain usable after rejected update/create requests.
- `server::quic::certificate_validation_test::quic_rejects_non_string_san_entries` exercises the actual protocol adapter without a socket bind or model.
- `easy_startup_test` verifies local TCP client memory/handler retention, static HTTP server handling, and rejection of port 65,536 before instance creation.

## Cancellation while a new instance is starting

Final integration review identified a gap before a create call returns its newly allocated ID. A client could be registered with scoped tasks and then fail its handshake; the old error path marked it `Error` but returned no ID, so the caller could not roll it back. Cancelling either server or client startup while it awaited protocol work had the same ownership gap. This also affected cancellation of session restore before `form.create` returned.

The shared private `src/cli/startup_guard.rs` guard now takes ownership immediately after `add_server` or `add_client` returns, before the next await. It stays armed through configuration, task registration, protocol startup and final status updates. Successful startup disarms it immediately before returning the ID. Cancellation schedules removal through the active runtime; removal also aborts associated instance workers and scheduled executions. Ordinary client failure explicitly awaits `remove_client` before returning its error, and the existing server failure cleanup retains its awaited removal. A cancelled explicit rollback leaves the guard armed so cleanup is still attempted.

`tests/startup_cancellation_test.rs` adds two VNC-feature regressions. A local peer closing before the RFB greeting makes create fail and verifies cleanup is already complete when the error returns. A peer withholding the greeting holds session restore inside client startup; aborting restore then removes that unreturned registration and its task while preserving a preexisting unrelated client/task. The peer observes EOF, showing the cancelled handshake released its socket. No VNC frame, model, GUI or external service is involved. POP3 was considered as a barrier but rejected after confirming its greeting is handled in a background task rather than inside the create future.

A trivial unnecessary `mut` in `src/server/dc/mod.rs` was also removed after the wide native check identified the warning.

## Individual peer cancellation

`AppState` records peer worker handles by `(ServerId, connection_id)`. `spawn_peer_command_task` registers its worker in that map. Registration checks the server and peer handle still exist; if close won the race, the worker is aborted immediately.

`remove_peer_handle`, central connection close, central connection removal, and server cleanup all release the corresponding worker handles and abort pending operations. Closing a command channel alone was insufficient when a worker was already awaiting a blocked write; explicit abort now releases the writer and pending command reply.

The TCP peer lifecycle fixture supplies an intentionally blocking writer and checks its drop signal. It exercises both full server removal and individual peer close; the second test verifies the server remains present. No peer traffic or model call is necessary to establish cancellation.

## SQLite query boundaries and classification

Query dispatch no longer guesses from text prefixes. It prepares one statement, rejects a second statement before execution, uses `column_count` to detect row-producing statements, and uses `readonly` to decide whether metadata needs refreshing. Leading comments, CTEs, `REPLACE`, `RETURNING`, and query-producing PRAGMAs follow SQLite's actual statement behavior.

Named limits are enforced in `src/state/sqlite.rs`:

| Limit | Value | Enforcement |
|---|---:|---|
| Returned rows | 10,000 | Checked before appending the next row. |
| Aggregate result budget | 8 MiB | Conservative JSON byte estimate checked before copying each value. |
| SQLite value/row allocation | 8 MiB | SQLite `SQLITE_LIMIT_LENGTH`. |
| SQL text | 1 MiB | SQLite `SQLITE_LIMIT_SQL_LENGTH`. |
| VM work | 10,000,000 steps | SQLite progress callback, checked every 1,000 steps. |
| Query duration | 5 seconds | Same progress callback checks elapsed time. |

SQLite engine limits run before a huge `zeroblob`/text value is copied into Rust. Text accounting includes a conservative escape allowance and BLOB accounting includes hexadecimal expansion. The progress callback is cleared after both success and error so a cancelled query does not poison the next one. Limit-installation errors are propagated with context.

A modifying statement can commit changes before its `RETURNING` rows exceed the result budget. Error messages state that possibility; this API has not silently wrapped arbitrary caller SQL in a new transaction. Query interrupts have SQLite's normal transaction behavior. Metadata refresh follows successful mutations, including CTE-prefixed mutations.

`tests/sqlite_query_bounds_test.rs` covers statement classification/metadata, row and byte limits, oversized engine values, an unbounded recursive CTE interrupted by the work budget, recovery on the next query, and rejection of multiple statements before a DDL side effect. All databases are in memory. Root enabled the `rusqlite` `limits` and `hooks` dependency features.

## Bounded canvas integration

The surfaces agent made display rendering fallible with pixel/command/text bounds. The VNC server now calls `DisplayCanvas::try_render` inside its blocking renderer and propagates failures instead of treating the compatibility wrapper's empty image as a real frame. The BGRX output buffer uses fallible reservation before expansion. Display limit regressions and VNC feature validation are in the central test handoff.

## Safe cancellation for shared Cargo targets

The obsolete `cargo-isolated-kill.sh` found builds by old isolated target directory names and process text. That no longer matched the shared-target wrapper and could not safely distinguish sessions.

The wrappers now launch Cargo through `scripts/cargo_session.py`. The supervisor starts its child in a dedicated process group and records a private session entry under `tmp/cargo-sessions`. Each entry includes the caller PID plus process start identity, supervisor identity, canonical repository root, private Unix-socket path, random token, command and target directory. Linux identity includes boot identity and kernel start ticks. Darwin reads microsecond process start time from `PROC_PIDTBSDINFO`; second-resolution `ps` timestamps are insufficient for rapid PID reuse.

The cancellation command filters registry entries by live caller identity and repository, then sends the random token to the private socket. It never signals a PID discovered from a JSON record or a process listing. Only the original supervisor signals its own child process group. During cancellation escalation it retains the unreaped child until after signalling, avoiding reuse of the group identifier between checks. Stale or fabricated records can fail socket IPC; they cannot direct `kill` at an unrelated PID.

`CARGO_SESSION_PID` can explicitly tie several wrapper invocations to a live shell; by default it inherits the caller. `cargo-isolated.sh` exports it before delegating to `cargo.sh`. `cargo-isolated-kill.sh --list` is read-only, the default cancellation path asks before sending, and `--yes` supports explicitly automated cancellation. Shared target/cache behavior and Cargo exit status are retained. Log filenames include both session and wrapper IDs to avoid parallel log collisions.

Registry directories and records must be owned by the current user and private. The short private socket directory avoids Darwin Unix-socket path-length failures in deep checkouts. Missing process-identity access fails closed. The scripts require Python 3 on a POSIX host, consistent with the shell wrappers; native Windows process-group cancellation is not represented by this Unix IPC design.

Validation: `python3 tests/build_scripts_test.py` passed **7/7** after the final supervisor changes. This included shared-target isolation, stale/fabricated PID records, Cargo failure propagation, argument preservation, wrapper selection, legacy cleanup and private literal credential generation. The local process-inspection/socket fixture required a sandbox escalation, which was approved. No real Cargo build was a cancellation target. `bash -n cargo.sh cargo-isolated.sh cargo-isolated-kill.sh` passed.

## Race-free ephemeral test ports

`get_available_port` bound a temporary TCP listener, read its port, and dropped the socket before NetGet used the number. That introduced a race under parallel execution and did not reserve a UDP port at all.

The common helper and re-export are removed. `{AVAILABLE_PORT}` now becomes `0`; the actual server owns its OS-assigned socket from bind onward. The shared startup parser consumes canonical server-ID/address messages, accepts IPv4 and IPv6, merges duplicate start confirmations, and preserves a nonzero bound port when a later direct-start acknowledgement has no address. It no longer assigns a random listening message to the most recent zero-port server. Socketless protocols still retain their explicit startup record.

All Rust call sites were audited and migrated:

- The shared live-LLM helper requests port zero and reads the actual `NetGetServer.port` before protocol traffic. Its live-model gate is unchanged; it was not run.
- Four SNMP behavior tests and the SNMP failure-path test request port zero and send UDP traffic to the reported port.
- LLMNR requests port zero and uses the server's actual port for both UDP and TCP.
- The IGMP client fixture records the retained UDP socket's `local_addr` port from its mocked connected event before sending multicast. It no longer attempts to protect UDP with a released TCP reservation. This platform-dependent multicast test was not run here.
- Two MySQL tool-call and two web-search HTTP tests now use the managed shared startup helper and the resulting server port instead of duplicate bind/drop helpers and fixed startup sleeps. Existing explicit real-model opt-in/ignore annotations remain. None was executed during this review.
- Guidance under `tests/README.md` and the affected protocol `CLAUDE.md` files now describes port-zero discovery.

`tests/harness_port_allocation_test.rs` verifies startup confirmations arriving out of order, duplicate IDs, IPv6, invalid addresses, socketless startup, and retained local ephemeral listener ownership. The parser module is pure standard-library code, making the parsing regression independently testable. All Rust `get_available_port` definitions and callers are absent after this migration.

## Validation handoff and final review

All edited Rust files were individually formatted with `rustfmt --edition 2021 --config skip_children=true`. Shell syntax and full-worktree `git diff --check` passed at the final local checkpoint. The accumulated scheduler, ownership, schema, TLS, easy, SQLite, startup parser, wrapper and headless-loop diffs were re-read for introduced regressions. Review specifically checked claim/spawn/remove ordering, alias cleanup, callback lifetime, early/duplicate startup confirmation behavior, process identity reuse, and retention of model test gates.

New follow-up Rust test functions owned by this section: four scheduler lifecycle, four SQLite bounds/classification, two easy dispatch, one required/type preflight, one management preflight, one QUIC SAN, one individual-peer close, two harness port tests, one restored-global headless test, and two startup cancellation/error tests. That is **19 new follow-up functions**, in addition to the 15 first-pass server/runtime functions. Existing test migrations are not counted as new tests. Cross-agent MCP/display/session tests are reported by their owners and not double-counted here.

Additional targets handed to root:

| Target/filter | CPU feature requirement | Execution boundary |
|---|---|---|
| `scheduled_task_lifecycle_test` | none | State, futures, local runtime only. |
| `sqlite_query_bounds_test`, `sqlite_identifier_test`, `sqlite_test` | `sqlite` with `limits,hooks` | In-memory SQL. |
| `easy_startup_test` | `tcp,http` | Static loopback client/server. |
| `startup_params_result_test` | none | Pure JSON schema/accessors. |
| `management_test` | `http` plus shared TLS feature in union | Static loopback server; invalid updates. |
| `server` filter `quic_rejects_non_string_san_entries` | `quic` | Rejects before bind. |
| `server` filter `peer_lifecycle_test` | `tcp` | Controlled blocked writer. |
| `startup_cancellation_test` | `vnc` | Local handshake failure/cancellation; no model or framebuffer. |
| `harness_port_allocation_test` | none | Pure parser plus retained loopback listeners. |
| `non_interactive_run_limits_test` | `tcp` | Child binary, static handlers, unavailable loopback model URL. |
| `build_scripts_test.py` | Python 3/POSIX | Temporary fake commands/process groups; 7/7 passed locally. |

Root's final validation report is authoritative for centralized Cargo results. This file records implemented behavior and concrete evidence boundaries, not blanket success across the full protocol matrix.

## Final evaluation-harness handoff

The client agent completed a pure scoring extraction while ownership was transferred for final integration. `tests/eval/scoring.rs::score_probe` is shared by the live runner and the new CPU-only `eval_probe_classification_test`. Output exceeding the capture cap is assigned verdict `error` and failure mode `probe_output_limit` before expectation matching or model diagnosis. This prevents both a false pass from a matching retained prefix and a misleading model-failure verdict. The runner retains its existing client-output, command, exit, timing, executed-action and model-evidence fields.

Final review added evidence-retention coverage and found the analogous invalid-regex path: the classifier already named it `harness_error`, but the runner still gave it verdict `fail`. The pure scorer now gives `HARNESS:` expectation errors verdict `error`. Four pure regressions cover cap precedence for matching and mismatching prefixes, ordinary pass/fail behavior, rejected action names versus actual execution, and invalid-regex harness errors with evidence. These four collaboration tests are additional to the 19 runtime/server follow-up functions counted above and should be counted once in the combined report.

`tests/ollama_model_test.rs` now calls the shared `real_ollama_requested` helper rather than treating environment-variable presence as opt-in. Existing pure affirmative-opt-in tests cover unset, empty, zero, false, off and misspelled values as disabled. The actual suite was not run against a real endpoint. Both saved-session CLI/startup cancellation fixtures were corrected to the implemented session format version 2 before centralized validation.

The surfaces agent reports the final startup guard also passed the isolated WASM rebuild and its 43-request Node smoke; root's validation ledger records those cross-agent results. Final additional native target: `eval_probe_classification_test` (no protocol feature requirement, no subprocess/network/model execution).

## Final repository checks and timer-fixture investigation

The independent final sweep passed **26/26 checks**: eight changed shell syntax checks, three changed Python AST checks, eight changed JavaScript/CJS/MJS syntax checks, all five workflow YAML files (including duplicate-key rejection), full diff whitespace, and module reachability/format inspection. The module graph contains **2,283 Rust files under `src`/`tests`, zero allowlisted and zero unreachable**. Results and per-check output are preserved in `followup/final-repository-checks.json` and `.log`.

The first module-check attempt exposed a check-script bookkeeping defect: its graph inventory excluded deleted files, but its formatting inventory still passed deleted `src/ui/events.rs` and `src/ui/layout.rs` to rustfmt. The formatting inventory now uses existing tracked/new files consistently. Initial failure details remain in the JSON history and `followup/module-format-diagnostic.log`; the corrected check passed.

Root's first final native run produced **323 passing tests and one failure across 41 targets**. The sole failure was the preexisting run-limit fixture's total elapsed bound (4.0318 seconds against `<4`). An exact old-binary rerun reproduced 4.019985 seconds. Two separate static CLI timestamp probes observed 2.1060 and 2.1063 seconds from server readiness to the two-second stop message. The library constructs its run-limit clock inside the noninteractive runner, after process/argument/settings initialization, while the fixture had started its clock before spawning the process. The shared CLI executable was also relinked by root's focused Cargo run between observations, so the old failure and direct timing probes are retained separately rather than presented as the same binary measurement.

Only the fixture changed: it retains the overall two-second minimum, starts the existing four-second upper bound at readiness, tightens its exit wait from twenty to four seconds, and prints startup/serving/total durations. The production timer is unchanged. Investigation evidence is under `tmp/audit-2026-10-01/followup/non-interactive-investigation.json`, with the original failure log and per-line timestamp probes. The rebuilt all-five-test target subsequently passed, as recorded below; the original failure remains preserved separately.

## Final centralized validation results

The fresh `non_interactive_run_limits_test` rebuild and all **5 tests passed** with zero failures/ignored tests. The timer fixture printed `startup=1.907018625s`, `after_ready=2.233383083s`, and `total=4.140402s`, directly demonstrating why startup must be separated from the serving deadline. Its exact locked/offline CPU-only Cargo command, exit code zero, elapsed build/test time and raw log are in `tmp/audit-2026-10-01/followup/non-interactive-final.json` and `.log`. The earlier 323-pass/one-failure manifest was retained rather than overwritten.

Final owned-target outcomes parsed from the centralized native log (the noninteractive row uses the fresh correction result):

| Test target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `scheduled_task_lifecycle_test` | 4 | 0 | 0 |
| `scheduled_task_claim_test` | 8 | 0 | 0 |
| `scheduled_task_actions_test` | 2 | 0 | 0 |
| `sqlite_query_bounds_test` | 4 | 0 | 0 |
| `sqlite_identifier_test` | 1 | 0 | 0 |
| `easy_startup_test` | 2 | 0 | 0 |
| `startup_cancellation_test` | 2 | 0 | 0 |
| `management_test` | 8 | 0 | 0 |
| `startup_params_result_test` | 11 | 0 | 0 |
| `harness_port_allocation_test` | 2 | 0 | 0 |
| `eval_probe_classification_test` | 4 | 0 | 0 |
| `log_template_test` | 10 | 0 | 0 |
| `log_template_injection_test` | 5 | 0 | 0 |
| `server_stop_cleans_scheduled_tasks_test` | 3 | 0 | 0 |
| `non_interactive_run_limits_test` | 5 | 0 | 0 |

All **10 server regressions across six exact filtered invocations passed**: certificate validation (5, including QUIC), DoT partial-body deadline (1), PTY failure cleanup (1), server removal with blocked peer write (1), individual peer close with blocked write (1), and proxy cache cardinality (1). Each command and raw log is indexed by `tmp/audit-2026-10-01/followup/final-check-results.json`.

Root's final 46-feature native library check passed. The final all-target Clippy run passed with `clippy::correctness` and `clippy::suspicious` denied. The recursive-decoder source check passed all 3 tests after root removed three stale allowlist entries whose implementations already had explicit depth bounds. Root also corrected the shared child-guard duplicate module import surfaced during integration. These are integration corrections, not additional protocol runtime claims.

The final **7/7 Python build-wrapper fixture** output is preserved at `tmp/audit-2026-10-01/followup/build-scripts-final.log`, with exact command, exit code zero, 9.229-second test duration, and capture provenance in the adjacent `.json`. This is the captured output of the already-completed final tool run (session 59969), not a new execution or the earlier five-test baseline. No real build was cancelled.

---

# Follow-up chapter: Clients and wire protocols

# Client follow-up implementation and validation map — 2026-10-01

This report follows `client-review.md`. The first report preserves the original inventory of 777 client, easy, pipe, and client-test files and the original findings. This report maps the eleven remaining findings to the subsequent implementation, explains compatibility changes, and identifies what CPU-only checks can establish. It does not replace the original inventory or claim that every protocol received the same depth of review.

All code and tests described here were developed without GPUs, model inference, model downloads, remote protocol services, or device access. The root agent coordinates Cargo builds and test execution; its final validation ledger is authoritative. This reviewer did not start competing Cargo builds. No commits or pushes were made.

## Original finding disposition

| Original remaining finding | Implementation | Evidence and actual boundary |
|---|---|---|
| 1. POP3 reply type guessed from `+OK` wording | Added a command writer that atomically serializes writes with a bounded FIFO of response expectations. Both event-driven and injected commands share it. | Regression checks USER/PASS, LIST/UIDL with and without arguments, RETR/TOP/CAPA, negative replies, unsolicited replies, CRLF injection, and cancellation during a partial write. No real mail server used. |
| 2. VNC type-2 authentication echoes the challenge | Implemented the RFB password-derived DES response, including eight-byte truncation/zero padding and per-byte bit reversal. Password authentication is preferred when a password is supplied and the server offers it. | Independent OpenSSL fixture, truncation, and zero-padding assertions. No remote VNC server or screen capture used. |
| 3. Inconsistent native HTTP response bounds | Both `FetchClient` backends enforce the buffered body policy. Shared bounded reqwest byte/text/JSON helpers also cover direct readers. Body failures are propagated instead of converted into empty successful responses. | Real loopback chunked HTTP response, over-limit buffered error, streaming download preservation, JSON parsing, and Windows-1252 decoding. Browser transport retains its existing whole-body bound. |
| 4. SMB unbounded reads and synchronous work under an async lock | Added an 8 MiB buffered read/write policy and moved native initialization, operations, and destruction onto blocking workers. A lifetime lease protects pavao's process-global native context. | Pure CPU bounded-reader regression; host has a discoverable libsmbclient package. Real credentials/share operations were not exercised. Native blocking calls cannot be forcibly cancelled safely. |
| 5. WebRTC callback ownership, dropped queues, and abort cleanup | Replaced callback self-ownership with weak references, added bounded FIFO draining, propagated a shutdown token into event calls, and introduced an owning peer-close guard. | Regression creates an actual library peer with empty RTC configuration, aborts its owner, and waits for the peer's Closed state. No STUN/TURN service, signaling service, or two-peer data exchange. |
| 6. SSH-agent injected Custom actions do not send packets | Event-driven and injected commands use the same checked SSH packet encoder. An independent registered command task is available while event handling waits for a model/manual action. | In-memory duplex regression observes the exact framed request-identities bytes and the real sent-byte outcome; overflow flags fail. No operator agent or key access. |
| 7. HTTP URL malformed port/userinfo handling | Explicitly reject invalid or empty ports, empty hosts, userinfo, and unescaped ASCII control/whitespace in the shared HTTP transport parser. | Invalid authority cases and valid IPv6 authority/path/query are tested. Native reqwest URLs retain reqwest's semantics. |
| 8. Incomplete-frame timeouts and aggregate reads | Added absolute partial-line/body/frame deadlines for the reviewed text, SSH-agent, VNC, BitTorrent peer, and CONNECT readers, plus relevant greeting/handshake deadlines and native buffered HTTP body deadlines. | Short CPU-only timeout regressions check partial text, explicitly armed frame deadlines, partial torrent headers, and SSH deadlines across cancellation and between polls. These are framing deadlines, not a global idle-disconnect policy. |
| 9. Unchecked binary narrowing | Added shared checked number/byte conversion and applied checked conversions to concrete action/startup fields and outgoing wire lengths listed below. Values that cannot be represented now fail instead of wrapping or disappearing. | Generic boundary regression plus VNC action and SSH packet regressions; feature checks cover other changed gates. Protocol-specific bit packing and casts already protected by bounds were retained. |
| 10. Stale documentation | Updated the affected protocol guides for implemented authentication, correlation, cleanup, bounds, deadlines, native ownership, and truthful command outcomes. | Documentation changes listed below. Historical protocol maturity is not upgraded merely because a module compiles. |
| 11. Hardware/unavailable environment validation | Kept changes testable through pure helpers and local streams and requested native feature checks independently of device access. | Device, privileged networking, browser execution, external interoperability, and runtime-shutdown behavior remain actual environment boundaries, not claims of verified support. |

The optional easy-client execution path was implemented by the runtime/server reviewer in `src/cli/easy_startup.rs`. Its contract accepts existing management forms: `open_server` uses `protocol`/`port`; `open_client` uses `protocol`/`remote_addr`. Startup parameters and event-handler configuration pass through those forms. The existing easy HTTP generator already emits compatible server actions. No additional easy protocol type or invented client metadata schema was necessary in `src/easy`.

## Buffered HTTP response policy

`src/client/http_fetch/mod.rs` now carries the selected body bound through the native request and response wrappers as well as the transport backend. The default remains 8 MiB, and `FetchClient::with_max_body` applies to buffered `bytes()`, `text()`, and `json()` on either backend.

The native helpers are public so callers that own a reqwest response can use the same policy:

```rust
read_response_bytes(response: reqwest::Response, limit: usize) -> Result<bytes::Bytes>
read_response_text(response: reqwest::Response, limit: usize) -> Result<String>
read_response_json<T: DeserializeOwned>(response: reqwest::Response, limit: usize) -> Result<T>
```

These helpers check a declared body length, incrementally account for chunks before appending, and impose a 30-second deadline over the whole buffered read. The text helper preserves reqwest charset/BOM handling by retaining response headers when decoding the already bounded bytes. JSON decoding receives only the bounded complete body.

Native `chunk()` remains streaming and does not acquire a new aggregate download limit. This preserves intentional large-download consumers and their own stream/file policies. The browser/in-memory transport continues to collect its bounded body before exposing chunks. This difference is documented in the shared transport module.

The shared wrapper covers HTTP-family clients that already use it, including package-metadata and OAuth/OIDC paths. Direct MCP reqwest reads now call the shared helper. Bitcoin, HTTP/2, JSON-RPC, WebDAV, and OAuth token parsing now return body/decode failures instead of silently substituting an empty body or null response. Root adopted the helpers in its separately owned LLM tools, model-list, and error-body paths.

Transport URL validation remains scoped to `parse_http_url`. It rejects userinfo rather than silently treating credentials as part of an authority and tells callers to use an Authorization header. Explicit out-of-range, nonnumeric, and empty ports fail instead of defaulting to port 80. Valid IPv6 authority parsing and origin-form path/query are retained. Extension methods retain their exact casing; the seven historically supported standard verbs keep the earlier case-insensitive convenience.

## POP3 command and response ordering

`CommandWriter<W>` owns the writer and its expected response FIFO. A shared mutex makes adding a reply expectation and writing/flushing the matching command one serialized operation across both producers. The queue is capped at 1,024 outstanding commands.

The expectation follows command semantics: RETR, TOP, and CAPA are multiline; LIST and UIDL are multiline only without an argument; other commands are single-line. A negative status consumes the expectation without reading a dot body. The server's prose no longer controls framing. Responses without an expected command fail instead of guessing.

The writer rejects embedded CR/LF, blank commands, and excess outstanding work. It marks itself failed before a write starts and clears that marker only after the write and flush complete. Cancellation or failure can therefore never leave a reusable stream whose queued expectations no longer match what reached the server. Command writes have a 30-second deadline. The existing shared dot reader retains whitespace, removes dot stuffing, bounds retained text, and refuses EOF before the exact terminator.

The reply loop propagates errors through the existing status/handle cleanup path. It does not introduce POP3 pipelining negotiation or new mail semantics; it makes concurrent command producers and received replies agree about the commands that were actually issued.

## VNC authentication and framing

The new `vnc_auth_response` implements the existing RFB password authentication algorithm using the cached `des` crate enabled by the `vnc` feature. It zero-pads or truncates the password to eight bytes, reverses each key byte's bit order, and encrypts each eight-byte half of the server's challenge with DES-ECB. It does not log credentials or retain a fake challenge-echo fallback.

Algorithm behavior was checked against the primary LibVNC implementation and a locally generated OpenSSL DES fixture:

- [LibVNC password/challenge handling](https://raw.githubusercontent.com/LibVNC/libvncserver/master/src/common/vncauth.c)
- [LibVNC OpenSSL DES implementation](https://raw.githubusercontent.com/LibVNC/libvncserver/master/src/common/crypto_openssl.c)

No implementation source was copied. For the ASCII password `password` and challenge bytes 0 through 15, the independently generated expected response is `b866924125c8eebb9debc1db61c538e2`.

The entire handshake has a 30-second deadline. After the initial message-type byte, a binary-frame deadline covers the rest of each message; it is disarmed between frames and during event handling. Existing first-wave text and raw-pixel allocation limits remain. Outgoing clipboard data is capped at 1 MiB, and its wire length is checked. Coordinates and button masks are validated before action results are emitted, preventing a downstream Custom action from receiving already-truncated values.

This is compatibility with the protocol's existing authentication mechanism. It does not add a new VNC security type or claim stronger security for DES-based RFB authentication.

## SSH-agent dispatch, framing, and ownership

`encode_custom_action` is now the single packet construction path used for event results and injected commands. The encoder checks u32 flags and length-prefixed byte strings, refuses oversized messages before sending, and reports actual framed bytes sent. The previous generic Custom-action success without a packet is removed.

The command channel is registered before the connected event. A separately registered command task can send commands even while the event flow waits for a manual action. Event handling snapshots client memory before any model/manual wait. The old unused accumulation state and frame-dropping queue were removed; the serial framed reader and socket backpressure preserve pending frames.

`AgentResponseReader` wraps a length-delimited reader with a progress tracker and an absolute timer. The progress tracker covers the case where the codec consumes all four length bytes internally and its visible read buffer becomes empty while the body is missing. The timer persists when a caller cancels `next()` and resumes it later. An expired timer is checked before a newly completed frame can be accepted, so pausing polls cannot renew or bypass the deadline. Responses remain capped at 1 MiB. Writes have a 30-second deadline.

The default socket remains NetGet's own fabricated-agent socket. This work did not connect to `$SSH_AUTH_SOCK`, enumerate identities, request signatures from an operator agent, or change that safety-sensitive default.

## SMB native ownership and limits

The pavao 0.2.13 source was inspected locally. Its client owns a process-global libsmbclient context, and dropping a client frees that context. Allowing a second independent owner could invalidate the first. NetGet therefore holds a single native-session semaphore lease for the entire native client's lifetime and returns a clear error for a second active SMB session. This is a material compatibility restriction that prevents invalid native ownership with the currently pinned library.

`NativeSmb` retains both the native client and the lease. Its destructor transfers native teardown to a blocking worker and releases the lease only after teardown. Initialization, directory operations, file operations, and teardown run outside Tokio's async workers. Native file handles are created, used, and dropped inside the blocking closure; none crosses a model event await.

`read_file_bounded` reads at most 8 MiB plus one detection byte, returns an error on overflow, and never publishes partial file contents as success. Buffered writes enforce the same cap. Operation errors still generate their error event and are also returned as errors to command callers rather than reported as successful execution. The native client receives a 30-second operation timeout.

Boundaries: the pinned native API returns directory entries as an allocated vector, so this change does not promise a new bound on directory enumeration. A running C-library operation cannot safely be force-aborted; cancellation can leave the blocking operation finishing under the native timeout. No real share, network filesystem, credentials, ACL behavior, or SMB dialect interoperability was exercised. `pkg-config --modversion smbclient` returned `0.8.1` on this host, permitting a native feature check rather than assuming the library is absent.

## WebRTC lifecycle and queues

`PeerConnectionGuard` retains the peer and a cancellation token. Dropping its last owner cancels event work and schedules `peer.close()` on the live Tokio runtime. The command task owns a guard for the client lifetime; setup errors explicitly close and unregister. This gives AppState task abortion a cleanup path instead of relying on a detached task or raw pointer.

Data-channel callbacks upgrade weak references when needed, avoiding the client/channel/callback ownership cycle. Event calls select against the cancellation token so shutdown does not wait indefinitely for a manual/model decision. The active message processor drains its FIFO before returning to idle. The FIFO is bounded by 128 messages and 8 MiB of retained message content; individual incoming messages are capped at 1 MiB. Overflow is reported and closes the channel rather than silently losing queued data. Binary classification uses the library's actual string flag.

The lifecycle test uses a real `RTCPeerConnection` with empty configuration and asserts that aborting the owning task reaches `Closed`. It does not negotiate an ICE connection, use media, or contact STUN/TURN servers. Async close can only run while a runtime exists; abrupt process termination or a fully stopped runtime is outside that guarantee. The existing injected `send_offer` behavior remains explicitly rejected, and stale documentation claiming it was executed has been corrected; adding a new renegotiation command was not part of the identified cleanup defect.

## Framing policies and checked wire values

| Path | Bound/deadline now enforced |
|---|---|
| Shared FTP/POP3/NNTP/CONNECT response line | 64 KiB; 30 seconds after the first byte of a line |
| POP3/NNTP dot response | 8 MiB retained text; one 30-second deadline for the whole body |
| POP3/NNTP greeting | Must begin and complete within 30 seconds |
| CONNECT response head | 64 KiB aggregate; one 30-second deadline over status and headers |
| BitTorrent peer inbound frame | 8 MiB; 30 seconds after first length-prefix byte |
| BitTorrent peer handshake read | 68-byte handshake must complete within 30 seconds |
| SSH-agent inbound frame | 1 MiB; 30-second partial-frame deadline survives cancelled polling |
| VNC handshake and each started server message | 30-second absolute deadline; existing 1 MiB text and 256 MiB raw-rectangle caps |
| Native buffered HTTP body | Selected cap, 8 MiB by default; 30-second whole-read deadline |
| SMB buffered file | 8 MiB; native operation timeout configured to 30 seconds |

Idle connections remain idle where the protocol has no solicited handshake in progress. These changes do not claim to impose a universal timeout on every command, connection attempt, event callback, frame type, or protocol in the repository. FTP's initial idle greeting wait, for example, retains the existing behavior; a started FTP line receives the shared partial-line deadline.

`src/client/wire_values.rs` supplies checked unsigned-field conversion and complete validation of byte arrays. Missing or null optional numeric fields retain their documented default; negative numbers, fractional numbers, wrong types, and values outside the target type fail. Byte arrays must contain only integer values from 0 through 255. Previously filtered invalid entries or narrowing casts could silently construct different packets.

Concrete applications in this follow-up:

| Client | Changed field or length handling |
|---|---|
| MQTT | QoS must fit u8 and be 0, 1, or 2 before creating the action result |
| SSDP | MX is clamped to the existing protocol range before converting to u32 |
| WireGuard | Persistent-keepalive startup value must fit u16 |
| HTTP/3 | Optional action priority must fit u8 |
| ICMP | Identifier/sequence must fit u16; TTL must fit u8 |
| NFS | Read count and mode must fit u32; outgoing write length is checked |
| OpenID Connect | Callback port must fit u16 |
| TURN | Lifetime must fit u32; attribute/message lengths must fit u16; data byte arrays validate every entry |
| UDP and IGMP | Custom byte arrays reject malformed or out-of-range entries |
| gRPC and DNS-over-TLS | Length-prefix conversion checked before writing the wire frame |
| Direct Connect | Maximum reconnect count must fit u32 |
| SNMP | Negative startup timeouts/retries rejected; GETBULK counts checked as u32 |
| Bluetooth and IPP | Characteristic/document byte arrays validate every entry |
| USB | Output byte arrays validate; control-transfer sizes fit u16; rejected validation has an explicit rejected outcome |
| BitTorrent tracker and Ident | Custom port values checked as u16 |
| BitTorrent peer | Message type checked as u8 and outgoing payload/frame length bounded |
| VNC and SSH-agent | Action fields and wire lengths checked as described above |

## Documentation updated

- `src/client/http/CLAUDE.md`: shared buffered body bounds and preserved streaming semantics.
- `src/client/pop3/CLAUDE.md`: command-based response correlation, poisoning after interrupted writes, and deadlines.
- `src/client/vnc/CLAUDE.md`: real DES authentication, framing/pixel policies, checked actions, and handshake timeout.
- `src/client/ssh_agent/CLAUDE.md`: working injected command dispatch, serialized framing, and timeout/cancellation behavior.
- `src/client/webrtc/CLAUDE.md`: owning cleanup guard, weak callbacks, bounded queue draining, and truthful rejected command behavior.
- `src/client/smb/CLAUDE.md`: pinned pavao version, off-thread operations, one-context limitation, file bounds, and cancellation limits.
- `src/client/ftp/CLAUDE.md`, `nntp/CLAUDE.md`, `http_proxy/CLAUDE.md`: actual text/aggregate framing and timeout policy.
- `src/client/torrent_peer/CLAUDE.md`: wire-frame bounds and partial-frame/handshake behavior.

Older descriptions of protocol maturity elsewhere remain historical evidence rather than a promise of testing by this audit. Feature compilation and helper tests alone cannot certify hardware, authentication against external deployments, or browser transport interoperability.

## CPU regression target

`tests/client_followup_test.rs` contains 18 tests when its relevant features are enabled:

1. `wire_values_reject_overflow_and_invalid_array_elements`
2. `http_target_refuses_invalid_explicit_ports_and_userinfo`
3. `bounded_native_response_helpers_keep_charset_and_json`
4. `native_buffered_cap_counts_chunked_body_but_download_chunks_still_stream`
5. `incomplete_text_lines_have_a_deadline_after_the_first_byte`
6. `binary_frame_deadline_excludes_idle_and_completed_event_handling`
7. `pop3_framing_tracks_each_written_command_not_status_wording`
8. `pop3_interrupted_write_poisoning_prevents_wrong_response_correlation`
9. `vnc_des_matches_independent_openssl_fixture_and_password_truncation`
10. `vnc_actions_reject_values_before_custom_results_can_truncate_them`
11. `injected_agent_request_writes_a_framed_packet_and_reports_actual_bytes`
12. `agent_partial_body_deadline_survives_cancelled_next_calls`
13. `agent_expired_deadline_rejects_a_body_completed_between_polls`
14. `peer_partial_headers_have_an_absolute_deadline`
15. `smb_buffered_file_read_refuses_oversize_without_returning_partial_success`
16. `aborted_client_owner_closes_the_webrtc_peer`
17. `agent_incomplete_writes_close_and_poison_the_transport`
18. `agent_write_deadline_covers_lock_wait_without_poisoning_an_untouched_transport`

The first-wave `tests/client_review_regression_test.rs` target remains relevant: it checks the earlier allocation, line/dot framing, HTTP method/driver cleanup, easy Markdown, and pipe fixes. These targets use bounded in-memory data and local loopback sockets. Constructed AppState model URLs use an unreachable local port and are never invoked by these tests.

Suggested focused test invocation, to be run only by the root coordinator through the repository's normal CPU-safe Cargo environment:

```sh
cargo test --offline --no-default-features --features 'http,ftp,nntp,pop3,http_proxy,vnc,torrent-peer,ssh-agent,webrtc,smb-client' --test client_followup_test --test client_review_regression_test
```

Changed-gate check union supplied to the root coordinator:

```text
http,http2,http3,http_proxy,bitcoin,jsonrpc,mcp,webdav,oauth2,openidconnect,pop3,nntp,vnc,torrent-peer,ssh-agent,webrtc,mqtt,ssdp,wireguard,icmp,nfs,turn,udp,grpc,dot,dc,igmp,snmp,bluetooth,ipp,usb,torrent-tracker,ident,smb-client
```

This reviewer ran targeted rustfmt on changed files and `git diff --check` on owned source/test paths, which passed. At this report's creation, root's broad native check and final test runs were in progress. An added test is not recorded here as passing merely because its source exists. Exact feature exclusions, platform build failures, final counts, and command logs belong to the root's final validation ledger.

## Integration cross-review

At the parent's request, this reviewer also read the latest root-owned circuit-breaker lease/generation logic, resizable FIFO rate-limiter gate, session restore, and native file I/O changes without editing those files. No concrete FIFO resize/cancellation or breaker generation regression was found in that read-only review. Three targeted findings were sent to the root for ownership-preserving follow-up:

- Validate that a saved resource action is an object before mutating `action["protocol"]`; scalar/array JSON can otherwise panic in serde_json's string index mutation.
- Validate that an easy wrapper's referenced resource protocol matches its declared underlying protocol, in addition to validating registry metadata and resource existence.
- Install atomic-file cleanup ownership only after `create_new` succeeds, so a failed open cannot remove a file the writer never created.

The root's final diff and validation record determine those findings' ultimate disposition. No shared Cargo, LLM, utility, session, or runtime ownership files were edited by this reviewer during that integration review.

## Windows validation handoff

The root requested an independent Windows compile check after the client work stabilized, using the installed `x86_64-pc-windows-gnu` target, CPU-only `tcp,http` features, two build jobs, debug info disabled, offline resolution, and the isolated target directory `/private/tmp/netget-audit-windows-20261001`.

The initial command selected `/opt/homebrew/bin/rustc` through PATH. That Homebrew sysroot did not include the Windows standard library, although rustup listed the target under its separate stable toolchain. It failed with E0463, `can't find crate for core`. The exact log is `tmp/audit-2026-10-01/windows-check.log`.

The check was rerun using the already installed rustup Cargo and rustc explicitly:

```sh
env CARGO_TARGET_DIR=/private/tmp/netget-audit-windows-20261001 \
  RUSTC=/Users/matus/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc \
  RUSTC_WRAPPER= CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 \
  /Users/matus/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo \
  check -p netget --lib --no-default-features --features tcp,http \
  --target x86_64-pc-windows-gnu
```

The second attempt compiled Windows Rust dependencies, then exited 101 in the `ring 0.17.14` native build script because `x86_64-w64-mingw32-gcc` is absent. The exact log is `tmp/audit-2026-10-01/windows-rustup-check.log`. No compiler or target was installed, no speculative cross-compilation workaround was attempted, and the main target directory was not used. **NetGet's Windows ProcessGroup and atomic configuration paths were not reached by this local check and are not recorded as compiled or executed.**

Per the root's fallback instruction, a distinct `windows-resource-checks` job was appended to `.github/workflows/ci.yml`. It runs on `windows-2022`, uses stable Rust and Node 22, and disables default features:

- Rust targets: `core_followup_test`, `llm_rate_limiter_test`, and `llm_config_test`, with `tcp,http` features. This builds the Windows library path and executes portable configuration/concurrency regressions; it does not execute Unix descendant-process tests.
- Node targets: `tests/npm_launcher_test.cjs` and `tests/npm_download_test.cjs`, using harmless local fixtures. The existing Unix shell-cache and Unix signal cases explicitly skip on Windows; the remaining launcher/archive behavior runs on Windows.

This job is added coverage, not a claimed CI result: it was not dispatched or executed from this session. No Windows source change was justified by the dependency-toolchain blocker.

### Isolated Windows ProcessGroup compile evidence

After the full-package blocker, the root authorized a dependency-minimal fixture. This reviewer coordinated it with the surfaces reviewer, who created `/private/tmp/netget-windows-process-fixture-20261001`, imported the exact repository `src/scripting/process_io.rs` source, and checked it for `x86_64-pc-windows-gnu` using the installed rustup compiler. Direct versions were pinned to Tokio 1.48.0, UUID 1.18.1, and windows-sys 0.61.2. The fixture avoids ring and does not modify the main workspace or its target.

The fixture **passed** in 6.89 seconds. This verifies the Windows Job Object API signatures and the exact module's Rust type checking. It emitted dead-code warnings expected from an isolated fixture and an unused-mut warning for a builder whose mutation is Unix-only. No source change was necessary. Log: `tmp/audit-2026-10-01/followup/windows-process-fixture.log`. This is cross-compilation evidence, not execution on Windows, and it does not compile the rest of NetGet or its Windows atomic-file paths.

### Restore startup ownership review

A later read-only review confirmed a gap below `RestoreOwnership`: forms return a resource ID only after startup finishes, while the startup functions register the resource before awaiting memory updates, task registration, protocol startup, and final status updates. Cancellation during those awaits can leave the new resource absent from the outer restore guard. Client startup also retained its newly registered error row on an ordinary connection error, so failed restore could leak that row and its scoped tasks without cancellation. The server error branch removes its row, but cancellation can bypass or interrupt that branch.

The recommendation sent to both the root and runtime/server reviewer was a startup ownership guard installed immediately after `add_server`/`add_client` returns, armed until the final successful return, with awaited cleanup on ordinary errors and asynchronous drop cleanup on cancellation. AppState's add methods mutate and return without another await, so installing the guard immediately afterward does not introduce an extra cancellation window. Rollback must not infer ownership from before/after ID sets, which could accidentally include unrelated concurrent creations.

A deterministic CPU regression was proposed and then corrected after checking the complete startup path: restore a VNC client against a local peer that accepts but withholds its RFB greeting, wait until the resource is registered, cancel restore, and assert removal of that resource and scoped tasks while preserving a preexisting unrelated resource. VNC handshaking runs inline before create returns; POP3 greeting handling runs in a background task and would not provide the required startup barrier. EOF from the controlled VNC peer tests ordinary failure without relying on a released-port race. The runtime/server reviewer implemented the shared startup guard and `tests/startup_cancellation_test.rs`; no startup or save/load files were edited by this reviewer.

The earlier three core cross-review corrections were subsequently observed in the root-owned source: resource actions are required to be objects before mutation, easy wrappers validate the referenced protocol and refuse duplicate wrapping, and the atomic-file cleanup guard is created only after the staging file opens successfully. Final regression outcomes remain in the root's validation ledger.

## Final integration corrections

The root reported that the broad 46-feature native check passed, covering all changed client gates including SMB, Bluetooth, and USB. These are compilation results, not device or remote-service executions. Its first focused native test group also passed; the exact count and later SMB-specific run belong to the root's final validation ledger. Subsequent changes described below require the final focused rerun.

### SSH partial-write cancellation

Final review found that timing out `write_all` could leave a partial SSH frame on a reusable stream, and the timeout originally began only after acquiring the writer lock. The new `AgentWriter` stores its transport in an `Option`. A send takes ownership of that transport before awaiting any bytes and restores it only after the entire frame was written. Error, timeout, or cancellation drops the transport and leaves the writer permanently unusable. Production now uses `UnixStream::into_split` so dropping the owned write half half-closes the socket even while the read half exists.

One absolute deadline encloses both mutex acquisition and writing. A timeout while merely waiting for the lock does not poison the transport because it has not been taken or written. New duplex tests assert that internal timeouts and caller cancellation both produce EOF with only the original partial prefix, that a later command cannot append bytes, and that a lock-wait timeout leaves an untouched connection reusable. These raise `client_followup_test` to 18 tests.

### Eval harness classification and explicit model opt-in

Final read-only review found that output capture overflow was marked in `ProbeOutcome` but still passed through generic model-failure classification. A new pure `tests/eval/scoring.rs` helper now returns a harness `error` with `probe_output_limit` before checking expectations or diagnosing the model. `runner.rs` uses that helper when constructing `RunRecord`, preserving command/output/log evidence. No live suite is imported by the new `tests/eval_probe_classification_test.rs` target.

This reviewer added three pure scoring regressions: matching and nonmatching truncated output must both be harness errors; complete output must retain pass/fail behavior; and merely mentioning an action in rejected output must not count as execution. The runtime/server reviewer independently reviewed the handoff, added evidence-preservation checks, and added a fourth regression/fix for malformed expectation regexes being harness errors. Existing run-count/pass-rate accounting was preserved; the broader reporting denominator is not redesigned by this classification fix.

`tests/ollama_model_test.rs` now calls the common affirmative opt-in helper instead of treating any present `NETGET_USE_OLLAMA` value as consent. A search for the same concrete presence-only pattern under `tests` and `src` found no remaining matches. No model endpoint or live evaluation was invoked. These files were formatted and passed owned-path diff checks before handoff for centralized validation.

## Final centralized results

The final combined native run with 24 CPU-only features, including `smb-client`, passed **all 18 tests in `client_followup_test`** and all **22 tests in `client_review_regression_test`**. The pure `eval_probe_classification_test` passed **4/4**. The only failed target in that combined run was an unrelated pre-existing CLI timing fixture; after correcting its clock scope, all five CLI tests passed. The resulting native selection totals **324 passed across 41 targets**, with no outstanding failures. The final Clippy correctness/suspicious gate passed across all targets. The final 46-feature native library check passed; it compiles the changed optional protocol gates without exercising hardware or external services. Exact commands/logs are in the consolidated follow-up verification manifest. No client implementation changes were needed after these successful runs.

---

# Follow-up chapter: Scripting, UI, virtual networking, browser and packaging

# Follow-up: automation, display, dashboard, browser network, and npm

This implements the remaining concrete issues and optional improvements listed in `automation-review.md` and `surfaces-review.md`. No GPU workload, GPU capability probe, real model endpoint, model download, deployment, package publication, or commit is involved. The browser checks use Chromium with GPU-related features disabled and plain JavaScript model/GPU fixtures; they never invoke those real APIs.

## Mapping of every original automation item

| Original item | Resolution | Evidence and limits |
|---|---|---|
| Interpreter probes could deadlock while draining inherited pipes | Replaced exit polling followed by blocking `wait_with_output` with concurrent, bounded Tokio collectors and child wait under one deadline. The four runtime probes run concurrently. | `scripting_resources_test`: noisy stdout refusal, large stderr without deadlock, descendant-retained pipe deadline. Probe output limited to 64 KiB per stream. Browser detects no subprocess runtimes. |
| Per-event and resident output was unbounded | Per-event stdout 8 MiB, stderr 1 MiB; collectors fail immediately on excess. Resident reply lines 8 MiB with strict UTF-8 and complete-line EOF validation. Resident diagnostics log at most 1 MiB over the child lifetime, then drain/discard in fixed 8 KiB scratch space. | Oversized-output and resident-eviction regressions. Error paths retain ordinary BrokenPipe compatibility on stdin. The parent bounds retained output; trusted child code itself is not memory-sandboxed. |
| Only immediate interpreter children were killed | Added shared `scripting::process_io::ProcessGroup`: independent Unix process groups and Windows kill-on-close Job Objects; completion, failure, timeout, cancellation and resident shutdown terminate the group/job. | Unix descendant termination regression. Public helper also available to the coordinator's eval probe. Windows API/type signatures passed an isolated x86_64-pc-windows-gnu cross-check importing this exact module; lifecycle execution still requires Windows runtime CI. No Windows execution claimed on macOS. Cleanup is not a hostile-code sandbox: deliberate new Unix sessions can escape; Windows Job assignment immediately follows spawn. |
| Predictable Go files and cancellation leaks | Random exclusively created private directories (0700 Unix), fixed `main.go` inside, RAII directory cleanup. Creation, staging and compilation are inside the overall execution budget. | Cancellation regression identifies its unique staged source, verifies directory mode, cancels the Go future and requires directory removal. Uses the real local Go toolchain without dependencies/model calls. |
| Synchronous file-backed source loading | Added `get_code_async` on the blocking pool; opens and checks the actual descriptor is a regular file; Unix `O_NONBLOCK` refuses FIFOs without waiting for a writer. Both inline/file source capped at 4 MiB. Per-event and resident dispatch deadlines cover source loading and registry waits. | Tests oversized file, directory, valid regular file, FIFO without writer. A caller stops awaiting a slow filesystem operation at the deadline; a kernel filesystem call already running on a worker is not forcibly interrupted. |
| Detached MCP reaper/ticker retained state | Shared service now owns reaper/ticker/status-drain lifecycle; last service owner closes these tasks even when another component retains an AppState clone. | Last-owner lifecycle regression first proves a retained service clone keeps ticking, then proves AppState alone does not. A per-service cancellation token also cancels already-launched executions from that service; their definitions remain with Failed status, and externally launched executions keep running. A second lifecycle test covers that distinction. The ticker finishes its current claim/spawn batch before stopping. |
| Static interpolation could amplify or recurse without budget | Shared expanded-text budget 8 MiB, 65,536 nodes and 64-level trees. Iterative preflight before recursive transformation or cloning; bounded writer for embedded JSON; aggregate output validated before return. Duplicate interpolated object keys now fail explicitly. | Tests repeated whole-value/embedded substitutions, aggregate action budget, 500-level programmatic JSON, colliding keys, and existing type-preserving/literal-brace suite. Limits are deliberate configuration bounds. |
| Handle detection stripped `#` in every language and searched substrings | Language-aware tokenizer skips relevant comments, ordinary/triple/template strings, JS regexes and Perl quote operators; whitespace-separated declarations and async/ordinary arrow bindings are recognized. | Regression fixtures distinguish real declarations from comments, strings, regexes and ordinary parenthesized assignments. This is a configuration diagnostic, not a full language parser or security sandbox. |
| MCP validates action names, not every parameter schema | Documented the existing division explicitly: control vocabulary validation; protocol executor owns parameter semantics. | No invented universal schema was imposed. Static references receive their own new resource/syntax checks. This is a trust/interface boundary, not unfinished generic-validator code. |
| FIFO parents/ownership were not authenticated | Retained prior startup FIFO check and open-time `O_NOFOLLOW` plus descriptor FIFO check; documented trusted parent-path/ownership boundary. | Existing FIFO replacement/file/symlink regressions remain. The local configured pathname is trusted; authenticated ownership and hostile ancestor traversal were not the contract of a notification FIFO. |

## Mapping of every original surface item

| Original item | Resolution | Evidence and limits |
|---|---|---|
| New TextRenderer per canvas text operation reloads fonts | Canvas rendering lazily owns one TextRenderer for the whole render, shared by labels, textboxes, windows and ASCII art. Glyph cache reused and bounded to about 32 MiB between glyphs. | Existing alpha/baseline/wide-text checks plus native display suite. Buffer layout is clipped to visible height, offscreen glyphs skip rasterization, fonts capped at 512 px and text at the canvas budget. |
| Infallible huge canvas allocation | Added `try_render` with an explicit CanvasError, 16-megapixel/10,000-command/1 MiB text budgets, checked/fallible backing allocations and bounded font sizes. | Oversized dimension test fails before allocating pixels. Compatibility `render()` returns an empty image on error; the sole production VNC caller was changed by the server agent to propagate `try_render()` errors. |
| Recursive window rendering and cloned subtrees | Preflight/execute borrowed command references in an iterative queue with accumulated saturating offsets. Preserve preorder and title-bar offsets. Canvas command destruction/clear is iterative too. | 20,000-level rejected tree can be cleared/dropped without recursion; nested-window pixel test verifies exact offsets and draw order. |
| Unbounded virtual TCP accept queues | Bounded 128-entry backlog. Connect reserves a slot before allocating its duplex pair and waits for accept capacity; closing listener returns ConnectionRefused. | Shim backlog backpressure/resumption/close regression. Existing 8 TCP peek/read/split/EOF checks pass. TCP peek scratch allocation also clamps to per-direction pipe capacity. |
| Unbounded UDP queues | Bounded 128-datagram queue; new arrivals are dropped at capacity, modeling receive-buffer loss, without allocating their payload when no permit exists. | Overflow/drop-new/recovery/zero-byte datagram regression. Up to one additional datagram may occupy the shared peek slot. |
| Concurrent UDP peek/readiness and connected filtering parity | Queue and peek slot now share one mutex; pending peeks cannot separately consume and overwrite datagrams. Every receive/peek/readiness variant filters connected peer ports. | Simultaneous pending peek test, connected recv_from/peek test, old try_recv/filter tests. Addresses remain the documented single-host virtual network abstraction. |
| Feed cursor changes identity when the ring evicts | Selection and mouse hit targets now use stable sequence IDs. Evicting the selected entry moves to the oldest retained entry. | 5,000-entry eviction regression retains selected text while earlier entries disappear, then checks selected eviction fallback. |
| Scrolled activity jumps as entries arrive | Stores top entry sequence plus wrapped-line offset and resolves the anchor at subsequent paints; explicit scroll commands invalidate/recompute it. Unseen counter saturates at ring capacity. | Software TestBackend viewport test compares the same top row before/after ten new events. |
| Card fold state survives vanished instances/peers forever | Prunes collapsed/open/show-all state against current cards, live/recent peers, connectionless requests and client attempt history. | Fold lifecycle test preserves state while nodes exist, removes it when absent, and gives a returned node default state. |
| Inactive UI source referenced removed APIs | Removed uncompiled `src/ui/events.rs` and `src/ui/layout.rs`; `src/ui/mod.rs` only exposes the still-used app state. | Coordinator removed their entries from `.github/unreachable-modules.txt`; no references from active modules/tests were found. |
| npm downloads trusted archives without checksum provenance | Fallback requires exact single archive entry in release `SHA256SUMS`, streams SHA-256 during download, refuses mismatch/missing/ambiguous manifests before extraction. Extracts only the expected binary; regular-file check remains. | Coordinator wires generation/verification/upload in release and npm publication pipelines. Manifest authenticates bytes relative to the trusted release/mirror; not an independent publisher signature. Existing platform dependencies and explicit NETGET_BINARY retain precedence. |
| npm timeout/staging/signals lacked fault injection | Download bytes bounded (512 MiB archive, 128 KiB manifest), deadlines for download/extractor, random cache staging, cleanup of both locations on failure, repeated signal forwarding tested. | Eight Node launcher/download tests pass: argv/status, platform cache, manifest matching, valid installation, corruption/missing manifest, rename failure cleanup, stream excess/stall, repeated SIGTERM. Fetched executables are harmless inert fixtures and never run. Windows signal/extractor runtime requires Windows CI. |
| Browser tests required potentially real GPU/model probing | Added explicit `NETGET_CPU_ONLY=1` mode disabling GPU/compositing/software rasterizer/WebGPU/on-device model features, initializes pages with no real GPU/model APIs, and skips real Prompt API probe. Requests outside local server are fulfilled from fixtures or blocked, including fonts. | All 12 synthetic browser scenarios passed against both the preexisting bundle and the rebuilt current-source bundle, Chromium 154.0.8037.93 and xterm stub. No screenshots taken; real Prompt API probe explicitly skipped. |
| Asset packaging for added Telnet module | Existing JS asset packaging already includes `site/js/telnet.js`; no deployment required. | Six hermetic Node parser/composer tests rerun successfully. |
| Windows runtime coverage unavailable locally | Implemented Windows Job Objects and retained cross-platform launcher logic, while marking native Windows execution evidence separately. | An isolated Windows GNU cross-check importing the exact ProcessGroup module passed. Full package cross-build stops in ring because MinGW GCC is absent. Coordinator added a Windows CI job; macOS does not claim Windows execution. |
| Historical public/repository/model documentation could drift | Changed only verifiable local behavior in scripting/MCP/npm/browser docs. No external model/hosting calls were made to refresh unrelated claims. | External currentness is a source/provenance boundary rather than a reason to invent values. |

## Additional integration improvements

- `web/build.sh` now respects `CARGO_TARGET_DIR` when locating the wasm-bindgen input instead of hardcoding `target/`. Cargo builds use `--locked`; installed wasm-bindgen version is still checked against the lockfile.
- The server agent changed the VNC production path to propagate the fallible renderer result and allocate its output copy fallibly.
- Resource helper APIs are reusable by the root agent's eval/probe lifetime cleanup instead of introducing a second implementation.
- CI now installs Playwright/Chromium and runs the CPU-only browser fixture suite after the WASM build/smoke. The resource lifecycle job installs Go and includes the MCP startup/owner tests. CI YAML and browser Python parse successfully.
- Original first-pass fixes and tests remain part of the final diff; this follow-up does not replace their evidence.

## Verification record

Completed locally:

1. `cargo test -p netget-tokio-wasm --test tcp_peek_test --test udp_receive_test --test time_math_test --test backlog_test --locked --offline` with isolated CPU target: **18 passed**, zero failures/ignored.
2. `node --test tests/npm_download_test.cjs tests/npm_launcher_test.cjs`: **8 passed**, zero failures/skips. Log `tmp/audit-2026-10-01/followup/npm-tests.log`.
3. `node --test web/test/composer_model_test.mjs web/test/telnet_test.mjs`: **6 passed**, zero failures/skips. Log `tmp/audit-2026-10-01/followup/browser-model-tests.log`.
4. First `NETGET_CPU_ONLY=1 python3 web/test/page_composer.py`: **all 12 synthetic scenarios passed**, existing WASM bundle. Initial sandbox loopback bind was denied; the CPU-only loopback test was subsequently approved and ran. No application publication or external request was involved.
5. `env CARGO_TARGET_DIR=/private/tmp/netget-audit-web-20261001 RUSTC_WRAPPER= CARGO_NET_OFFLINE=true CARGO_PROFILE_DEV_DEBUG=0 ./web/build.sh --dev`: initial full WASM build **passed** in 4m47s with cached toolchains/dependencies. The final current-source incremental rebuild also **passed** in 1m48s; see final integration results below.
6. Targeted rustfmt, JS/Python/shell syntax checks and `git diff --check`: passed at this checkpoint.

Coordinator-run native targets requested: `scripting_resources_test`, `scripting_resident_test`, `scripting_executor_test`, `scripting_environment_test`, `static_handler_interpolation_test`, `mcp_startup_config_test`, `dashboard_frame_test`, `display_rendering_test`. MCP features include tcp/mcp-stdio; mcp-http compile covers the prior IPv6 transport change. The consolidated root report is authoritative for final native pass counts and any platform conditions.

## Final integration results

- Current-source dev-WASM build **passed**: `tmp/audit-2026-10-01/followup/wasm-build-final.log`.
- Rebuilt-bundle `node web/test/smoke.mjs` **passed**, including 43 synthetic requests over virtual TCP/UDP, HTTP, OpenAPI, JSON-RPC, RSS, HTTP/2 and HTTP-family client fixtures. These use a JavaScript model bridge and local virtual protocol fixtures, including the fixture named Ollama; no real model was used. Log `tmp/audit-2026-10-01/followup/wasm-smoke-final.log`.
- Rebuilt-bundle `NETGET_CPU_ONLY=1 python3 web/test/page_composer.py` **passed all 12 synthetic scenarios**, Chromium 154.0.8037.93, xterm DOM stub; real Prompt API explicitly reported `not probed (CPU-only mode)`. Responsive DOM layout was checked at 1280x800, 1440x900, 1920x1080 and 390x844. This is interaction/layout evidence, not a screenshot or real xterm canvas rendering check. Log `tmp/audit-2026-10-01/followup/browser-cpu-final.log`.
- Isolated Windows GNU fixture **passed** in 6.89s. Its library imports the exact current `src/scripting/process_io.rs`, with direct dependencies pinned to Tokio 1.48.0, UUID 1.18.1 and windows-sys 0.61.2; `cargo check --target x86_64-pc-windows-gnu --offline` checks Job Object APIs without needing a linker. Fixture at `/private/tmp/netget-windows-process-fixture-20261001`, log `tmp/audit-2026-10-01/followup/windows-process-fixture.log`. This does not claim Windows process execution.
- An initial unoptimized dev-WASM smoke exposed a memory access fault late in the synthetic server scenario. Moving new 8 KiB read scratch arrays onto the heap reduced nested async future construction size; the subsequent unchanged-profile build and full smoke passed. The failure and correction are retained in the logs rather than hidden as a skipped scenario.

The coordinator's `native-second` CPU run completed successfully (exit 0, 219.76 seconds), with 32 test threads. Within this report's owned surface targets: **120 passed, 0 failed, 0 ignored across 10 targets**. This includes all new scripting resource, service-owner, interpolation, dashboard and fallible renderer regressions.

| Native target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `dashboard_frame_test` | 20 | 0 | 0 |
| `display_rendering_test` | 6 | 0 | 0 |
| `mcp_startup_config_test` | 13 | 0 | 0 |
| `scripting_environment_test` | 3 | 0 | 0 |
| `scripting_executor_test` | 11 | 0 | 0 |
| `scripting_highlight_test` | 2 | 0 | 0 |
| `scripting_manager_test` | 8 | 0 | 0 |
| `scripting_resident_test` | 15 | 0 | 0 |
| `scripting_resources_test` | 8 | 0 | 0 |
| `static_handler_interpolation_test` | 34 | 0 | 0 |

Evidence: `tmp/audit-2026-10-01/followup/native-second.log` and `native-second.json`. The root consolidated report records the complete multi-agent native target count and features. There are no pending failures in this report's native/browser/Node/shim or ProcessGroup cross-check results.

The final read-only integration review rechecked renderer traversal/allocation/drop, glyph rendering, interpreter/descendant/temp-file ownership, resident output, virtual TCP/UDP queue behavior, Windows fixture portability, and CPU browser routing. No additional concrete defect was found in those changes. A remaining false-valued live-model opt-in in root-owned `tests/ollama_model_test.rs` was reported to the coordinator for consistency with its shared explicit-opt-in helper.


### Startup ownership integration recheck

After the coordinator introduced the common startup registration guard, an isolated incremental `web/build.sh --dev` rebuilt the current source successfully in **14.32 seconds**. Its cleanup path using `tokio::runtime::Handle::try_current().spawn(...)` compiles against the WASM runtime shim. The rebuilt Node smoke again **passed all 43 synthetic requests**, with no real models, GPU APIs, or external services. Logs: `tmp/audit-2026-10-01/followup/wasm-build-startup-guard.log` and `wasm-smoke-startup-guard.log`. The already-passing CPU Chromium interaction suite was not repeated because no browser interaction source changed.

The resource lifecycle CI job now also selects `startup_cancellation_test`, `non_interactive_run_limits_test`, and the pure `eval_probe_classification_test` scoring fixtures. YAML parsing and `git diff --check` passed after these CI changes.


### Final formatted-source snapshot

After the session restoration guard adopted the same runtime-presence check, the final formatted source rebuilt successfully in **22.38 seconds**, and its Node smoke again **passed 43 synthetic requests**. Both startup ownership and restoration cleanup now compile against the WASM shim. Source hashes for **839 Rust/build inputs** were compared after build and smoke: **zero changes** during verification.

- Exact final commands, exit codes, log paths and generated bundle SHA-256 values: `audit/2026-10-01/wasm-final-verification.json`.
- Full source SHA-256 inventory: `audit/2026-10-01/wasm-final-source-sha256.json`.
- Logs: `tmp/audit-2026-10-01/followup/wasm-build-final-snapshot.log` and `wasm-smoke-final-snapshot.log`.

This supersedes earlier WASM build/smoke snapshots while preserving their diagnostic history. No additional GPU or real-model work was performed.

---

# Current implementation file ledger

The JSON ledger contains exact SHA-256 hashes. “Retained” means unchanged since the first-pass recorded result; “Follow-up” identifies this turn's additional implementation or formatting change.

| File | Change from base | Follow-up disposition | Lines now |
|---|---|---|---:|
| `.github/scripts/check-module-reachability.sh` | modified | Follow-up | 146 |
| `.github/unreachable-modules.txt` | modified | Follow-up | 26 |
| `.github/workflows/ci.yml` | modified | Follow-up | 1478 |
| `.github/workflows/fuzz.yml` | modified | Retained first-pass change | 155 |
| `.github/workflows/nightly-eval.yml` | modified | Retained first-pass change | 131 |
| `.github/workflows/nightly-soak.yml` | modified | Retained first-pass change | 115 |
| `.github/workflows/release.yml` | modified | Follow-up | 194 |
| `Cargo.lock` | modified | Follow-up | 17756 |
| `Cargo.toml` | modified | Follow-up | 1286 |
| `PROTOCOL_ROADMAP.md` | modified | Follow-up | 1401 |
| `cargo-isolated-kill.sh` | modified | Follow-up | 9 |
| `cargo-isolated.sh` | modified | Follow-up | 80 |
| `cargo.sh` | modified | Follow-up | 152 |
| `crates/netget-tokio-wasm/src/net.rs` | modified | Follow-up | 829 |
| `crates/netget-tokio-wasm/src/time.rs` | modified | Retained first-pass change | 348 |
| `crates/netget-tokio-wasm/src/time_math.rs` | new | Retained first-pass change | 22 |
| `crates/netget-tokio-wasm/tests/backlog_test.rs` | new | Follow-up | 29 |
| `crates/netget-tokio-wasm/tests/time_math_test.rs` | new | Retained first-pass change | 38 |
| `crates/netget-tokio-wasm/tests/udp_receive_test.rs` | new | Follow-up | 153 |
| `examples/external_protocol/Cargo.toml` | modified | Retained first-pass change | 18 |
| `examples/external_protocol/README.md` | modified | Retained first-pass change | 41 |
| `examples/external_protocol/src/lib.rs` | modified | Retained first-pass change | 151 |
| `examples/test_doc_gen.rs` | modified | Retained first-pass change | 60 |
| `npm/netget/README.md` | modified | Follow-up | 57 |
| `npm/netget/bin/netget.js` | modified | Follow-up | 216 |
| `scripts/cargo_session.py` | new | Follow-up | 224 |
| `scripts/sccache/cargo-sccache.sh` | modified | Retained first-pass change | 47 |
| `scripts/sccache/setup-sccache-r2.sh` | modified | Retained first-pass change | 88 |
| `scripts/sccache/setup-sccache-upstash.sh` | modified | Retained first-pass change | 79 |
| `site/js/composer.js` | modified | Retained first-pass change | 503 |
| `site/js/demo.js` | modified | Retained first-pass change | 1383 |
| `site/js/telnet.js` | new | Retained first-pass change | 63 |
| `src/cli/args.rs` | modified | Follow-up | 936 |
| `src/cli/client_startup.rs` | modified | Follow-up | 401 |
| `src/cli/easy_startup.rs` | modified | Follow-up | 148 |
| `src/cli/management.rs` | modified | Follow-up | 1355 |
| `src/cli/mod.rs` | modified | Follow-up | 781 |
| `src/cli/non_interactive.rs` | modified | Follow-up | 756 |
| `src/cli/server_startup.rs` | modified | Follow-up | 803 |
| `src/cli/startup_guard.rs` | new | Follow-up | 56 |
| `src/cli/tasks.rs` | modified | Follow-up | 451 |
| `src/client/bitcoin/mod.rs` | modified | Follow-up | 667 |
| `src/client/bluetooth/mod.rs` | modified | Follow-up | 1189 |
| `src/client/dc/mod.rs` | modified | Follow-up | 1932 |
| `src/client/dot/mod.rs` | modified | Follow-up | 740 |
| `src/client/ftp/CLAUDE.md` | modified | Follow-up | 141 |
| `src/client/ftp/mod.rs` | modified | Retained first-pass change | 337 |
| `src/client/grpc/mod.rs` | modified | Follow-up | 1281 |
| `src/client/http/CLAUDE.md` | modified | Follow-up | 344 |
| `src/client/http2/mod.rs` | modified | Follow-up | 750 |
| `src/client/http3/actions.rs` | modified | Follow-up | 427 |
| `src/client/http_fetch/mod.rs` | modified | Follow-up | 608 |
| `src/client/http_fetch/transport.rs` | modified | Follow-up | 405 |
| `src/client/http_proxy/CLAUDE.md` | modified | Follow-up | 234 |
| `src/client/http_proxy/mod.rs` | modified | Follow-up | 804 |
| `src/client/icmp/mod.rs` | modified | Follow-up | 821 |
| `src/client/ident/mod.rs` | modified | Follow-up | 1024 |
| `src/client/igmp/mod.rs` | modified | Follow-up | 562 |
| `src/client/ipp/mod.rs` | modified | Follow-up | 901 |
| `src/client/jsonrpc/mod.rs` | modified | Follow-up | 944 |
| `src/client/llm_budget.rs` | modified | Retained first-pass change | 210 |
| `src/client/mcp/mod.rs` | modified | Follow-up | 846 |
| `src/client/mod.rs` | modified | Follow-up | 627 |
| `src/client/mqtt/actions.rs` | modified | Follow-up | 517 |
| `src/client/nfs/mod.rs` | modified | Follow-up | 992 |
| `src/client/nntp/CLAUDE.md` | modified | Follow-up | 251 |
| `src/client/nntp/mod.rs` | modified | Follow-up | 648 |
| `src/client/oauth2/mod.rs` | modified | Follow-up | 1619 |
| `src/client/openidconnect/mod.rs` | modified | Follow-up | 1787 |
| `src/client/pop3/CLAUDE.md` | modified | Follow-up | 247 |
| `src/client/pop3/mod.rs` | modified | Follow-up | 527 |
| `src/client/response_reader.rs` | new | Follow-up | 170 |
| `src/client/smb/CLAUDE.md` | modified | Follow-up | 404 |
| `src/client/smb/mod.rs` | modified | Follow-up | 910 |
| `src/client/snmp/mod.rs` | modified | Follow-up | 1066 |
| `src/client/ssdp/actions.rs` | modified | Follow-up | 790 |
| `src/client/ssh_agent/CLAUDE.md` | modified | Follow-up | 261 |
| `src/client/ssh_agent/actions.rs` | modified | Follow-up | 410 |
| `src/client/ssh_agent/mod.rs` | modified | Follow-up | 661 |
| `src/client/torrent_peer/CLAUDE.md` | modified | Retained first-pass change | 177 |
| `src/client/torrent_peer/mod.rs` | modified | Follow-up | 562 |
| `src/client/torrent_tracker/mod.rs` | modified | Follow-up | 906 |
| `src/client/turn/mod.rs` | modified | Follow-up | 1110 |
| `src/client/udp/mod.rs` | modified | Follow-up | 580 |
| `src/client/usb/mod.rs` | modified | Follow-up | 942 |
| `src/client/vnc/CLAUDE.md` | modified | Follow-up | 292 |
| `src/client/vnc/actions.rs` | modified | Follow-up | 558 |
| `src/client/vnc/mod.rs` | modified | Follow-up | 1066 |
| `src/client/webdav/mod.rs` | modified | Follow-up | 830 |
| `src/client/webrtc/CLAUDE.md` | modified | Follow-up | 562 |
| `src/client/webrtc/mod.rs` | modified | Follow-up | 1181 |
| `src/client/wire_values.rs` | new | Follow-up | 34 |
| `src/client/wireguard/actions.rs` | modified | Follow-up | 351 |
| `src/display/ascii.rs` | modified | Follow-up | 86 |
| `src/display/canvas.rs` | modified | Follow-up | 523 |
| `src/display/text.rs` | modified | Follow-up | 159 |
| `src/easy/http/actions.rs` | modified | Retained first-pass change | 439 |
| `src/events/handler.rs` | modified | Follow-up | 2953 |
| `src/llm/actions/tools.rs` | modified | Follow-up | 2713 |
| `src/llm/agent_queue.rs` | modified | Retained first-pass change | 270 |
| `src/llm/circuit_breaker.rs` | modified | Follow-up | 393 |
| `src/llm/config.rs` | modified | Follow-up | 262 |
| `src/llm/conversation_state.rs` | modified | Follow-up | 358 |
| `src/llm/model_selection.rs` | modified | Follow-up | 276 |
| `src/llm/ollama_client.rs` | modified | Follow-up | 2555 |
| `src/llm/rate_limiter.rs` | modified | Follow-up | 717 |
| `src/llm/reference_parser.rs` | modified | Retained first-pass change | 203 |
| `src/mcp_stdio/CLAUDE.md` | modified | Follow-up | 430 |
| `src/mcp_stdio/mod.rs` | modified | Retained first-pass change | 82 |
| `src/mcp_stdio/tools.rs` | modified | Follow-up | 2285 |
| `src/pipe/mod.rs` | modified | Retained first-pass change | 419 |
| `src/protocol/log_template.rs` | modified | Retained first-pass change | 285 |
| `src/protocol/spawn_context.rs` | modified | Follow-up | 671 |
| `src/scripting/CLAUDE.md` | modified | Follow-up | 383 |
| `src/scripting/environment.rs` | modified | Follow-up | 265 |
| `src/scripting/event_handler.rs` | modified | Follow-up | 1019 |
| `src/scripting/executor.rs` | modified | Follow-up | 545 |
| `src/scripting/highlight.rs` | modified | Retained first-pass change | 64 |
| `src/scripting/mod.rs` | modified | Follow-up | 32 |
| `src/scripting/process_io.rs` | new | Follow-up | 172 |
| `src/scripting/resident.rs` | modified | Follow-up | 799 |
| `src/scripting/types.rs` | modified | Follow-up | 339 |
| `src/server/dc/mod.rs` | modified | Follow-up | 657 |
| `src/server/dot/CLAUDE.md` | modified | Follow-up | 403 |
| `src/server/dot/mod.rs` | modified | Retained first-pass change | 621 |
| `src/server/peer_support.rs` | modified | Follow-up | 242 |
| `src/server/proxy/CLAUDE.md` | modified | Follow-up | 515 |
| `src/server/proxy/cert_cache.rs` | modified | Retained first-pass change | 312 |
| `src/server/pty/CLAUDE.md` | modified | Retained first-pass change | 102 |
| `src/server/pty/mod.rs` | modified | Retained first-pass change | 360 |
| `src/server/quic/CLAUDE.md` | modified | Follow-up | 303 |
| `src/server/quic/actions.rs` | modified | Follow-up | 555 |
| `src/server/tls/CLAUDE.md` | modified | Follow-up | 578 |
| `src/server/tls_cert_manager.rs` | modified | Follow-up | 405 |
| `src/server/vnc/mod.rs` | modified | Follow-up | 1243 |
| `src/settings.rs` | modified | Follow-up | 148 |
| `src/state/app_state.rs` | modified | Follow-up | 3413 |
| `src/state/sqlite.rs` | modified | Follow-up | 643 |
| `src/state/task.rs` | modified | Follow-up | 365 |
| `src/tui/activity.rs` | modified | Follow-up | 542 |
| `src/tui/app.rs` | modified | Follow-up | 406 |
| `src/tui/cards.rs` | modified | Follow-up | 1342 |
| `src/tui/event_loop.rs` | modified | Retained first-pass change | 268 |
| `src/tui/hit.rs` | modified | Follow-up | 157 |
| `src/tui/keymap.rs` | modified | Follow-up | 713 |
| `src/tui/modal/text_editor.rs` | modified | Retained first-pass change | 104 |
| `src/tui/render/chat.rs` | modified | Retained first-pass change | 131 |
| `src/tui/render/stream.rs` | modified | Follow-up | 303 |
| `src/ui/events.rs` | deleted | Follow-up | 0 |
| `src/ui/layout.rs` | deleted | Follow-up | 0 |
| `src/utils/file_io.rs` | new | Follow-up | 240 |
| `src/utils/json_budget.rs` | new | Follow-up | 56 |
| `src/utils/mod.rs` | modified | Follow-up | 23 |
| `src/utils/redact.rs` | modified | Retained first-pass change | 80 |
| `src/utils/save_load.rs` | modified | Follow-up | 575 |
| `tests/README.md` | modified | Follow-up | 325 |
| `tests/agent_queue_fifo_test.rs` | new | Retained first-pass change | 59 |
| `tests/audit_ci_coverage_test.rs` | new | Retained first-pass change | 58 |
| `tests/build_scripts_test.py` | new | Follow-up | 165 |
| `tests/client/igmp/e2e_test.rs` | modified | Follow-up | 273 |
| `tests/client/udp/CLAUDE.md` | modified | Follow-up | 210 |
| `tests/client_followup_test.rs` | new | Follow-up | 465 |
| `tests/client_review_regression_test.rs` | new | Retained first-pass change | 411 |
| `tests/core_followup_test.rs` | new | Follow-up | 283 |
| `tests/dashboard_frame_test.rs` | modified | Follow-up | 733 |
| `tests/display_rendering_test.rs` | new | Follow-up | 160 |
| `tests/easy_startup_test.rs` | new | Follow-up | 62 |
| `tests/eval/CLAUDE.md` | modified | Follow-up | 300 |
| `tests/eval/mod.rs` | modified | Follow-up | 54 |
| `tests/eval/probe.rs` | modified | Follow-up | 265 |
| `tests/eval/probe_check.rs` | modified | Follow-up | 1089 |
| `tests/eval/runner.rs` | modified | Follow-up | 529 |
| `tests/eval/scoring.rs` | new | Follow-up | 65 |
| `tests/eval_probe_classification_test.rs` | new | Follow-up | 96 |
| `tests/eval_probe_followup_test.rs` | new | Follow-up | 73 |
| `tests/harness_port_allocation_test.rs` | new | Follow-up | 47 |
| `tests/helpers/common.rs` | modified | Follow-up | 497 |
| `tests/helpers/llm_live.rs` | modified | Follow-up | 692 |
| `tests/helpers/mod.rs` | modified | Follow-up | 41 |
| `tests/helpers/netget.rs` | modified | Follow-up | 1326 |
| `tests/helpers/startup_ports.rs` | new | Follow-up | 50 |
| `tests/integration_toolcall.rs` | modified | Follow-up | 21 |
| `tests/llm_circuit_breaker_test.rs` | modified | Follow-up | 491 |
| `tests/llm_rate_limiter_test.rs` | modified | Retained first-pass change | 407 |
| `tests/log_template_test.rs` | modified | Retained first-pass change | 127 |
| `tests/management_test.rs` | modified | Follow-up | 383 |
| `tests/mcp_startup_config_test.rs` | modified | Follow-up | 291 |
| `tests/mcp_stop_cleanup_test.rs` | modified | Follow-up | 272 |
| `tests/non_interactive_run_limits_test.rs` | modified | Follow-up | 387 |
| `tests/npm_download_test.cjs` | new | Follow-up | 100 |
| `tests/npm_launcher_test.cjs` | new | Retained first-pass change | 39 |
| `tests/ollama_model_test.rs` | modified | Follow-up | 932 |
| `tests/prompt_growth_test.rs` | modified | Retained first-pass change | 286 |
| `tests/recursive_decoder_depth_test.rs` | modified | Follow-up | 1015 |
| `tests/reference_parser_test.rs` | modified | Retained first-pass change | 185 |
| `tests/scheduled_task_actions_test.rs` | modified | Follow-up | 215 |
| `tests/scheduled_task_claim_test.rs` | new | Follow-up | 140 |
| `tests/scheduled_task_lifecycle_test.rs` | new | Follow-up | 182 |
| `tests/scripting_resident_test.rs` | modified | Retained first-pass change | 674 |
| `tests/scripting_resources_test.rs` | new | Follow-up | 239 |
| `tests/secret_redaction_test.rs` | modified | Retained first-pass change | 90 |
| `tests/server/dot/CLAUDE.md` | modified | Retained first-pass change | 272 |
| `tests/server/dot/connection_bounds_test.rs` | modified | Retained first-pass change | 216 |
| `tests/server/kafka/connection_task_cleanup_test.rs` | modified | Follow-up | 153 |
| `tests/server/llmnr/CLAUDE.md` | modified | Follow-up | 142 |
| `tests/server/llmnr/e2e_test.rs` | modified | Follow-up | 319 |
| `tests/server/openai/CLAUDE.md` | modified | Follow-up | 201 |
| `tests/server/proxy/CLAUDE.md` | modified | Follow-up | 300 |
| `tests/server/proxy/certificate_cache_bound_test.rs` | new | Retained first-pass change | 57 |
| `tests/server/proxy/mod.rs` | modified | Retained first-pass change | 16 |
| `tests/server/pty/CLAUDE.md` | modified | Retained first-pass change | 61 |
| `tests/server/pty/mod.rs` | modified | Retained first-pass change | 7 |
| `tests/server/pty/startup_cleanup_test.rs` | new | Retained first-pass change | 74 |
| `tests/server/quic/CLAUDE.md` | modified | Follow-up | 197 |
| `tests/server/quic/certificate_validation_test.rs` | new | Follow-up | 42 |
| `tests/server/quic/mod.rs` | modified | Follow-up | 10 |
| `tests/server/snmp/llm_failure_test.rs` | modified | Follow-up | 172 |
| `tests/server/snmp/test.rs` | modified | Follow-up | 590 |
| `tests/server/tcp/CLAUDE.md` | modified | Follow-up | 226 |
| `tests/server/tcp/mod.rs` | modified | Retained first-pass change | 6 |
| `tests/server/tcp/peer_lifecycle_test.rs` | new | Follow-up | 128 |
| `tests/server/tls/CLAUDE.md` | modified | Retained first-pass change | 320 |
| `tests/server/tls/certificate_validation_test.rs` | new | Retained first-pass change | 63 |
| `tests/server/tls/mod.rs` | modified | Retained first-pass change | 12 |
| `tests/server_stop_cleans_scheduled_tasks_test.rs` | modified | Follow-up | 124 |
| `tests/sqlite_identifier_test.rs` | new | Retained first-pass change | 51 |
| `tests/sqlite_query_bounds_test.rs` | new | Follow-up | 68 |
| `tests/startup_cancellation_test.rs` | new | Follow-up | 126 |
| `tests/startup_params_result_test.rs` | modified | Follow-up | 206 |
| `tests/static_handler_interpolation_test.rs` | modified | Follow-up | 633 |
| `tests/test_infrastructure_review_test.rs` | new | Retained first-pass change | 178 |
| `tests/tool_call_integration_test.rs` | modified | Follow-up | 232 |
| `tests/toolcall/web_search_integration_test.rs` | modified | Follow-up | 258 |
| `tests/utils_save_load_test.rs` | modified | Follow-up | 238 |
| `web/README.md` | modified | Follow-up | 444 |
| `web/build.sh` | modified | Follow-up | 73 |
| `web/test/composer_model_test.mjs` | new | Retained first-pass change | 44 |
| `web/test/page_composer.py` | modified | Follow-up | 1286 |
| `web/test/telnet_test.mjs` | new | Retained first-pass change | 41 |

---

# Historical appendix: complete first-pass report

**Historical snapshot.** The following report, its findings and its test totals describe the first review before the user requested every remaining/optional improvement. Its “remaining/deferred” lists are superseded by the four current follow-up chapters above. The original inventory remains useful coverage evidence; it is not a new execution claim.

# NetGet codebase review and improvements — 2026-10-01

This report collects the completed parallel review, implemented changes, validation evidence, file coverage, and unresolved findings. **119 implementation, test, workflow and documentation files changed: 99 existing files modified and 20 files added.** Reports and evidence manifests are additional artifacts. All changes are local and uncommitted.

**273 CPU-only test executions passed in the final validation set: 260 Rust, 8 JavaScript and 5 Python.** The selected native feature set also passed Clippy with its correctness and suspicious lint groups denied, formatting, module reachability, script syntax, and local evidence checks. Existing Clippy style warnings remain.

**No GPUs, GPU probes, real model inference, model downloads, deployments or publishing were run.** Some tests use an in-process mock HTTP model server with canned responses; that is ordinary CPU test code. CPU font rasterization and native in-memory tests of the browser compatibility crate do not start a browser GPU runtime.

The review inventoried **all 3,342 tracked files**, representing **1,250,366 text lines including documentation, fixtures and vendored code**. The whole-source heuristic scan covered **811 tracked Rust source files and 512,054 source lines** at its checkpoint. Section owners used those scans to guide focused control-flow review and implemented concrete fixes. **Inventory and pattern scanning are not a claim that every line was manually proved correct or every protocol was executed.** The coverage ledgers below identify focused and sweep-only areas. Remaining known issues are explicitly listed.

Base commit: `d34d91c09ee1731ec13eb3977c17344aeda95497`.

## Contents

- [Results and behavior changes](#results)
- [Parallel work and coverage](#coverage)
- [Validation and reproducibility](#validation)
- [Remaining findings and test boundaries](#remaining)
- [Changed-file ledger](#changes)
- [Shared core, build tooling and CI report](#core)
- [Server report](#servers)
- [Client, easy HTTP and pipe report](#clients)
- [CLI, state and protocol report](#runtime)
- [Terminal, display, browser and npm report](#surfaces)
- [Scripting and MCP report](#automation)
- [Tests, examples, prompts, schemas and vendor report](#infrastructure)
- [Complete tracked-file inventory](#inventory)
- [Evidence artifact index](#artifacts)

<a id="results"></a>
## Results and behavior changes

| Area | Implemented outcome |
|---|---|
| Shared HTTP transport | Cancellation aborts connection drivers; valid extension methods are accepted with their case preserved. |
| Protocol response readers | FTP/POP3/NNTP/proxy lines and aggregate bodies have explicit bounds; truncated dot responses fail; dot stuffing is decoded. |
| Binary client framing | BitTorrent peer and VNC allocations are checked before reading; SSH agent messages are decoded by length-delimited frames. |
| Client lifecycle | POP3/VNC readers clear stale handles on exit; an obsolete WebRTC raw Arc leak is removed. |
| Easy HTTP and pipes | Balanced, escaped Markdown subset rendering; bounded template expansion; invalid explicit mapping/source values produce errors. |
| TLS and server ownership | Certificate inputs return validation errors; DoT partial bodies time out; failed PTY creation releases descriptors; server stop aborts peer workers. |
| Proxy certificates | Generated leaf-certificate cache is capped at 1,024 entries with oldest-generated eviction. |
| Scheduler and state | Stored task IDs match allocated IDs; due work is claimed atomically; recurring tasks stop at the requested execution limit. |
| Startup and management | Non-object startup parameters are rejected before an update restarts or mutates a live instance. |
| Templates and SQL metadata | Log field values remain literal; SQLite identifiers with quotes, punctuation and Unicode refresh correctly. |
| Persistence | Requested directories survive extension normalization; saved instances retain event handlers and feedback instructions. |
| LLM bookkeeping | Queued requests recheck token limits; counters saturate; huge windows avoid Instant subtraction; lock ordering is safer. |
| Reference parsing and history | Nested tags do not cause overlapping removal panics; substitutions are literal and JSON escaped; inline references and tiny conversation limits work. |
| Secret display | Bearer token variants, authorization headers, cookies and private-key names are redacted while token counts remain visible. |
| Resident scripts | Cancellation owns and drops the interpreter; deadlines include queue wait; invalid responses fail; JavaScript handlers can be asynchronous. |
| MCP notifications | Existing paths and opened descriptors must really be FIFOs; IPv6 HTTP binding and reported ephemeral ports are corrected. |
| Dashboard and CPU display | Input scrolling, wide Unicode cursor/wrapping, terminal cleanup, zero-sized geometry, alpha, color glyphs and text baselines are corrected. |
| Browser compatibility | Timer math and missed-tick catch-up are corrected; virtual UDP receive/peer handling improves; Telnet decoding survives arbitrary chunks. |
| Answer composer | Raw JSON edits and prototype-named fields survive; lossy form conversions and unsafe form integers are rejected. |
| npm launcher | Cache separates platforms; downloads stream with a deadline; extracted binaries must be regular files; failed staging is cleaned; repeated signals forward. |
| Tests and examples | Real models require affirmative opt-in; binary lookup uses Cargo paths; retry deadlines cover attempts/backoff; protocol example APIs are current. |
| Build and CI | Cargo wrappers preserve failures and wrapper overrides; generated credentials are literal shell data; workflow inputs stay data; all 29 fuzz targets are scheduled. |

### Intentional new resource bounds

| Resource | Bound or policy |
|---|---|
| Client text line | 64 KiB |
| HTTP CONNECT response headers in aggregate | 64 KiB |
| POP3/NNTP accumulated dot response | 8 MiB |
| BitTorrent peer frame | 8 MiB |
| SSH agent response frame | 1 MiB |
| VNC remote text | 1 MiB |
| VNC raw rectangle | 256 MiB, consumed using bounded scratch reads |
| Pipe intermediate representation | 1 MiB |
| Pipe decoded payload | Existing 64 KiB cap retained |
| Generated proxy leaf certificates | 1,024 entries |
| DNS-over-TLS incomplete body | 10-second read timeout |
| npm archive download | Two-minute abort deadline |

These bounds intentionally reject oversized data. They are material compatibility changes for unusually large responses, rather than silent truncation. Easy HTTP remains a documented small Markdown subset. No dependency/lockfile upgrades or protocol maturity promotions were made.

<a id="coverage"></a>
## Parallel work and coverage

The environment allowed **four concurrent agents total**. The coordinator and three subagents worked at that limit in waves rather than creating idle agents beyond the available slots. The first wave split server protocols, client/easy/pipe protocols, and terminal/browser/package surfaces. The second wave covered CLI/state/protocol runtime, test infrastructure/examples/prompts/vendor, and scripting/MCP. The coordinator handled shared LLM utilities, persistence, CI/build scripts, integration and final evidence.

Agents owned separate edit areas and then cross-reviewed changes from other sections. Integration review found and fixed custom HTTP method casing, a resident extreme-timeout overflow, reference parsing inside JSON strings, and missing camelCase token redaction. Cargo builds sharing the main target directory were serialized; selected tests used 32 test threads. The independent compatibility-crate tests used a separate temporary target directory.

Coverage evidence has distinct meanings:

1. **Inventory:** a file was enumerated and assigned to a review section; this applies to every tracked file.
2. **Static sweep:** lexical/interface/risk inspection identified relevant parsing, arithmetic, allocation, ownership, filesystem or execution paths. Signal matches include intentional code and comments.
3. **Focused review:** manual control-flow inspection followed a specific behavior through callers and error/cancellation paths.
4. **Executed regression:** a named test ran successfully in the selected CPU environment. This is stronger evidence for that behavior, not general certification of its protocol.

New files added after the inventory checkpoint are included in the changed-file ledger. Inventory hashes describe that checkpoint, which was taken during the work, and must not be treated as pristine pre-change hashes. Final changed-file hashes are recorded separately.

Existing untracked user artifacts were preserved: `netget.log.1`, `netget.log.2`, `netget.log.3`, `paseo.json`, and the pre-existing Python cache files under `fuzz/__pycache__/` and `scripts/__pycache__/`. They are excluded from the tracked inventory and improvement ledger. No commit, push, external message or direct home-configuration migration occurred; normal application startup in tests may read existing settings.

<a id="validation"></a>
## Validation and reproducibility

The authoritative structured result is [verification-results.json](../../audit/2026-10-01/verification-results.json). Raw local build/test output remains in `tmp/audit-2026-10-01/`; those temporary logs are supporting evidence, not required source files.

| Validation set | Final result | Evidence |
|---|---:|---|
| 24 selected native regression targets | 187 passed, 0 failed, 0 ignored | `regression-final.log`; native table below |
| Five focused server filters | 8 passed, 0 failed | Certificate, DoT, PTY, peer lifecycle and proxy cache logs |
| 18 source/documentation ratchet targets | 51 passed after one documentation correction | `source-ratchets.log` plus `doc-test-counts-final.log` |
| Native tests of WASM compatibility crate | 14 passed, 0 failed, 0 ignored | Surface report; separate target directory |
| Browser parser/composer and npm launcher Node tests | 8 passed, 0 failed, 0 skipped | `node-tests.log` |
| Python build-wrapper fixtures | 5 passed, 0 failed | `build-scripts-tests.log` |
| **Final successful test executions** | **273** | **260 Rust + 8 Node + 5 Python** |
| Offline baseline `cargo check --tests` | Passed with narrower CPU feature subset | `baseline-check.log` |
| Clippy, selected features, all targets | Passed; correctness/suspicious groups denied | `clippy.log` |
| Rust formatting | Passed | `format-check.log` |
| Source/test module reachability | 2,255 files checked; two documented legacy allowlist entries | `module-reachability.log` |
| Tracked Bash/Python/JavaScript syntax checks | 40 passed | `script-syntax-results.json` |
| Server/client Beta-evidence metadata checks | Both passed | `server-beta-evidence.log`, `client-beta-evidence.log` |
| Diff whitespace/error check | Passed | `git diff --check` |

The total counts successful test **executions**, including existing regressions and helper tests instantiated in multiple binaries. It does not mean 273 new or unique regression functions. Repeated exploratory runs are not added to the total.

The initial source-ratchet run had 50 passes and one failure: PTY documentation still said its LLM call-budget module contained one test when it contained two. The documentation was corrected and the already-built documentation-count test passed on rerun. The initial aggregate driver's nonzero exit is retained in its historical manifest; it is not concealed or mistaken for the final status. No existing assertion was weakened. Earlier combined build attempts also caught integration errors in newly written code/tests; final compiled and executed results supersede those attempts.

Clippy emitted pre-existing style warnings and a future-compatibility warning for `num-bigint-dig 0.8.5`. This is not a claim that all warnings have been eliminated. No speculative dependency upgrade was performed.

### Native regression targets

| Target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `agent_queue_fifo_test` | 2 | 0 | 0 |
| `audit_ci_coverage_test` | 2 | 0 | 0 |
| `client_review_regression_test` | 22 | 0 | 0 |
| `dashboard_frame_test` | 17 | 0 | 0 |
| `display_rendering_test` | 4 | 0 | 0 |
| `llm_rate_limiter_test` | 11 | 0 | 0 |
| `log_template_injection_test` | 5 | 0 | 0 |
| `log_template_test` | 10 | 0 | 0 |
| `management_test` | 7 | 0 | 0 |
| `mcp_startup_config_test` | 11 | 0 | 0 |
| `prompt_growth_test` | 14 | 0 | 0 |
| `proxy_cert_cache_test` | 3 | 0 | 0 |
| `reference_parser_test` | 12 | 0 | 0 |
| `scheduled_task_actions_test` | 2 | 0 | 0 |
| `scheduled_task_claim_test` | 8 | 0 | 0 |
| `scripting_highlight_test` | 2 | 0 | 0 |
| `scripting_manager_test` | 8 | 0 | 0 |
| `scripting_resident_test` | 15 | 0 | 0 |
| `secret_redaction_test` | 3 | 0 | 0 |
| `server_stop_cleans_scheduled_tasks_test` | 3 | 0 | 0 |
| `sqlite_identifier_test` | 1 | 0 | 0 |
| `startup_params_result_test` | 10 | 0 | 0 |
| `test_infrastructure_review_test` | 12 | 0 | 0 |
| `utils_save_load_test` | 3 | 0 | 0 |

### Focused server tests

| Filter | Passed | What was exercised |
|---|---:|---|
| `certificate_validation_test` | 4 | Invalid SAN/validity values and valid certificate behavior |
| `an_incomplete_dns_body_releases_its_connection` | 1 | Body stalls after a length prefix release the connection after the deadline |
| `rejected_link_path_does_not_leak_pty_descriptors` | 1 | Failed startup descriptor ownership in an isolated child |
| `server_removal_cancels_a_blocked_peer_write` | 1 | Server removal cancels a blocked owned writer |
| `certificate_cache_evicts_the_oldest_pair_at_its_capacity` | 1 | Full cache evicts without exceeding its cardinality bound |

### Exact CPU build/test setup

The native feature union was:

```text
tcp,http,dns,udp,redis,mcp-stdio,mcp-http,finger,tls,dot,pty,vnc,torrent-peer,proxy,ssh-agent,webrtc,ftp,nntp,pop3,http_proxy,sqlite
```

No `--all-features` run was used because that would pull in excluded embedded-model paths. The normal test environment used:

```sh
export CARGO_TARGET_DIR=/Users/matus/dev/netget/target
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=4
export RUSTC_WRAPPER=
unset NETGET_USE_OLLAMA
```

All native Cargo invocations selected `--locked --offline --no-default-features` and the feature union above. The complete argument arrays, including all 24 test target names and all 18 ratchet targets, are preserved in the JSON manifest. The command shapes were:

```sh
cargo test --locked --offline --no-default-features --features "$AUDIT_FEATURES" \
  --no-fail-fast --test TARGET_1 --test TARGET_2 -- --test-threads=32
cargo test --locked --offline --no-default-features --features "$AUDIT_FEATURES" \
  --test server FILTER -- --test-threads=32
cargo clippy --locked --offline --no-default-features --features "$AUDIT_FEATURES" \
  --all-targets -- -D clippy::correctness -D clippy::suspicious
cargo fmt --all -- --check
node --test web/test/composer_model_test.mjs web/test/telnet_test.mjs tests/npm_launcher_test.cjs
python3 tests/build_scripts_test.py
```

Here `AUDIT_FEATURES`, `TARGET_1`, `TARGET_2` and `FILTER` are explanatory placeholders for the concrete feature string/manifest arguments, not a separate executed script. Loopback-only native socket tests needed the host's sandbox allowance; they did not contact real model endpoints. The selected scripting tests ran local Python, Node and Perl interpreters with controlled fixtures.

<a id="remaining"></a>
## Remaining findings and test boundaries

The implemented batch is complete and its selected checks pass. The repository still has substantial follow-up work. The section reports preserve detailed evidence and caveats; this table collects the main actionable findings without presenting them as fixed.

| Follow-up | Why it matters | Work needed to close it |
|---|---|---|
| POP3 command/response correlation | Multiline expectations are guessed from reply wording and can wait for a nonexistent dot terminator. | Queue response expectations atomically with both command sources and test interleaving/EOF. |
| SSH agent injected commands | Generic command handling cannot execute some Custom action results and can report success without a packet. | Connect custom dispatch to actual wire writes and assert peer-observed behavior. |
| VNC type-2 authentication | Existing implementation is a documented placeholder rather than DES challenge authentication. | Implement and test the protocol's authentication exchange. |
| Buffered response/resource policies | Several HTTP-family bodies, SMB reads, interpreter output, virtual transport queues and canvas allocations remain insufficiently bounded. | Define per-path retention/backpressure/error contracts and test limits without breaking streaming use cases. |
| Scheduler extreme delays | Multiple constructors/builders add arbitrary durations to Instant and can overflow. | Adopt fallible validation before state mutation and propagate actionable errors through all task creation paths. |
| Circuit-breaker half-open ownership | Concurrent requests can pass while a probe is unresolved. | Introduce a cancellation-safe probe lease and concurrent regression cases. |
| Limiter live reconfiguration | Replaced semaphores can overlap old/new permit pools; cancellation accounting is incomplete. | Define hot-reconfiguration semantics and test outstanding/queued permits. |
| Legacy settings migration | A legacy `~/.netget` file conflicts with a newer `~/.netget/` directory expectation. | Non-destructive migration, rollback and explicit filesystem fixtures. |
| Full session persistence | Saves are not a full image of pipes/easy instances/tasks and lack universal atomic replacement. | Versioned representation and atomic-write/recovery design. |
| Process and evaluator lifecycle | Descendant processes, output retention and eval stdin/output sequencing have additional failure cases. | Concurrent I/O/deadlines, explicit truncation and process-tree cleanup fixtures. |
| Per-connection peer shutdown | Server-wide cleanup is covered; closing a single peer while its write blocks needs separate ownership. | Connection-scoped cancellation and regression. |
| QUIC SAN extraction | Its adapter still filters malformed non-string SAN values separately. | Share strict extraction and test malformed arrays. |
| npm artifact provenance/platform behavior | Fallback downloads lack checksum/signature verification; Windows behaviors were not exercised. | Coordinate release manifests, verification and platform tests. |
| Browser/display parity | No actual wasm-target/browser run; huge/deep canvas trees and some UDP readiness/peek interactions remain. | CPU-safe browser fixtures, limits and explicit parity tests. |
| Broad interoperability and documentation history | Static sweeps do not establish protocol completeness; historical docs have contradictory claims. | Per-protocol peers/oracles and evidence-backed documentation refresh. |

The following were **not executed**: GPU capability checks or workloads; embedded or remote real models; a complete all-features build or complete repository test suite; live external protocol services; new fuzz campaigns; real browser/Playwright/model demos; Windows/Linux/mobile hardware-dependent tests; release builds for every platform; deployments or publication. Feature-specific code outside the selected native union was primarily reviewed statically. The compatibility-crate tests ran natively and do not certify wasm-target integration.

Local Beta-evidence checks reported 60 Beta / 105 Experimental / 4 Stable server entries and 13 Beta / 89 Experimental client entries. Those are metadata consistency results, not fresh interoperability certification. Vendor comparison establishes local patch scope, not security currency. No external standards, prices, dependency releases or historical benchmark claims were refreshed by this source-code task.

<a id="changes"></a>
## Changed-file ledger

This ledger excludes pre-existing untracked user files, generated build outputs and the audit report artifacts. Line counts are final whole-file sizes, not lines changed. Final content hashes are available in `audit/2026-10-01/changed-files.json`.

| File | Change | Final lines |
|---|---|---:|
| `.github/workflows/ci.yml` | modified | 1401 |
| `.github/workflows/fuzz.yml` | modified | 155 |
| `.github/workflows/nightly-eval.yml` | modified | 131 |
| `.github/workflows/nightly-soak.yml` | modified | 115 |
| `cargo-isolated.sh` | modified | 77 |
| `cargo.sh` | modified | 148 |
| `crates/netget-tokio-wasm/src/net.rs` | modified | 816 |
| `crates/netget-tokio-wasm/src/time.rs` | modified | 348 |
| `crates/netget-tokio-wasm/src/time_math.rs` | added | 22 |
| `crates/netget-tokio-wasm/tests/time_math_test.rs` | added | 38 |
| `crates/netget-tokio-wasm/tests/udp_receive_test.rs` | added | 68 |
| `examples/external_protocol/Cargo.toml` | modified | 18 |
| `examples/external_protocol/README.md` | modified | 41 |
| `examples/external_protocol/src/lib.rs` | modified | 151 |
| `examples/test_doc_gen.rs` | modified | 60 |
| `npm/netget/bin/netget.js` | modified | 183 |
| `scripts/sccache/cargo-sccache.sh` | modified | 47 |
| `scripts/sccache/setup-sccache-r2.sh` | modified | 88 |
| `scripts/sccache/setup-sccache-upstash.sh` | modified | 79 |
| `site/js/composer.js` | modified | 503 |
| `site/js/demo.js` | modified | 1383 |
| `site/js/telnet.js` | added | 63 |
| `src/cli/management.rs` | modified | 1355 |
| `src/cli/mod.rs` | modified | 780 |
| `src/cli/tasks.rs` | modified | 410 |
| `src/client/ftp/CLAUDE.md` | modified | 133 |
| `src/client/ftp/mod.rs` | modified | 337 |
| `src/client/http/CLAUDE.md` | modified | 335 |
| `src/client/http_fetch/transport.rs` | modified | 382 |
| `src/client/http_proxy/CLAUDE.md` | modified | 226 |
| `src/client/http_proxy/mod.rs` | modified | 802 |
| `src/client/llm_budget.rs` | modified | 210 |
| `src/client/mod.rs` | modified | 626 |
| `src/client/nntp/CLAUDE.md` | modified | 243 |
| `src/client/nntp/mod.rs` | modified | 645 |
| `src/client/pop3/CLAUDE.md` | modified | 237 |
| `src/client/pop3/mod.rs` | modified | 456 |
| `src/client/response_reader.rs` | added | 76 |
| `src/client/ssh_agent/CLAUDE.md` | modified | 247 |
| `src/client/ssh_agent/mod.rs` | modified | 633 |
| `src/client/torrent_peer/CLAUDE.md` | modified | 177 |
| `src/client/torrent_peer/mod.rs` | modified | 532 |
| `src/client/vnc/CLAUDE.md` | modified | 285 |
| `src/client/vnc/mod.rs` | modified | 1046 |
| `src/client/webrtc/mod.rs` | modified | 1141 |
| `src/display/ascii.rs` | modified | 68 |
| `src/display/canvas.rs` | modified | 506 |
| `src/display/text.rs` | modified | 113 |
| `src/easy/http/actions.rs` | modified | 439 |
| `src/llm/agent_queue.rs` | modified | 270 |
| `src/llm/conversation_state.rs` | modified | 323 |
| `src/llm/rate_limiter.rs` | modified | 610 |
| `src/llm/reference_parser.rs` | modified | 203 |
| `src/mcp_stdio/CLAUDE.md` | modified | 417 |
| `src/mcp_stdio/mod.rs` | modified | 82 |
| `src/mcp_stdio/tools.rs` | modified | 2255 |
| `src/pipe/mod.rs` | modified | 419 |
| `src/protocol/log_template.rs` | modified | 285 |
| `src/protocol/spawn_context.rs` | modified | 611 |
| `src/scripting/CLAUDE.md` | modified | 343 |
| `src/scripting/highlight.rs` | modified | 64 |
| `src/scripting/resident.rs` | modified | 760 |
| `src/scripting/types.rs` | modified | 281 |
| `src/server/dot/CLAUDE.md` | modified | 402 |
| `src/server/dot/mod.rs` | modified | 621 |
| `src/server/peer_support.rs` | modified | 240 |
| `src/server/proxy/CLAUDE.md` | modified | 513 |
| `src/server/proxy/cert_cache.rs` | modified | 312 |
| `src/server/pty/CLAUDE.md` | modified | 102 |
| `src/server/pty/mod.rs` | modified | 360 |
| `src/server/tls/CLAUDE.md` | modified | 577 |
| `src/server/tls_cert_manager.rs` | modified | 399 |
| `src/state/app_state.rs` | modified | 3302 |
| `src/state/sqlite.rs` | modified | 612 |
| `src/tui/event_loop.rs` | modified | 268 |
| `src/tui/modal/text_editor.rs` | modified | 104 |
| `src/tui/render/chat.rs` | modified | 131 |
| `src/tui/render/stream.rs` | modified | 261 |
| `src/utils/redact.rs` | modified | 80 |
| `src/utils/save_load.rs` | modified | 209 |
| `tests/agent_queue_fifo_test.rs` | added | 59 |
| `tests/audit_ci_coverage_test.rs` | added | 58 |
| `tests/build_scripts_test.py` | added | 91 |
| `tests/client_review_regression_test.rs` | added | 411 |
| `tests/dashboard_frame_test.rs` | modified | 652 |
| `tests/display_rendering_test.rs` | added | 107 |
| `tests/helpers/common.rs` | modified | 527 |
| `tests/helpers/llm_live.rs` | modified | 691 |
| `tests/helpers/netget.rs` | modified | 1449 |
| `tests/llm_rate_limiter_test.rs` | modified | 407 |
| `tests/log_template_test.rs` | modified | 127 |
| `tests/management_test.rs` | modified | 319 |
| `tests/mcp_startup_config_test.rs` | modified | 189 |
| `tests/npm_launcher_test.cjs` | added | 39 |
| `tests/prompt_growth_test.rs` | modified | 286 |
| `tests/reference_parser_test.rs` | modified | 185 |
| `tests/scheduled_task_claim_test.rs` | added | 138 |
| `tests/scripting_resident_test.rs` | modified | 674 |
| `tests/secret_redaction_test.rs` | modified | 90 |
| `tests/server/dot/CLAUDE.md` | modified | 272 |
| `tests/server/dot/connection_bounds_test.rs` | modified | 216 |
| `tests/server/proxy/CLAUDE.md` | modified | 300 |
| `tests/server/proxy/certificate_cache_bound_test.rs` | added | 57 |
| `tests/server/proxy/mod.rs` | modified | 16 |
| `tests/server/pty/CLAUDE.md` | modified | 61 |
| `tests/server/pty/mod.rs` | modified | 7 |
| `tests/server/pty/startup_cleanup_test.rs` | added | 74 |
| `tests/server/tcp/CLAUDE.md` | modified | 219 |
| `tests/server/tcp/mod.rs` | modified | 6 |
| `tests/server/tcp/peer_lifecycle_test.rs` | added | 102 |
| `tests/server/tls/CLAUDE.md` | modified | 320 |
| `tests/server/tls/certificate_validation_test.rs` | added | 63 |
| `tests/server/tls/mod.rs` | modified | 12 |
| `tests/sqlite_identifier_test.rs` | added | 51 |
| `tests/startup_params_result_test.rs` | modified | 184 |
| `tests/test_infrastructure_review_test.rs` | added | 178 |
| `tests/utils_save_load_test.rs` | modified | 110 |
| `web/test/composer_model_test.mjs` | added | 44 |
| `web/test/telnet_test.mjs` | added | 41 |

<a id="core"></a>
## Shared core, build tooling and CI review — 2026-10-01

**Coordinator completion note:** The final combined CPU regression, Clippy, formatting and source-ratchet outcomes are recorded above. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and method

The coordinator reviewed shared LLM bookkeeping and parsing, configuration persistence,
credential display, logging/utilities, the executable/build surface, scripts, CI and the
whole-tree coverage mechanisms. Other reports cover client/server implementations,
runtime management, UI/browser code, scripts/MCP execution and test infrastructure.

The inventory snapshot contains **3,342 tracked files and 1,250,366 text lines**. These
include documentation, test fixtures, corpus inputs, vendored source and implementation;
the line total is not a count of production code. The whole-source heuristic scan covers
**811 tracked Rust source files and 512,054 source lines** at its checkpoint, including
unchanged files. New source introduced afterward is also covered by targeted review and
the final changed-file ledger. The inventory records paths, byte counts, line counts and
hashes; the static scan records review-signal line numbers without exposing local runtime
configuration or logs.

This is complete inventory/section coverage plus targeted deep review, not a claim that
1.25 million lines were each manually verified or every protocol behavior was executed.
The risk scans include comments and intentional constructs: their counts are leads, not
defect counts. No unrelated untracked user files were removed, staged or included as audit
artifacts. No commit, push, deployment, publication or third-party message occurred.

### Implemented improvements

#### C1. Save/load preserves directory components

`normalize_filename` previously used `Path::file_stem` without restoring its parent path.
Saving `/chosen/location/session.json` therefore wrote `session.netget` in the process
working directory; loading through the same input path could likewise read the wrong
file. Replacing only the extension preserves absolute and relative parent directories,
including a filename already ending in `.netget` and the hidden `.netget` filename.
Existing whitespace trimming and ordinary basename extension replacement remain.

Files: `src/utils/save_load.rs`, `tests/utils_save_load_test.rs`.

#### C2. Saved instances retain routing and feedback behavior

Server/client save actions omitted `event_handlers` and `feedback_instructions`. Reloading
a saved deterministic/manual instance could therefore change who answers its events.
Both the all-instance and individual-instance paths now serialize the configured handler
array and feedback instructions. Optional absent values remain absent. The existing
action parser accepts these fields, including the serialized wildcard representation.

Individual saves previously manufactured partial `ServerInstance`/`ClientInstance`
objects with many defaulted fields. They now use the actual state snapshot through the
read APIs, removing the divergence that would otherwise keep losing future fields.

The regression creates server/client state without opening sockets or contacting a model,
saves each separately and together into a temporary directory, loads all three files,
checks the returned paths and feedback fields, and reparses the restored handler rules.

#### C3. Queued requests recheck the token budget

The limiter checked token capacity before waiting for concurrency. A queued request could
pass that check, wait while the preceding request spent the remaining allowance, and
still receive a permit. The budget check now also occurs after the concurrency permit is
acquired. Network requests return the existing typed TokenLimit error and release their
permit; user requests retain the existing wait-for-budget behavior.

The regression holds the sole permit, waits until a second request is demonstrably queued,
records the first request's final usage, and verifies that releasing the first request
causes the second to be refused exactly once with no leaked queue slot.

#### C4. Extreme usage/window values remain safe

Backend token counters and aggregate window totals now saturate instead of overflowing.
A very large reported count cannot wrap into apparent free capacity or panic a debug
build. Window filtering compares elapsed ages to the configured duration instead of
subtracting an arbitrary u64 duration from Instant, which could panic for huge windows.
The regression supplies u64::MAX usage and a u64::MAX window, verifies saturated totals,
and requires the exhausted budget to stay closed.

#### C5. Limiter diagnostics avoid nested lock ordering

Configuration and usage are copied/read before taking statistics locks; the refusal path
does not hold the statistics mutex while awaiting the configuration read lock. This removes
the previous inversion with statistics readers and a queued configuration writer. Network
and model waits continue to happen outside these locks. An independent subagent reviewed
permit release and lock lifetimes in the final diff.

Files for C3–C5: `src/llm/rate_limiter.rs`, `tests/llm_rate_limiter_test.rs`.

#### C6. Credential redaction includes bearer and header credentials

The shared redactor covered passwords/secrets/API keys but missed access/refresh/identity/
auth tokens, generic `token`, HTTP Authorization/Proxy-Authorization and cookies. It now
covers those names, camelCase token spellings and hyphenated header names. Counters such
as `input_tokens`/`max_tokens` and endpoint metadata such as `token_url` remain useful.
Redaction still copies values for display: it does not alter credentials sent on the wire.
Null values and the existing recursion-depth guard retain their behavior.

Files: `src/utils/redact.rs`, `tests/secret_redaction_test.rs`.

#### C7. Reference extraction treats block contents as opaque

Nested tag-like content could produce overlapping removal ranges. Removing the inner
range invalidated the outer indices and could panic while processing model text.
Matched outer reference bodies now remain opaque, including nested tags and Unicode.
Extraction also tracks quoted JSON content and escaped quotes, preserving embedded
placeholders such as `"prefix <script1> suffix"` before an external block definition.

#### C8. Reference resolution is literal, deterministic and valid JSON

Repeated HashMap-driven replacements could interpret placeholders inside an inserted
script, making results depend on iteration order. One regex replacement pass touches only
the original placeholders. A shared lazily initialized regex avoids recompilation on every
extraction/detection call. JSON serialization escapes the entire ASCII control-character
range, not just newline/tab/quote/backslash, so NUL and other controls no longer corrupt
resolved action JSON.

Regressions cover nested blocks, Unicode, every JSON control character, nonrecursive
replacement, mixed inline placeholders and escaped JSON quotes through the complete
extract/resolve/parse path.

Files for C7–C8: `src/llm/reference_parser.rs`, `tests/reference_parser_test.rs`.

#### C9. Tiny conversation windows and empty messages respect storage limits

The per-message cap had a 256-byte minimum regardless of the configured history window,
and appended a truncation marker outside the cap. A small/zero history could therefore
exceed its own limit. The cap now fits the configured window and includes the marker when
space permits. Empty messages no longer accumulate indefinitely while consuming zero
bytes of the eviction budget. UTF-8 truncation remains character-safe.

Tests exercise zero/tiny/ordinary limits with mixed Unicode and repeated long messages,
then add thousands of empty messages and require history to stay empty.

Files: `src/llm/conversation_state.rs`, `tests/prompt_growth_test.rs`.

#### C10. Fuzz CI includes every declared harness

`zabbix_packet`, `gearman_packet` and `nostr_message` were declared in the fuzz manifest
but absent from the dispatched matrix. All 29 declared targets now appear. A Rust test
parses the actual TOML and YAML, requires equal nonempty target sets and rejects duplicate
matrix entries. The test is explicitly wired into the blocking source-ratchet job.
Fuzz searches themselves were not launched during this audit.

#### C11. Workflow inputs remain data instead of shell source

Manual nightly eval and soak inputs were directly interpolated into generated shell text.
The fuzz budget took the same unsafe route indirectly through a GitHub env expression.
They now enter shell scripts through environment variables and quoted argument expansion;
the protocol list is split into a Bash array without evaluating its contents. Fuzz budgets
must be positive decimal integers. Matrix target names remain workflow-owned constants.
The soak's descriptor limit now runs in the same shell as the workload, so it actually
applies; the previous separate step's shell limit was discarded on exit. Soak commands
also use the lockfile explicitly.

Files for C10–C11: `.github/workflows/{ci,fuzz,nightly-eval,nightly-soak}.yml`,
`tests/audit_ci_coverage_test.rs`. These workflows were edited and locally checked;
none was dispatched and no live eval was run.

#### C12. Build wrappers execute the intended command

`cargo.sh` used post-increment under `set -e`; the first successful cleanup returned an
arithmetic status of one and terminated before Cargo ran. Assignment arithmetic fixes the
control flow. `cargo-isolated.sh` now respects an explicitly empty RUSTC_WRAPPER as a
request to disable wrapping. The sccache wrapper resolves the root wrapper through the
correct two-parent path and its missing-sccache fallback actually disables sccache.

#### C13. Generated cache credentials are quoted literal values

The interactive cache setup scripts wrote credential input into double-quoted shell source
and later sourced it. Embedded quotes, command substitutions or backticks could change
its meaning on reload. Bash printf `%q` writes literal values. A restrictive umask applies
before file creation; the existing chmod remains. Reads preserve backslashes, and the
Redis credential prompt suppresses echo. No real credential setup was executed.

Five Python fixture tests use copied wrappers, stub Cargo/ps commands and temporary config
paths. They prove cleanup reaches Cargo, explicit wrapper disablement, fallback path and
argv preservation, failed Cargo status propagation, and exact round-trip of shell-special
credential text without executing it. They also assert 0600 permissions. The fixture suite
is wired into CI and passed locally.

Files for C12–C13: root Cargo wrappers, `scripts/sccache/*.sh`,
`tests/build_scripts_test.py`.

### Validation and review evidence

- Baseline offline CPU-feature `cargo check --tests` passed in 6m34s before the combined
  regression runs. It compiled tests; it did not execute the live-model suites.
- All 40 tracked shell/Python/JavaScript sources passed Bash syntax, Python AST or Node
  syntax checks. Details: `script-syntax-results.json`.
- Server and client Beta-evidence static checks both passed. Their reported metadata totals
  were server 60 Beta / 105 Experimental / 4 Stable; client 13 Beta / 89 Experimental.
  These are local metadata audit results, not fresh interoperability certification.
- Build script fixture suite: 5 passed.
- Root parser/persistence/limiter changes received independent subagent review; the review
  identified inline JSON extraction and camelCase redaction omissions, which were fixed.
- Native regression, source-ratchet, clippy/format and server checks are recorded centrally
  in the consolidated summary. This section does not infer execution from source review.

### Remaining shared-core risks and boundaries

1. Circuit-breaker acquire clears its open timestamp when allowing a probe; concurrent
   requests can then pass before the probe resolves. A cancellation-safe probe lease needs
   a coordinated API/call-site change and concurrent cancellation tests.
2. Dynamic limiter semaphore replacement can temporarily overlap old and new permit pools.
   User-wait statistics also need cancellation accounting. This batch fixes token-budget
   sequencing and arithmetic, not all hot-reconfiguration semantics.
3. Conversation content caps do not constitute a total heap budget: parsed action metadata,
   tool metadata and protocol documentation tracking are separate allocations. Huge nested
   in-memory JSON remains a different problem from the tested content-byte limit.
4. Several HTTP/model/tool response paths still buffer full response bodies before trimming
   display text. Streaming byte limits and timeout semantics need a consistent API across
   those paths. Local file-read size checks can also race file growth.
5. `Settings` uses a legacy `~/.netget` file while NetGetConfig expects a `~/.netget/`
   directory. A non-destructive migration with rollback and explicit path fixtures is
   required to reconcile existing installations. No migration or direct home-configuration
   edit was attempted; normal application test startup may read its existing settings.
6. Save files are not yet atomically replaced on all targets, and the save representation
   does not capture every runtime capability such as pipes/easy instances/scheduled tasks.
   The added handler/feedback round-trip is intentionally narrower than a full session image.
7. The isolated-kill helper still targets legacy per-session directories while current build
   wrappers share a target directory. It was inspected, not run or broadened to risk killing
   unrelated builds. Current compilation was managed through its exact tool session.
8. GPU/embedded inference, hardware-backed protocols, mobile/Windows builds, real browsers
   with model runtimes, production services and release publishing were not executed.
9. Documentation under archive and historical evaluation outputs is evidence of earlier
   work, not refreshed measurement. No external claims/prices/library releases were inferred
   from it. Dependency versions and lockfiles were not upgraded speculatively.

All remaining items are follow-up findings, not passed checks. Detailed per-protocol and
per-surface limitations are preserved in the other six reports.

<a id="servers"></a>
## Server review — 2026-10-01

**Coordinator completion note:** All eight focused server regressions passed. The separate proxy_cert_cache_test target also passed three tests. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and evidence standard

This section review covers `src/server/**` and `tests/server/**`. At the initial inventory there were **434 Rust source files / 302,242 source lines**, **815 Rust test files / 189,321 test lines**, **166 immediate source directories**, and **seven shared source files**. `oracle/` contains planning documentation only; it is not an implemented or registered server. `http_common/` is shared HTTP infrastructure, while `usb/` contains multiple nested protocols.

Every directory and Rust file participated in structural and risk-pattern scans. Deep manual inspection concentrated on shared lifecycle/TLS code, framed stream reads and allocations, unchecked conversions, platform resource ownership, HTTP body limits, and certificate caching. **This is not a claim that every line received an independent manual proof or every protocol was exercised.** The table below identifies the complete scan surface and focused follow-ups.

No GPU computation, embedded model execution, real LLM endpoint, public protocol service, privileged raw socket, kernel device installation, deployment, or commit was used. New tests are pure CPU/in-process checks or a local TLS session with an incomplete message that cannot trigger a model call. Cargo validation is centralized by the root agent to avoid shared-target contention.

### Implemented changes

#### S1. Certificate input validation returns errors instead of panicking

**Files:** `src/server/tls_cert_manager.rs`; `tests/server/tls/certificate_validation_test.rs`; TLS test registration and documentation.

The SAN builder previously called `try_into().unwrap()` on names coming from user/model startup parameters. A non-ASCII DNS SAN therefore panicked instead of returning the function's advertised `Result`. Certificate validity used `Duration::days(i64)` followed by unchecked date addition: extreme values overflowed duration construction or the supported date range, and nonpositive values created certificates with invalid or empty lifetimes. Startup SAN arrays silently dropped values that were not strings.

The implementation now collects fallible SAN conversions with contextual errors, requires a positive lifetime, checks the day-to-second multiplication, uses `OffsetDateTime::checked_add`, and rejects malformed SAN array elements with their index. Signing starts only after validation. The startup parameter description explains the positive/range requirement.

**Regression coverage:** non-ASCII SAN; zero, negative, minimum and maximum signed lifetimes; duration values that fit seconds but exceed the date range; a successful one-day wildcard certificate; numeric/null/object elements in the startup SAN array. Four CPU-only tests. DNS syntax beyond the existing rcgen IA5 conversion is not broadened by this change.

#### S2. DoT partial bodies have a finite deadline

**Files:** `src/server/dot/mod.rs`; `tests/server/dot/connection_bounds_test.rs`; protocol/test documentation.

The server bounded the TLS handshake and DNS length-prefix read but awaited the DNS body without a timeout. A peer sending a two-byte length and a partial body could permanently hold a TLS session, task and connection permit. The five-minute between-query deadline was no longer being polled.

The body read now has a separate **10-second completion deadline** and a `decision=fail_closed_read_timeout` diagnostic. The normal between-query timeout remains 300 seconds. The timeout surrounds only the network body read; model/manual handling is outside it.

**Regression coverage:** establish a real loopback TLS connection, send a 12-byte declared DNS message with only one body byte, and require connection closure before a 15-second test deadline. No complete query exists and no model is invoked. Existing peer cleanup releases the cap slot when the connection handler exits.

#### S3. Failed PTY setup releases both descriptors

**Files:** `src/server/pty/mod.rs`; `tests/server/pty/startup_cleanup_test.rs`; PTY test registration and documentation.

After `openpty`, the slave descriptor immediately became an `OwnedFd`, but the master stayed a raw integer until after raw-mode configuration, slave-path resolution, symlink creation and nonblocking setup. Any error before the conversion leaked the master. An existing ordinary file in `link_path` was a deterministic trigger.

The master becomes a `File` immediately after allocation, before every fallible setup step. Rust now drops both descriptors on all those error returns; successful startup passes the same owned master into `AsyncFd`.

**Regression coverage:** an isolated invocation of the test executable attempts 16 startups against a regular file, requires the documented rejection, checks the file contents survive, and compares `/dev/fd` counts before/after. The subprocess prevents unrelated concurrent tests from corrupting the count. No server loop or model starts.

#### S4. Shared peer-command workers belong to the server

**Files:** `src/server/peer_support.rs`; `tests/server/tcp/peer_lifecycle_test.rs`; TCP test registration/documentation.

The shared peer-command helper detached its worker with `tokio::spawn`. Dropping the command sender at teardown only terminates a worker waiting on `recv`; it cannot cancel a worker already awaiting a blocked socket write or action. Such a worker retained the writer and state after server removal.

The helper now registers the worker with `AppState::register_server_task`. A short registration task preserves the synchronous API used by existing protocol callers. If server removal wins the registration race, the existing registration API immediately aborts the worker. This fixes server teardown centrally without changing protocol action behavior or signatures.

**Regression coverage:** a fake `AsyncWrite` announces its first poll and stays pending; the test removes the owning server and requires writer destruction and cancellation of the reply sender, while deliberately retaining the command sender. No network or model is involved.

**Reach:** the following 45 protocol modules invoke this helper: `amqp`, `beanstalkd`, `bitcoin`, `bolt`, `cassandra`, `db2`, `dc`, `dict`, `finger`, `ftp`, `gearman`, `gemini`, `gopher`, `ident`, `imap`, `irc`, `kafka`, `m3ua`, `memcached`, `modbus`, `mongodb`, `mqtt`, `mssql`, `nats`, `nntp`, `nostr`, `pop3`, `rdp`, `redis`, `reverse_shell`, `rtsp`, `smb`, `smtp`, `stomp`, `svn`, `tcp`, `telnet`, `tls`, `tor_relay`, `torrent_peer`, `torrent_tracker`, `vnc`, `whois`, `xmpp`, `zabbix`. A normal connection close during a blocked injected write, while its server continues running, remains a distinct lifecycle case and is not claimed as fixed here.

#### S5. MITM leaf certificate cache has a cardinality bound

**Files:** `src/server/proxy/cert_cache.rs`; `tests/server/proxy/certificate_cache_bound_test.rs`; proxy test registration/documentation.

The per-domain cache retained certificates and private keys for 24 hours with hourly expired-entry cleanup but no entry cap. Unique peer-selected hostnames could grow it independently of the concurrent connection cap.

The cache now retains at most **1,024 certificate/key pairs**. A new domain at capacity evicts the oldest generated entry under the same write lock used for insertion, so concurrent misses cannot race above the bound. Replacing the same hostname uses its existing slot. Active TLS sessions own their copied certificate/key material and continue normally; an evicted domain generates a new pair on a future lookup. The policy is oldest-generation eviction, not LRU.

**Regression coverage:** fill the cache, prove a hit retains the original identity, insert beyond capacity, require oldest-pair regeneration, and prove the newest cached certificate still has the same matching key. An existing separate target, `tests/proxy_cert_cache_test.rs`, covers generation, key/certificate pairing, and normalization; the root agent has its validation command.

### Validation and execution status

- Individual changed Rust files were formatted with `rustfmt --edition 2021 --config skip_children=true`; successful.
- `git diff --check -- src/server tests/server`; successful at the local review checkpoint.
- Structural audit: every directory under `tests/server/` is declared in its parent module; no orphaned test directory found.
- Structural audit: no production `#[cfg(test)]` or inline `mod tests` found under `src/server/`.
- Every source section containing `TcpListener` also references `accept_bounded` or `ConnectionLimiter`; this is a lexical adoption check, not proof that every path retains its permit correctly.
- `src/server/oracle/` is the only source directory absent from `src/server/mod.rs`; it contains no Rust and explicitly describes planned work, so no registration was added.
- New test modules are explicitly declared in the existing per-protocol `mod.rs` files.
- Cargo outcomes are supplied by the root agent's centralized validation and the main report. They must not be inferred from the existence of these tests.

Requested targeted commands, through the repository wrapper with a CPU-only feature union:

```sh
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test server -- certificate_validation_test --test-threads=100
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test server -- an_incomplete_dns_body_releases_its_connection --test-threads=100
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test server -- rejected_link_path_does_not_leak_pty_descriptors --test-threads=100
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test server -- server_removal_cancels_a_blocked_peer_write --test-threads=100
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test server -- certificate_cache_bound_test --test-threads=100
./cargo-isolated.sh test --no-default-features --features tcp,tls,dot,pty,proxy --test proxy_cert_cache_test -- --test-threads=100
```

### Review method and checked risk clusters

The scans inspect allocation/read sites (`read_exact`, `read_to_end`, collection, `Vec` sizes), panicking operations (`unwrap`, `expect`, explicit panic macros), literal/indexed slices, unchecked shifts, task spawning and registration, listener-cap references, time arithmetic, unsafe blocks, filesystem mutation, and per-directory test/module presence. Lexical hits include comments and deliberately safe operations and are not counted as defects.

- **Shared infrastructure:** read `accept_bounded.rs`, `connection.rs`, `socket_helpers.rs`, `server_trait.rs`, `peer_support.rs`, `tls_cert_manager.rs`, and module gating. Existing semaphore admission/RAII, refusal-write timeout, bounded idle readers and busy guards were inspected. The peer worker and TLS defects above were the actionable changes.
- **Framed TCP/TLS:** inspected DoT, LLMNR, AMQP, SMB, MongoDB, ZooKeeper, Kafka, RDP, VNC and SVN framing/read/allocation sites. Existing maximum lengths and read-wrapper deadlines explain many superficially unbounded `read_exact` calls. DoT's body deadline was genuinely absent.
- **HTTP and HTTP-derived protocols:** scanned all `collect()` calls; inspected `http_common`, DoH, OpenAI, OpenAPI, etcd, WebDAV, Git, Mercurial and Ollama collection sites. Those inspected collections already use bounded bodies. No mechanical replacement was made merely because `.collect()` appeared.
- **Proxy:** inspected request/response handling, certificate generation/cache/TTL cleanup, and MITM body preview slicing. Byte-slice preview truncation uses `from_utf8_lossy` and is not a UTF-8 boundary panic. Certificate cache cardinality required the implemented bound.
- **UDP/datagrams:** inspected task-registration and buffer/read structure in DNS, CoAP, UDP, NTP, syslog and TFTP; scanned every datagram protocol's source. No live packet service or privileged socket was started.
- **Platform transports:** inspected PTY/FIFO ownership and relevant raw-socket conversion sites. Raw socket buffers are converted to slices from the returned initialized byte count; platform correctness is not claimed from static inspection. PTY ownership had a concrete error-path leak.
- **USB/BLE:** all nested source files were scanned. The USB transport guard and bounded allocation sites, mapped disk ownership and keyboard handler adaptations received focused checks. No USB device, BLE adapter, FIDO operation, disk-image mutation or privileged test was run.
- **Parser/codec inventory:** all code containing slicing, allocations and panic patterns was scanned; focused validation inspected NSQ, Gearman, OTLP decompression, VNC/RDP allocation limits and guarded wire slices. Existing recursive-parser limits and fuzz suites were inventoried but not fuzzed in this review.

### Remaining limits and follow-ups

1. Running all server E2E tests would start optional programs, devices and some real-model modes; the review intentionally requests exact CPU-safe regressions instead. Interoperability coverage, packet-dissection oracles, fuzz execution, timing at production load and protocol completeness remain at their previous evidence levels.
2. The QUIC startup adapter independently filters non-string SAN entries before calling the shared generator. Shared certificate generation is now panic-safe, but the stricter malformed-array rejection added to the common TLS extractor does not automatically reach this adapter. Consolidating its parameter extraction would remove that discrepancy.
3. The generic peer-command change fixes **server removal**. To bound a blocked peer write after only that peer is closed, the task needs a connection-scoped cancellation mechanism; command-channel closure alone is insufficient while a write is pending. Existing per-protocol write/deadline handling is not uniformly proven by this review.
4. Several protocol `CLAUDE.md` files contain historical contradictions (for example older unbounded-connection claims alongside later connection-bound sections). Touched claims relevant to fixes were updated; wholesale rewriting of all protocol histories was outside this code-focused pass.
5. Source-pattern absence is not safety proof. Arithmetic, parser and resource defects outside the focused paths may remain. No protocol maturity rating was raised on the strength of these scans.

### Complete per-directory coverage ledger

Counts below are the initial inventory. `cap` means an `accept_bounded` or `ConnectionLimiter` reference exists; `timeout` means a timeout-related token exists; `unsafe` counts explicit unsafe-block tokens. These are triage signals, not pass/fail ratings. Every listed section received the same structural/risk scan; focused notes identify extra manual work or direct fixes. Test counts are Rust files, not test cases. USB tests are split among `usb_*` directories; shared HTTP tests also live outside this tree.

| Source section | Rust files | Source lines | Same-name test Rust files | Scan signals | Focused review / disposition |
|---|---:|---:|---:|---|---|
| `amqp` | 3 | 4,214 | 6 | TCP, cap, timeout | Inspected frame allocation cap and outer timeout ownership. |
| `arp` | 2 | 1,006 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `beanstalkd` | 3 | 2,200 | 9 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `bgp` | 3 | 3,128 | 7 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `bitcoin` | 2 | 1,796 | 4 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `bluetooth_ble` | 2 | 2,111 | 5 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_battery` | 2 | 435 | 5 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_beacon` | 4 | 1,853 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_cycling` | 2 | 320 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_data_stream` | 2 | 321 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_environmental` | 2 | 337 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_file_transfer` | 2 | 335 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_gamepad` | 2 | 386 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_heart_rate` | 2 | 398 | 5 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_keyboard` | 2 | 497 | 5 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_mouse` | 2 | 471 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_presenter` | 2 | 554 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_proximity` | 2 | 334 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_remote` | 2 | 524 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_running` | 2 | 327 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_thermometer` | 2 | 322 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bluetooth_ble_weight_scale` | 2 | 318 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `bolt` | 5 | 3,170 | 10 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `bootp` | 2 | 963 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `can` | 4 | 2,460 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `cassandra` | 2 | 3,025 | 5 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `cdp` | 3 | 2,302 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `coap` | 3 | 2,005 | 6 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `couchdb` | 2 | 1,924 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `datalink` | 2 | 737 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `db2` | 3 | 1,509 | 4 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `dc` | 2 | 1,473 | 5 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `dhcp` | 2 | 1,206 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `dhcpv6` | 2 | 1,937 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `dict` | 3 | 1,794 | 8 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `dns` | 2 | 1,352 | 6 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `docker` | 3 | 2,221 | 6 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `doh` | 2 | 1,044 | 5 | TCP, cap, timeout, limited-body | Focused TLS/ALPN and limited HTTP body inspection. |
| `dot` | 2 | 822 | 5 | TCP, cap, timeout | Fixed missing DNS body deadline; real TLS partial-message regression. |
| `dynamo` | 2 | 879 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `eapol` | 3 | 2,870 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `elasticsearch` | 2 | 1,466 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `etcd` | 2 | 1,866 | 6 | TCP, cap, timeout, limited-body | Confirmed bounded request collection before gRPC frame parsing. |
| `finger` | 2 | 1,256 | 3 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `ftp` | 2 | 1,587 | 7 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `gearman` | 3 | 1,772 | 8 | TCP, cap, timeout | Inspected fixed-size header guarded conversions. |
| `gemini` | 3 | 1,528 | 9 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `git` | 4 | 1,900 | 3 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `gopher` | 2 | 1,047 | 4 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `grpc` | 2 | 1,891 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `gtp` | 3 | 4,354 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `hls` | 2 | 1,118 | 5 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `hsrp` | 3 | 2,126 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `http` | 2 | 1,325 | 7 | cap, timeout | Scanned shared HTTP delegation and TLS startup path. |
| `http2` | 4 | 1,753 | 5 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `http_common` | 3 | 937 | 0 | limited-body | Focused bounded HTTP body and response builder review; tests elsewhere. |
| `icmp` | 2 | 1,966 | 3 | timeout, unsafe=1 | Structural/risk scan; no demonstrated defect changed in this section. |
| `ident` | 2 | 1,226 | 3 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `igmp` | 2 | 1,240 | 3 | unsafe=2 | Structural/risk scan; no demonstrated defect changed in this section. |
| `imap` | 2 | 2,560 | 10 | cap, timeout, limited-body | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `ipp` | 2 | 1,660 | 6 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `ipsec` | 2 | 832 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `irc` | 3 | 1,581 | 7 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `isis` | 2 | 1,489 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `jsonrpc` | 2 | 1,151 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `kafka` | 2 | 2,599 | 5 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `kubernetes` | 4 | 2,573 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `ldap` | 2 | 2,854 | 6 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `lldp` | 3 | 2,700 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `llmnr` | 2 | 1,588 | 3 | TCP, cap, timeout | Inspected per-prefix and per-body read deadlines. |
| `m3ua` | 3 | 3,230 | 4 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `maven` | 2 | 1,390 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `mcp` | 3 | 2,259 | 5 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `mdns` | 2 | 836 | 3 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `memcached` | 3 | 2,065 | 8 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `mercurial` | 2 | 1,458 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `modbus` | 3 | 2,719 | 9 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `mongodb` | 2 | 1,772 | 9 | TCP, cap, timeout | Inspected minimum length, maximum frame and body deadline. |
| `mqtt` | 2 | 2,756 | 7 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `mssql` | 2 | 2,151 | 6 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `mysql` | 4 | 2,408 | 8 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `named_pipe` | 2 | 812 | 2 | timeout, unsafe=4 | Inspected FIFO validation, nonblocking ownership and write timeout. |
| `nats` | 2 | 2,202 | 4 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `ndp` | 3 | 3,217 | 3 | unsafe=1 | Inspected raw socket returned-length slice construction. |
| `netbios_ns` | 3 | 2,228 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `nfc` | 3 | 1,949 | 3 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `nfs` | 3 | 2,423 | 4 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `nntp` | 2 | 1,663 | 8 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `nostr` | 5 | 3,293 | 9 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `npm` | 2 | 1,244 | 5 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `nsq` | 3 | 2,692 | 9 | TCP, cap, timeout | Inspected count/length guarded frame allocations. |
| `ntp` | 2 | 1,144 | 5 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `oauth2` | 2 | 1,934 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `oci_registry` | 2 | 2,357 | 4 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `ollama` | 2 | 2,179 | 6 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `openai` | 2 | 1,085 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `openapi` | 2 | 1,618 | 7 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `openid` | 2 | 1,620 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `openvpn` | 8 | 3,212 | 4 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `oracle` | 0 | 0 | 0 | codec/action/transport scan | Planning documentation only; no Rust implementation to register/test. |
| `ospf` | 2 | 2,686 | 2 | unsafe=2 | Structural/risk scan; no demonstrated defect changed in this section. |
| `otlp` | 3 | 1,628 | 8 | cap, timeout, limited-body | Inspected bounded multi-member gzip output path. |
| `pop3` | 2 | 1,842 | 8 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `postgresql` | 2 | 1,746 | 7 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `prometheus` | 3 | 1,647 | 6 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `proxy` | 5 | 4,287 | 6 | TCP, cap, timeout | Fixed unbounded certificate cache; checked MITM/read paths. |
| `pty` | 2 | 760 | 2 | unsafe=8 | Fixed failed-startup master-fd leak; isolated descriptor regression. |
| `pypi` | 2 | 1,027 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `quic` | 2 | 1,372 | 3 | timeout | Inspected stream lifecycle/TLS parameter adapter; SAN-array discrepancy noted. |
| `radius` | 3 | 2,062 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `rawip` | 2 | 1,661 | 2 | unsafe=1 | Inspected initialized-length raw buffer conversion. |
| `rdp` | 2 | 1,045 | 4 | cap, timeout | Inspected TPKT size checks and idle-wrapped read path. |
| `redis` | 2 | 1,390 | 8 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `reverse_shell` | 2 | 1,102 | 4 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `rip` | 2 | 827 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `rss` | 2 | 1,054 | 4 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `rtp` | 3 | 1,602 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `rtsp` | 2 | 1,470 | 6 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `s3` | 2 | 1,637 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `saml_idp` | 2 | 1,128 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `saml_sp` | 2 | 1,268 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `sip` | 2 | 1,464 | 7 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `smb` | 4 | 4,521 | 11 | TCP, cap, timeout | Inspected header/body framing and bounded allocation paths. |
| `smtp` | 2 | 1,691 | 6 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `snmp` | 2 | 1,716 | 5 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `snowflake` | 2 | 1,597 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `socket_file` | 2 | 1,472 | 3 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `socks5` | 3 | 2,080 | 4 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `spark` | 2 | 1,025 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `sqs` | 2 | 891 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `ssdp` | 3 | 1,930 | 2 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `ssh` | 3 | 3,421 | 5 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `ssh_agent` | 2 | 2,036 | 5 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `stdio` | 2 | 712 | 2 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `stomp` | 3 | 2,193 | 5 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `stp` | 3 | 2,653 | 3 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `stun` | 2 | 1,239 | 6 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `svn` | 3 | 2,401 | 6 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `syslog` | 2 | 728 | 2 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `tcp` | 2 | 1,728 | 3 | cap, timeout | Shared peer-worker cancellation regression; existing lifecycle/bounds reviewed. |
| `telnet` | 2 | 1,369 | 6 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `tftp` | 2 | 1,902 | 4 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `tls` | 2 | 1,867 | 6 | TCP, cap, timeout | Shared certificate validation regression; checked queued-data/refusal paths. |
| `tor_relay` | 4 | 3,570 | 5 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `torrent_dht` | 2 | 1,243 | 4 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `torrent_peer` | 2 | 1,566 | 5 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `torrent_tracker` | 2 | 1,382 | 6 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `tuntap` | 3 | 3,559 | 3 | timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `turn` | 2 | 2,915 | 6 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `udp` | 2 | 843 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `usb` | 29 | 16,692 | 0 | cap, timeout, unsafe=1 | Nested transport/device files included; guards/ownership inspected; tests in usb_*. |
| `vault` | 3 | 1,483 | 6 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `vnc` | 2 | 2,250 | 5 | cap, timeout | Inspected clipboard allocation cap and CPU framebuffer rendering bounds. |
| `vrrp` | 3 | 2,839 | 3 | unsafe=3 | Structural/risk scan; no demonstrated defect changed in this section. |
| `webdav` | 2 | 1,718 | 5 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `webrtc` | 2 | 1,963 | 4 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `webrtc_signaling` | 2 | 1,552 | 6 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `websocket` | 2 | 3,126 | 4 | cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `whois` | 2 | 1,182 | 6 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `wireguard` | 2 | 1,427 | 2 | timeout | Structural/risk scan; no demonstrated defect changed in this section. |
| `wol` | 2 | 1,235 | 4 | codec/action/transport scan | Structural/risk scan; no demonstrated defect changed in this section. |
| `xmlrpc` | 2 | 1,661 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `xmpp` | 2 | 1,445 | 5 | cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `yarn` | 2 | 1,334 | 4 | cap, timeout, limited-body | Structural/risk scan; no demonstrated defect changed in this section. |
| `zabbix` | 3 | 1,182 | 9 | TCP, cap, timeout | Structural/risk scan; benefits from shared server-owned peer-command worker. |
| `zookeeper` | 2 | 1,912 | 4 | TCP, cap, timeout | Structural/risk scan; no demonstrated defect changed in this section. |

### Shared source files

| File | Review disposition |
|---|---|
| `accept_bounded.rs` | Inspected semaphore permits, refusal timeout, idle readers and activity guards; no change. |
| `connection.rs` | Inspected connection-ID parsing and basic counters; no change. |
| `mod.rs` | Checked module/test directory relationships and TLS feature gating; no change. |
| `peer_support.rs` | Fixed worker ownership; applies to 45 protocol callers. |
| `server_trait.rs` | Read common server trait; no change. |
| `socket_helpers.rs` | Inspected reusable TCP/UDP listeners and raw OSPF descriptor ownership; no change. |
| `tls_cert_manager.rs` | Fixed SAN and validity validation before key generation. |

### Test-only integration families

`tests/server/tor_integration/` and `tests/server/torrent_integration/` were included in the test-file structural inventory. Their network/integration scenarios were not executed. Nested USB suites (`usb_fido2`, `usb_keyboard`, `usb_mouse`, `usb_msc`, `usb_serial`, `usb_smartcard`) map to source subdirectories under `src/server/usb/`, rather than to immediate source siblings.

<a id="clients"></a>
## Client, easy HTTP, and pipe review — 2026-10-01

**Coordinator completion note:** The final client_review_regression_test target passed all 22 tests under the complete selected client feature union; Clippy covered these features. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and evidence

Inventory: 777 files across `src/client`, `src/easy`, `src/pipe`, and `tests/client`. Every inventoried text file was included in the static sweep. The sweep enumerated declarations, framing/allocation operations, unbounded reads and channels, unchecked arithmetic, process/filesystem access, task ownership, TODOs, and protocol/test documentation. Manual control-flow review concentrated on the changes and risks below. This is **not a claim that every line received equal-depth manual review or that every protocol was exercised**.

No GPU operations, model inference, model downloads, external protocol services, live LLM tests, hardware access, commits, or pushes were run by this reviewer. Rust builds/tests are centralized by the root agent; their authoritative results belong in the combined report.

### Implemented improvements

| Area | Defect | Change | Regression evidence |
|---|---|---|---|
| HTTP shared transport | Connection driver cleanup was after an await, so caller cancellation bypassed explicit cleanup. | An owning drop guard aborts HTTP/1 and HTTP/2 drivers on every exit. | In-memory request/prelude observed, then exchange cancelled and peer must reach EOF. |
| HTTP extension methods | Shared transport admitted only seven methods; WebDAV operations were refused. | Use HTTP Method parsing to admit valid extension-method tokens and preserve their casing; retain normalization of the seven previously supported methods. | PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK, mixed/lowercase custom tokens and standard-method normalization wire requests. |
| Easy HTTP Markdown | All emphasis/code delimiters became opening tags; code contents were reinterpreted; code fences could begin inside an unclosed list. | Paired escaped inline tags, literal unmatched syntax, code isolation, bounded recursion, close list before code. | Balanced tags, identifier underscores, escaped markup, unmatched delimiters, list/fence structure. |
| Pipe template memory | 64KiB decoded cap was applied after arbitrary template expansion and JSON serialization. | 1MiB intermediate representation cap enforced during append and streaming JSON serialization;64KiB payload cap retained. | Exact UTF-8/hex payload bound, expansion failure, oversized structured value and encoding substitution. |
| Pipe validation | An invalid explicit source silently defaulted to current server; invalid mapping values silently disappeared. | Only an absent source defaults; explicit source and every map value must validate. | Invalid string, negative, overflowing, null source; numeric encoding; valid contextual default. |
| Pipe allocation | Whole event payload was cloned before each dispatch batch. | Borrow the event during rendering. | Covered by existing and new mapping tests. |
| BitTorrent peer | Remote u32 length allocated up to4GiB before validation. | 8MiB inbound frame cap before allocation/read, with explicit keepalive handling. | Oversize/u32::MAX, exact cap, keepalive, next frame and truncated body. |
| VNC text | Remote failure/name/clipboard u32 lengths allocated without a cap. | One1MiB bounded text decoder used at all four allocation sites. | Over-limit/u32::MAX, exact cap, truncation. |
| VNC pixels | Raw rectangle allocated width*height*4 (up to~17GiB) then discarded; server pixel size was assumed. | Negotiate32bpp true color; discard via bounded scratch reads;256MiB per-rectangle cap. | Exact one-pixel read preserves following Bell, truncated pixels fail, maximum dimensions refused. |
| VNC framing/lifecycle | Unsupported encodings and malformed messages logged and continued with desynchronized stream. | End reader and clear command handle/status on framing error. | Decoder tests cover failure causes; end-to-end lifecycle requires further peer validation. |
| SSH agent | Raw socket chunks including length prefix were passed to parser expecting a message type; split/coalesced frames broke. | LengthDelimitedCodec strips prefix, preserves partial frames across cancellation and caps messages at1MiB. | Coalesced identities/success, cancelled partial header, over-limit/truncated frames. |
| FTP/POP3/NNTP/HTTP proxy | read_line could allocate without bound on an endless line. | Shared response reader limits lines to64KiB and treats partial EOF as framing error. | Exact cap, next-line boundary, too-long and incomplete line. |
| POP3/NNTP multiline | POP3 spun forever at EOF before terminator; NNTP reported truncated response as success; total response unbounded. | Require exact dot terminator,8MiB aggregate bound, undo dot stuffing and preserve content whitespace. | EOF failure, aggregate cap, dot stuffing, whitespace around dot, following response preserved. |
| POP3 lifecycle | Reader exit did not remove injected-command handle or consistently update status. | Cleanup after both normal and error return removes handle and sets final status. | Static control-flow review; full peer lifecycle not yet separately asserted. |
| HTTP CONNECT | 200 status plus malformed/EOF header block could be marked established; arbitrary number of short headers unbounded. | 64KiB aggregate head cap; incomplete/invalid headers return terminal error before tunnel event. | Shared reader tests; independent CONNECT exchange remains integration follow-up. |
| WebRTC ownership | Obsolete Arc::into_raw reference stored in JSON was released only by cleanup task, which stop could abort. | Remove the unused raw reference and unsafe reconstruction; live tasks retain proper Arc owners. | Static reference search; no hardware/network WebRTC session run. |
| Client LLM budget | Warning percentage multiplication used u32 and could overflow for a large configured limit. | Widen operands to u64 before multiplying. | Static arithmetic proof; no model calls. |

### Validation performed by this reviewer

- `rustfmt --edition 2021` on changed files, with `skip_children=true` for module roots to avoid touching unrelated files.
- `git diff --check` for owned source/tests.
- Created `tests/client_review_regression_test.rs`,22 CPU-only tests with the relevant features enabled. These use in-memory readers/duplex streams and constructed state, and never invoke a model.
- Centralized Cargo test/check results are pending at report creation; do not equate a test file existing with a passing test run.
- Feature set covering changed gated clients: `http,vnc,torrent-peer,ssh-agent,webrtc,ftp,nntp,pop3,http_proxy`. The helper/pipe tests are available without those protocol features.

### Material behavior changes and limits

-64KiB client text lines and CONNECT header blocks;8MiB POP3/NNTP accumulated response text;8MiB BitTorrent peer messages;1MiB SSH agent response frames and VNC text;256MiB raw VNC rectangles;1MiB intermediate pipe mapping and64KiB decoded payload. These deliberately refuse larger inputs rather than truncate and misrepresent success.
- Text response readers use the existing lossy UTF-8 line decoder; non-UTF-8 network text is represented with replacement characters instead of failing allocation/unicode decoding.
- Dot response bodies preserve indentation and trailing spaces, unstuff leading double dots, and use newline-separated retained text. Whitespace around a dot is ordinary content.
- Easy HTTP still implements a small Markdown subset, not CommonMark; no new dependency or full parser was introduced.
- New public framing/rendering helpers make production behavior directly testable from the required external `tests/` directory.

### Remaining findings and explicit gaps

1. **POP3 command correlation:** Existing code guesses multiline replies from the wording of `+OK` rather than tracking the command queue. USER/PASS/LIST/RETR replies can still be misclassified and wait for a dot that will never arrive. The safe complete fix needs response expectations queued atomically with writes from both the model and command channel; the bound/EOF fix does not claim to solve it.
2. **VNC authentication:** Type2 still echoes the challenge rather than performing DES; existing docs call this a placeholder. It was not expanded into a cryptographic implementation during the allocation/framing patch.
3. **Native HTTP-family body bounds are inconsistent:** `FetchClient` transport responses are bounded, but several reqwest-side `text()/json()` users still buffer without a protocol-specific cap (bitcoin, jsonrpc, MCP, HTTP/2, WebDAV, package metadata, OAuth/OIDC). A global cap can break intentional large streaming downloads, so policy must distinguish buffered model events from download streams.
4. **SMB client file reads:** `file.read_to_end` remains unbounded and synchronous while holding its client lock. Solving the !Send libsmbclient ownership and size/error contract deserves dedicated tests.
5. **WebRTC lifecycle beyond raw reference removal:** Library-internal tasks, callback ownership cycles, dropped queued channel messages, and connection close-on-abort need a real lifecycle test. Removing the unused raw Arc fixes that specific guaranteed leak only.
6. **SSH agent command injection:** Generic injected-command handler cannot execute Custom action results, although SSH agent verbs return them; it can report an Executed detail without sending the requested agent packet. The receive framing fix is separate from this existing command-channel gap.
7. **HTTP URL validation:** `parse_http_url` uses hyper Authority and `port_u16().unwrap_or(80)`; malformed explicit port handling and userinfo should be independently verified. No broad URL semantics rewrite was attempted.
8. **Protocol-specific timeouts and aggregate buffering:** Some protocols still depend on peer closure or external stop after beginning a partial message. This pass enforces allocation limits for the paths changed, not a universal idle/handshake deadline policy.
9. **Binary protocol narrowing:** Numerous action integers use `as u16/u32/u8`, particularly routing/datagram protocols. Existing validation varies; values were not indiscriminately clamped because that would silently alter packets.
10. **Documentation maturity:** Many historical client docs still describe placeholder tests, older test commands, nonexistent TLS, or stale limitations. The added sections document actual changes; they are not blanket verification of every historical claim.
11. **Hardware / unavailable environments:** Raw/link-layer packets, USB/NFC/Bluetooth, Tor/WireGuard privileged networking, real remote databases and registries, browser wasm and native TLS were static-only. No maturity rating was upgraded.

### Directory coverage ledger

Every listed directory was inventoried and scanned; `Focused` means manual control-flow review included concrete changed paths, `Focused static` means targeted source inspection without a patch, and `Sweep` means automated hazard/declaration inventory plus protocol documentation review, not equal-depth manual review.

| Client directory | Rust files | Rust lines | Test Rust files | Coverage |
|---|---:|---:|---:|---|
| `amqp` | 2 | 963 | 3 | Sweep |
| `arp` | 2 | 1296 | 3 | Sweep |
| `bgp` | 2 | 1623 | 5 | Focused static |
| `bitcoin` | 2 | 1301 | 4 | Sweep |
| `bluetooth` | 2 | 1828 | 3 | Sweep |
| `bootp` | 2 | 880 | 3 | Focused static |
| `cassandra` | 2 | 976 | 3 | Sweep |
| `coap` | 2 | 1672 | 4 | Focused static |
| `couchdb` | 2 | 2455 | 3 | Sweep |
| `datalink` | 2 | 1625 | 4 | Sweep |
| `dc` | 2 | 2721 | 3 | Focused static |
| `dhcp` | 2 | 1134 | 3 | Focused static |
| `dns` | 2 | 1061 | 3 | Sweep |
| `doh` | 2 | 1123 | 3 | Sweep |
| `dot` | 2 | 1102 | 3 | Sweep |
| `dynamodb` | 2 | 1699 | 3 | Sweep |
| `elasticsearch` | 2 | 1730 | 3 | Sweep |
| `etcd` | 2 | 1011 | 4 | Sweep |
| `finger` | 2 | 1624 | 2 | Sweep |
| `ftp` | 2 | 617 | 3 | Focused |
| `git` | 3 | 2618 | 5 | Focused static |
| `gopher` | 2 | 1635 | 2 | Sweep |
| `grpc` | 2 | 1752 | 3 | Sweep |
| `http` | 2 | 1220 | 6 | Focused |
| `http2` | 2 | 1116 | 4 | Sweep |
| `http3` | 2 | 1314 | 3 | Sweep |
| `http_fetch` | 2 | 931 | 0 | Focused |
| `http_proxy` | 2 | 1318 | 4 | Focused |
| `icmp` | 2 | 1385 | 4 | Sweep |
| `ident` | 2 | 1560 | 2 | Sweep |
| `igmp` | 2 | 947 | 3 | Sweep |
| `imap` | 2 | 1318 | 4 | Sweep |
| `ipp` | 2 | 1372 | 4 | Sweep |
| `irc` | 2 | 1149 | 4 | Sweep |
| `isis` | 2 | 770 | 4 | Sweep |
| `jsonrpc` | 2 | 1311 | 3 | Sweep |
| `kafka` | 2 | 2249 | 3 | Focused static |
| `kubernetes` | 2 | 1575 | 3 | Sweep |
| `ldap` | 2 | 1448 | 3 | Sweep |
| `llmnr` | 2 | 1861 | 2 | Sweep |
| `maven` | 2 | 1695 | 3 | Sweep |
| `mcp` | 2 | 1283 | 3 | Sweep |
| `mdns` | 2 | 1066 | 3 | Sweep |
| `memcached` | 3 | 1868 | 4 | Sweep |
| `mercurial` | 0 | 0 | 0 | Documentation-only directory; no implementation |
| `modbus` | 2 | 1232 | 4 | Sweep |
| `mongodb` | 2 | 1275 | 3 | Sweep |
| `mqtt` | 2 | 1262 | 4 | Sweep |
| `mssql` | 2 | 976 | 3 | Sweep |
| `mysql` | 2 | 1046 | 4 | Sweep |
| `nats` | 2 | 2199 | 2 | Focused static |
| `netbios_ns` | 3 | 2039 | 2 | Focused static |
| `nfc` | 3 | 2432 | 3 | Focused static |
| `nfs` | 2 | 1479 | 3 | Sweep |
| `nntp` | 2 | 1153 | 3 | Focused |
| `npm` | 2 | 1564 | 4 | Sweep |
| `ntp` | 2 | 802 | 3 | Focused static |
| `oauth2` | 2 | 2229 | 3 | Sweep |
| `ollama` | 2 | 1628 | 4 | Sweep |
| `openai` | 2 | 1613 | 4 | Sweep |
| `openapi` | 2 | 1484 | 4 | Sweep |
| `openidconnect` | 2 | 2396 | 3 | Sweep |
| `oracle` | 0 | 0 | 0 | Documentation-only directory; no implementation |
| `ospf` | 2 | 1526 | 3 | Sweep |
| `pop3` | 2 | 750 | 4 | Focused |
| `postgresql` | 2 | 1010 | 4 | Sweep |
| `pypi` | 2 | 1527 | 4 | Sweep |
| `radius` | 3 | 1872 | 4 | Focused static |
| `redis` | 3 | 1229 | 5 | Focused static |
| `rip` | 2 | 971 | 4 | Sweep |
| `rss` | 2 | 890 | 3 | Sweep |
| `s3` | 2 | 1608 | 3 | Sweep |
| `saml` | 2 | 1293 | 5 | Sweep |
| `sip` | 2 | 1643 | 4 | Focused static |
| `smb` | 2 | 1429 | 3 | Focused static |
| `smtp` | 2 | 1019 | 4 | Sweep |
| `snmp` | 2 | 1551 | 3 | Focused static |
| `socket_file` | 2 | 743 | 3 | Sweep |
| `socks5` | 2 | 858 | 4 | Sweep |
| `sqs` | 2 | 1391 | 3 | Sweep |
| `ssdp` | 2 | 1819 | 2 | Sweep |
| `ssh` | 2 | 1047 | 3 | Sweep |
| `ssh_agent` | 2 | 1035 | 3 | Focused |
| `stomp` | 2 | 1726 | 2 | Focused static |
| `stun` | 2 | 805 | 3 | Sweep |
| `svn` | 0 | 0 | 0 | Documentation-only directory; no implementation |
| `syslog` | 2 | 770 | 3 | Sweep |
| `tcp` | 2 | 640 | 2 | Sweep |
| `telnet` | 2 | 879 | 2 | Sweep |
| `tftp` | 2 | 1228 | 3 | Focused static |
| `tls` | 2 | 955 | 4 | Sweep |
| `tor` | 2 | 1370 | 6 | Sweep |
| `torrent_dht` | 2 | 924 | 3 | Sweep |
| `torrent_peer` | 2 | 926 | 3 | Focused |
| `torrent_tracker` | 2 | 1221 | 3 | Sweep |
| `turn` | 2 | 1610 | 4 | Focused static |
| `udp` | 2 | 917 | 3 | Sweep |
| `usb` | 2 | 1550 | 3 | Sweep |
| `vnc` | 2 | 1615 | 4 | Focused |
| `webdav` | 2 | 1472 | 3 | Sweep |
| `webrtc` | 2 | 1651 | 3 | Focused |
| `websocket` | 2 | 1537 | 4 | Sweep |
| `whois` | 2 | 915 | 3 | Sweep |
| `wireguard` | 2 | 1139 | 3 | Sweep |
| `xmlrpc` | 3 | 1423 | 3 | Focused static |
| `xmpp` | 2 | 1218 | 4 | Sweep |
| `zookeeper` | 2 | 1108 | 2 | Sweep |

Also covered: client shared `mod.rs`, `command_support.rs`, `llm_budget.rs`; all4 easy/pipe Rust modules. Existing `tests/client` files were inventoried and their protocol guidance read; broad external-peer suites were not run.

### Complete file inventory

The counts below permit checking coverage against repository contents. Source content is not duplicated in the report. New root regression target and this report are additional artifacts.

| File | Lines | SHA-256 prefix |
|---|---:|---|
| `src/client/amqp/CLAUDE.md` | 95 | `55847da44394` |
| `src/client/amqp/actions.rs` | 346 | `add5258344fa` |
| `src/client/amqp/mod.rs` | 617 | `c4d32b6c3f01` |
| `src/client/arp/CLAUDE.md` | 534 | `c3bed7551a7e` |
| `src/client/arp/actions.rs` | 459 | `9e348221515f` |
| `src/client/arp/mod.rs` | 837 | `c99b33a44672` |
| `src/client/bgp/CLAUDE.md` | 196 | `162ef2fa84d0` |
| `src/client/bgp/actions.rs` | 505 | `1768b9184e99` |
| `src/client/bgp/mod.rs` | 1118 | `38ab1299dd00` |
| `src/client/bitcoin/CLAUDE.md` | 364 | `a4b656ff7c2f` |
| `src/client/bitcoin/actions.rs` | 634 | `0659682c51d2` |
| `src/client/bitcoin/mod.rs` | 667 | `b567f48a8a2b` |
| `src/client/bluetooth/CLAUDE.md` | 359 | `98359bd8ca0a` |
| `src/client/bluetooth/actions.rs` | 638 | `f840455ee138` |
| `src/client/bluetooth/mod.rs` | 1190 | `ff1e0c3cf8c0` |
| `src/client/bootp/CLAUDE.md` | 507 | `4b199c334b06` |
| `src/client/bootp/actions.rs` | 306 | `defe6970b807` |
| `src/client/bootp/mod.rs` | 574 | `4731a63c23a1` |
| `src/client/cassandra/CLAUDE.md` | 388 | `d4769c6e7295` |
| `src/client/cassandra/actions.rs` | 352 | `3dc1a65870e7` |
| `src/client/cassandra/mod.rs` | 624 | `3f09157b7704` |
| `src/client/coap/CLAUDE.md` | 119 | `7f35ac3ce25b` |
| `src/client/coap/actions.rs` | 651 | `fa6ec549a7b9` |
| `src/client/coap/mod.rs` | 1021 | `805865c45044` |
| `src/client/command_support.rs` | 206 | `1957cc4f2afd` |
| `src/client/couchdb/CLAUDE.md` | 444 | `4069b5a2c0eb` |
| `src/client/couchdb/actions.rs` | 662 | `ccdf4b898de0` |
| `src/client/couchdb/mod.rs` | 1793 | `19ec384c7a30` |
| `src/client/datalink/CLAUDE.md` | 389 | `697115aa38b3` |
| `src/client/datalink/actions.rs` | 738 | `7972af58e2f8` |
| `src/client/datalink/mod.rs` | 887 | `25ce68d61e65` |
| `src/client/dc/CLAUDE.md` | 497 | `14131281d168` |
| `src/client/dc/actions.rs` | 791 | `742ffb48ac10` |
| `src/client/dc/mod.rs` | 1930 | `3d4afac8d164` |
| `src/client/dhcp/CLAUDE.md` | 394 | `a14d3d0c813b` |
| `src/client/dhcp/actions.rs` | 327 | `e0b320b84bd0` |
| `src/client/dhcp/mod.rs` | 807 | `1c4e23bd796a` |
| `src/client/dns/CLAUDE.md` | 405 | `716078b41ea3` |
| `src/client/dns/actions.rs` | 343 | `6902da612221` |
| `src/client/dns/mod.rs` | 718 | `fa973776c379` |
| `src/client/doh/CLAUDE.md` | 459 | `f838047732d4` |
| `src/client/doh/actions.rs` | 366 | `1c821a34b264` |
| `src/client/doh/mod.rs` | 757 | `f5f6617e0c27` |
| `src/client/dot/CLAUDE.md` | 333 | `924ddf3370f7` |
| `src/client/dot/actions.rs` | 362 | `e66b517bc358` |
| `src/client/dot/mod.rs` | 740 | `3e5adf27821a` |
| `src/client/dynamodb/CLAUDE.md` | 424 | `39937ee14c47` |
| `src/client/dynamodb/actions.rs` | 663 | `7f9ce75d60cc` |
| `src/client/dynamodb/mod.rs` | 1036 | `f5d3d617d5a8` |
| `src/client/elasticsearch/CLAUDE.md` | 355 | `54efa546a312` |
| `src/client/elasticsearch/actions.rs` | 575 | `f3c595b0709b` |
| `src/client/elasticsearch/mod.rs` | 1155 | `bdf3227746c1` |
| `src/client/etcd/CLAUDE.md` | 459 | `62c66f5db34e` |
| `src/client/etcd/actions.rs` | 375 | `a4601c424ed0` |
| `src/client/etcd/mod.rs` | 636 | `1b1905610de1` |
| `src/client/finger/CLAUDE.md` | 161 | `70b76b8f0b0d` |
| `src/client/finger/actions.rs` | 750 | `df5e0a80e3e0` |
| `src/client/finger/mod.rs` | 874 | `6f65921b62e0` |
| `src/client/ftp/CLAUDE.md` | 133 | `5438adce25a6` |
| `src/client/ftp/actions.rs` | 280 | `ed661508ebf9` |
| `src/client/ftp/mod.rs` | 337 | `9a14df059b89` |
| `src/client/git/CLAUDE.md` | 487 | `c555a7c5bbb7` |
| `src/client/git/actions.rs` | 802 | `12169b0d4357` |
| `src/client/git/mod.rs` | 1529 | `40e0731a0e62` |
| `src/client/git/sandbox.rs` | 287 | `57cf3262e2dd` |
| `src/client/gopher/CLAUDE.md` | 229 | `b1df10874512` |
| `src/client/gopher/actions.rs` | 675 | `e8c4dbf268bc` |
| `src/client/gopher/mod.rs` | 960 | `e7930ab6c143` |
| `src/client/grpc/CLAUDE.md` | 456 | `e94806dec67d` |
| `src/client/grpc/actions.rs` | 475 | `90b2317daafc` |
| `src/client/grpc/mod.rs` | 1277 | `3b3cf1cdcaa2` |
| `src/client/http/CLAUDE.md` | 333 | `1525312d0336` |
| `src/client/http/actions.rs` | 391 | `b811f93df9da` |
| `src/client/http/mod.rs` | 829 | `da2d0bc59812` |
| `src/client/http2/CLAUDE.md` | 318 | `2c08dcdf921d` |
| `src/client/http2/actions.rs` | 366 | `f82f64330125` |
| `src/client/http2/mod.rs` | 750 | `206e17aa9586` |
| `src/client/http3/CLAUDE.md` | 459 | `087b3c637759` |
| `src/client/http3/actions.rs` | 426 | `64bc2e9f0950` |
| `src/client/http3/mod.rs` | 888 | `67c3689b3ce6` |
| `src/client/http_fetch/mod.rs` | 559 | `89ae049dbf5d` |
| `src/client/http_fetch/transport.rs` | 372 | `59a5bbbc82db` |
| `src/client/http_proxy/CLAUDE.md` | 226 | `c625d50e7af7` |
| `src/client/http_proxy/actions.rs` | 516 | `6e7efa0e8a9d` |
| `src/client/http_proxy/mod.rs` | 802 | `881a6c4cec1d` |
| `src/client/icmp/CLAUDE.md` | 396 | `cd0d94cf7909` |
| `src/client/icmp/actions.rs` | 565 | `f4da7af1c424` |
| `src/client/icmp/mod.rs` | 820 | `fe4a5bdf73ab` |
| `src/client/ident/CLAUDE.md` | 188 | `fb649ce7bc3e` |
| `src/client/ident/actions.rs` | 540 | `3c2021aac9e6` |
| `src/client/ident/mod.rs` | 1020 | `785771bc27da` |
| `src/client/igmp/CLAUDE.md` | 322 | `d0f4b7e68166` |
| `src/client/igmp/actions.rs` | 384 | `c602076fca92` |
| `src/client/igmp/mod.rs` | 563 | `5bccb4a10a8e` |
| `src/client/imap/CLAUDE.md` | 297 | `dfc0d0ed43eb` |
| `src/client/imap/actions.rs` | 543 | `0102c53b5a28` |
| `src/client/imap/mod.rs` | 775 | `6647d3db269c` |
| `src/client/ipp/CLAUDE.md` | 219 | `74d8b1d45cf0` |
| `src/client/ipp/actions.rs` | 470 | `378f49052b3e` |
| `src/client/ipp/mod.rs` | 902 | `c55f0eec5d55` |
| `src/client/irc/CLAUDE.md` | 250 | `75778674800d` |
| `src/client/irc/actions.rs` | 535 | `7f3aabd2ba49` |
| `src/client/irc/mod.rs` | 614 | `e9e9137eec71` |
| `src/client/isis/CLAUDE.md` | 272 | `6f9622649f7b` |
| `src/client/isis/actions.rs` | 269 | `e0c63b26d41a` |
| `src/client/isis/mod.rs` | 501 | `b6119b70b5c2` |
| `src/client/jsonrpc/CLAUDE.md` | 395 | `b89bc0f22a88` |
| `src/client/jsonrpc/actions.rs` | 367 | `139fa8b8008d` |
| `src/client/jsonrpc/mod.rs` | 944 | `e040b5cd7208` |
| `src/client/kafka/CLAUDE.md` | 194 | `7d7e1db1fee1` |
| `src/client/kafka/actions.rs` | 845 | `754d87838f52` |
| `src/client/kafka/mod.rs` | 1404 | `4ec305737cfb` |
| `src/client/kubernetes/CLAUDE.md` | 414 | `bcad10a7111c` |
| `src/client/kubernetes/actions.rs` | 642 | `39afa441dde6` |
| `src/client/kubernetes/mod.rs` | 933 | `f1d13659f64e` |
| `src/client/ldap/CLAUDE.md` | 288 | `bd03c1c8ef46` |
| `src/client/ldap/actions.rs` | 624 | `5d3bffee7f5d` |
| `src/client/ldap/mod.rs` | 824 | `50fafc7d2e0a` |
| `src/client/llm_budget.rs` | 210 | `5a7743a989b2` |
| `src/client/llmnr/CLAUDE.md` | 240 | `a8a4faa31991` |
| `src/client/llmnr/actions.rs` | 783 | `f447283e2223` |
| `src/client/llmnr/mod.rs` | 1078 | `882c5e72f614` |
| `src/client/maven/CLAUDE.md` | 278 | `b970bc835f43` |
| `src/client/maven/actions.rs` | 580 | `5b627d9e1989` |
| `src/client/maven/mod.rs` | 1115 | `2ed1ddbc8ae0` |
| `src/client/mcp/CLAUDE.md` | 394 | `82759d24e060` |
| `src/client/mcp/actions.rs` | 445 | `d769a6a4fffe` |
| `src/client/mcp/mod.rs` | 838 | `d6a4c987d716` |
| `src/client/mdns/CLAUDE.md` | 346 | `1c0a9ecc5aba` |
| `src/client/mdns/actions.rs` | 348 | `dcf327dc771f` |
| `src/client/mdns/mod.rs` | 718 | `1b851c666bf5` |
| `src/client/memcached/CLAUDE.md` | 107 | `13b3ba505604` |
| `src/client/memcached/actions.rs` | 812 | `c39770949164` |
| `src/client/memcached/mod.rs` | 556 | `f6961b18ecf0` |
| `src/client/memcached/wire.rs` | 500 | `61c4b840a378` |
| `src/client/mercurial/CLAUDE.md` | 1100 | `42dde3360bac` |
| `src/client/mod.rs` | 626 | `82354860ba56` |
| `src/client/modbus/CLAUDE.md` | 106 | `6742118d48ea` |
| `src/client/modbus/actions.rs` | 611 | `3aec10801077` |
| `src/client/modbus/mod.rs` | 621 | `0b6fcc8098f9` |
| `src/client/mongodb/CLAUDE.md` | 491 | `3b127c6453fd` |
| `src/client/mongodb/actions.rs` | 516 | `ee4f07e8709c` |
| `src/client/mongodb/mod.rs` | 759 | `f728b5c97e2d` |
| `src/client/mqtt/CLAUDE.md` | 235 | `ac700d4d123c` |
| `src/client/mqtt/actions.rs` | 511 | `fe03993ce9a8` |
| `src/client/mqtt/mod.rs` | 751 | `63c0ee4a3657` |
| `src/client/mssql/CLAUDE.md` | 296 | `af24118e39a2` |
| `src/client/mssql/actions.rs` | 311 | `acc49f489fca` |
| `src/client/mssql/mod.rs` | 665 | `bb4e5d3db694` |
| `src/client/mysql/CLAUDE.md` | 471 | `fc7aff3e4477` |
| `src/client/mysql/actions.rs` | 393 | `428e96a38f0f` |
| `src/client/mysql/mod.rs` | 653 | `0a179b7494b3` |
| `src/client/nats/CLAUDE.md` | 206 | `477a7f427a09` |
| `src/client/nats/actions.rs` | 1109 | `cdc0c8355958` |
| `src/client/nats/mod.rs` | 1090 | `5157cfc99cf5` |
| `src/client/netbios_ns/CLAUDE.md` | 214 | `71022a6f66e2` |
| `src/client/netbios_ns/actions.rs` | 674 | `dec3d6c0eaa3` |
| `src/client/netbios_ns/mod.rs` | 933 | `bafbc5d9202b` |
| `src/client/netbios_ns/wire.rs` | 432 | `497a80ef4bbe` |
| `src/client/nfc/CLAUDE.md` | 241 | `1b58f02b4864` |
| `src/client/nfc/actions.rs` | 689 | `1dfbd928d7c1` |
| `src/client/nfc/mod.rs` | 1043 | `be373a10a188` |
| `src/client/nfc/ndef.rs` | 700 | `d45d086de926` |
| `src/client/nfs/CLAUDE.md` | 533 | `3d87703fbb2e` |
| `src/client/nfs/actions.rs` | 487 | `4f8fc70f12ae` |
| `src/client/nfs/mod.rs` | 992 | `e8d933b94b58` |
| `src/client/nntp/CLAUDE.md` | 243 | `091b46dbbf47` |
| `src/client/nntp/actions.rs` | 508 | `b5337280f14e` |
| `src/client/nntp/mod.rs` | 645 | `fd89103a277c` |
| `src/client/npm/CLAUDE.md` | 441 | `fa145c4edd8d` |
| `src/client/npm/actions.rs` | 487 | `44429b1d4c77` |
| `src/client/npm/mod.rs` | 1077 | `1164e697716d` |
| `src/client/ntp/CLAUDE.md` | 275 | `0f0a094f2db6` |
| `src/client/ntp/actions.rs` | 259 | `da902c085598` |
| `src/client/ntp/mod.rs` | 543 | `0a0f30758f8c` |
| `src/client/oauth2/CLAUDE.md` | 262 | `96344a826532` |
| `src/client/oauth2/actions.rs` | 610 | `ae3d0c00e704` |
| `src/client/oauth2/mod.rs` | 1619 | `235bbe08553f` |
| `src/client/ollama/CLAUDE.md` | 371 | `1e940e804ad3` |
| `src/client/ollama/actions.rs` | 459 | `5d0d19bf7709` |
| `src/client/ollama/mod.rs` | 1169 | `c63741e73722` |
| `src/client/openai/CLAUDE.md` | 342 | `34c7de4c75c2` |
| `src/client/openai/actions.rs` | 493 | `638c4f7c9170` |
| `src/client/openai/mod.rs` | 1120 | `999dea179001` |
| `src/client/openapi/CLAUDE.md` | 401 | `0197e3ae92ca` |
| `src/client/openapi/actions.rs` | 526 | `db264ac06d2e` |
| `src/client/openapi/mod.rs` | 958 | `62c3d04bf5aa` |
| `src/client/openidconnect/CLAUDE.md` | 494 | `4130264bb2b9` |
| `src/client/openidconnect/actions.rs` | 609 | `2d251edcb2a9` |
| `src/client/openidconnect/mod.rs` | 1787 | `d046ad3cc266` |
| `src/client/oracle/CLAUDE.md` | 917 | `7c4afb68aa20` |
| `src/client/ospf/CLAUDE.md` | 698 | `680331cebef3` |
| `src/client/ospf/actions.rs` | 637 | `ee2c5cf313b0` |
| `src/client/ospf/mod.rs` | 889 | `127a32febbaf` |
| `src/client/pop3/CLAUDE.md` | 237 | `e9109138362f` |
| `src/client/pop3/actions.rs` | 294 | `aa85915ac420` |
| `src/client/pop3/mod.rs` | 456 | `f8028b9fec4b` |
| `src/client/postgresql/CLAUDE.md` | 288 | `d970fe6b5a16` |
| `src/client/postgresql/actions.rs` | 383 | `28b2ebf309c6` |
| `src/client/postgresql/mod.rs` | 627 | `76bbd61727a2` |
| `src/client/pypi/CLAUDE.md` | 315 | `5ddc3e82a706` |
| `src/client/pypi/actions.rs` | 488 | `6a7b3b473f5c` |
| `src/client/pypi/mod.rs` | 1039 | `9aa0ba0141ab` |
| `src/client/radius/CLAUDE.md` | 112 | `970731861992` |
| `src/client/radius/actions.rs` | 836 | `741b821c9cdb` |
| `src/client/radius/mod.rs` | 711 | `865a6f6133d4` |
| `src/client/radius/wire.rs` | 325 | `aeb92046207b` |
| `src/client/redis/CLAUDE.md` | 211 | `0e3922764d6d` |
| `src/client/redis/actions.rs` | 315 | `7b53b670f809` |
| `src/client/redis/mod.rs` | 465 | `85f71395962a` |
| `src/client/redis/resp.rs` | 449 | `fb2125d39a12` |
| `src/client/response_reader.rs` | 76 | `0676653e426c` |
| `src/client/rip/CLAUDE.md` | 294 | `4af63c56e806` |
| `src/client/rip/actions.rs` | 299 | `8e52d877208e` |
| `src/client/rip/mod.rs` | 672 | `9d46d493dca9` |
| `src/client/rss/CLAUDE.md` | 120 | `fef2a426e9d4` |
| `src/client/rss/actions.rs` | 317 | `acb8a2c9cc6d` |
| `src/client/rss/mod.rs` | 573 | `76c49be88a7c` |
| `src/client/s3/CLAUDE.md` | 384 | `24bad05886be` |
| `src/client/s3/actions.rs` | 711 | `b577c22d33db` |
| `src/client/s3/mod.rs` | 897 | `cd1a1a7aa56d` |
| `src/client/saml/CLAUDE.md` | 293 | `3cc4319315ab` |
| `src/client/saml/actions.rs` | 371 | `a0bda9510654` |
| `src/client/saml/mod.rs` | 922 | `336c128c2cdd` |
| `src/client/sip/CLAUDE.md` | 572 | `fb269bc28782` |
| `src/client/sip/actions.rs` | 663 | `957354224dee` |
| `src/client/sip/mod.rs` | 980 | `c2174a8dacb1` |
| `src/client/smb/CLAUDE.md` | 389 | `662dbaaaf832` |
| `src/client/smb/actions.rs` | 598 | `f82b3168a6d6` |
| `src/client/smb/mod.rs` | 831 | `2d07cdf487d2` |
| `src/client/smtp/CLAUDE.md` | 248 | `a349b7ae7656` |
| `src/client/smtp/actions.rs` | 416 | `90fb70ce6ddf` |
| `src/client/smtp/mod.rs` | 603 | `57f1401f901e` |
| `src/client/snmp/CLAUDE.md` | 493 | `f8ce5109b623` |
| `src/client/snmp/README.md` | 109 | `979b8b1f944b` |
| `src/client/snmp/actions.rs` | 482 | `1877ae1f6b3a` |
| `src/client/snmp/mod.rs` | 1069 | `fed6c7da68b9` |
| `src/client/socket_file/CLAUDE.md` | 247 | `2a9d3a6cb2b3` |
| `src/client/socket_file/actions.rs` | 378 | `efaef09878d0` |
| `src/client/socket_file/mod.rs` | 365 | `777e481b62dd` |
| `src/client/socks5/CLAUDE.md` | 357 | `326e261b38c1` |
| `src/client/socks5/actions.rs` | 471 | `ba0f12e4e018` |
| `src/client/socks5/mod.rs` | 387 | `c8095e5a4045` |
| `src/client/sqs/CLAUDE.md` | 343 | `fd88e5b8c2fd` |
| `src/client/sqs/actions.rs` | 497 | `a53864029a40` |
| `src/client/sqs/mod.rs` | 894 | `5f39a5d4fe85` |
| `src/client/ssdp/CLAUDE.md` | 192 | `297c55efff47` |
| `src/client/ssdp/actions.rs` | 790 | `ff62c063b78a` |
| `src/client/ssdp/mod.rs` | 1029 | `5797412887e9` |
| `src/client/ssh/CLAUDE.md` | 356 | `69c0c188c1c2` |
| `src/client/ssh/actions.rs` | 380 | `0491e7796224` |
| `src/client/ssh/mod.rs` | 667 | `86d1c79c72ba` |
| `src/client/ssh_agent/CLAUDE.md` | 247 | `224a1e8283bc` |
| `src/client/ssh_agent/actions.rs` | 402 | `f43c5c0ef565` |
| `src/client/ssh_agent/mod.rs` | 633 | `ea9ad85441c7` |
| `src/client/stomp/CLAUDE.md` | 292 | `a82260e046bb` |
| `src/client/stomp/actions.rs` | 886 | `d18a7f219bca` |
| `src/client/stomp/mod.rs` | 840 | `e8dd11d154b3` |
| `src/client/stun/CLAUDE.md` | 289 | `015fa35176be` |
| `src/client/stun/actions.rs` | 292 | `fa94af973964` |
| `src/client/stun/mod.rs` | 513 | `1b032568f3dd` |
| `src/client/svn/CLAUDE.md` | 1034 | `b460ea172ce7` |
| `src/client/syslog/CLAUDE.md` | 216 | `963fe92d30e9` |
| `src/client/syslog/actions.rs` | 312 | `14e183bb5f83` |
| `src/client/syslog/mod.rs` | 458 | `2fc87502de94` |
| `src/client/tcp/CLAUDE.md` | 120 | `8cd15371423d` |
| `src/client/tcp/actions.rs` | 300 | `3e34d37df100` |
| `src/client/tcp/mod.rs` | 340 | `e1cbb54dbf01` |
| `src/client/telnet/CLAUDE.md` | 255 | `5a52935b0c16` |
| `src/client/telnet/actions.rs` | 342 | `3d3a6f9c6d66` |
| `src/client/telnet/mod.rs` | 537 | `aa531ca38680` |
| `src/client/tftp/CLAUDE.md` | 121 | `9057d7b6253d` |
| `src/client/tftp/actions.rs` | 480 | `85e0dd5ab234` |
| `src/client/tftp/mod.rs` | 748 | `2533ea046f62` |
| `src/client/tls/CLAUDE.md` | 242 | `079ce26b5b85` |
| `src/client/tls/actions.rs` | 346 | `14a3f3482107` |
| `src/client/tls/mod.rs` | 609 | `13c7e6b91add` |
| `src/client/tor/CLAUDE.md` | 487 | `ba1f083b3f05` |
| `src/client/tor/actions.rs` | 558 | `d9589c57483b` |
| `src/client/tor/mod.rs` | 812 | `736a9ee0effa` |
| `src/client/torrent_dht/CLAUDE.md` | 152 | `a1758e8b753f` |
| `src/client/torrent_dht/actions.rs` | 360 | `284a7f3dbeee` |
| `src/client/torrent_dht/mod.rs` | 564 | `78126d284bbc` |
| `src/client/torrent_peer/CLAUDE.md` | 177 | `468800fe2313` |
| `src/client/torrent_peer/actions.rs` | 394 | `3a781d1ee552` |
| `src/client/torrent_peer/mod.rs` | 532 | `3ed05fefda78` |
| `src/client/torrent_tracker/CLAUDE.md` | 195 | `f3493b1530dd` |
| `src/client/torrent_tracker/actions.rs` | 316 | `741020dc2ac1` |
| `src/client/torrent_tracker/mod.rs` | 905 | `8b2a2ab6706e` |
| `src/client/turn/CLAUDE.md` | 417 | `3da8ee3c2bfb` |
| `src/client/turn/actions.rs` | 504 | `a488a4e72561` |
| `src/client/turn/mod.rs` | 1106 | `a9ca7259473a` |
| `src/client/udp/CLAUDE.md` | 312 | `fd26b728faff` |
| `src/client/udp/actions.rs` | 336 | `083b9d8ea7e1` |
| `src/client/udp/mod.rs` | 581 | `285332140133` |
| `src/client/usb/CLAUDE.md` | 245 | `59b5c8eb3631` |
| `src/client/usb/actions.rs` | 624 | `369ff4340999` |
| `src/client/usb/mod.rs` | 926 | `8efbf806b975` |
| `src/client/vnc/CLAUDE.md` | 285 | `a2bd8b73c544` |
| `src/client/vnc/actions.rs` | 569 | `056d012f8667` |
| `src/client/vnc/mod.rs` | 1046 | `20d833b6c08d` |
| `src/client/webdav/CLAUDE.md` | 292 | `0631dd4e344e` |
| `src/client/webdav/actions.rs` | 642 | `292782e45cd6` |
| `src/client/webdav/mod.rs` | 830 | `81323c27f96e` |
| `src/client/webrtc/CLAUDE.md` | 554 | `ff8d484da64b` |
| `src/client/webrtc/actions.rs` | 510 | `91347dac2da8` |
| `src/client/webrtc/mod.rs` | 1141 | `2c5c1bfc1686` |
| `src/client/websocket/CLAUDE.md` | 132 | `fc8f872a3044` |
| `src/client/websocket/actions.rs` | 627 | `1b0b6283e25a` |
| `src/client/websocket/mod.rs` | 910 | `0beb4692b73d` |
| `src/client/whois/CLAUDE.md` | 301 | `079ef473bf17` |
| `src/client/whois/actions.rs` | 315 | `588b828d44d4` |
| `src/client/whois/mod.rs` | 600 | `fdde3e4fb78e` |
| `src/client/wireguard/CLAUDE.md` | 441 | `ec8bbfde3b84` |
| `src/client/wireguard/actions.rs` | 350 | `46eb4c4c9dd7` |
| `src/client/wireguard/mod.rs` | 789 | `5decfb8accb6` |
| `src/client/xmlrpc/CLAUDE.md` | 360 | `767908dc71c2` |
| `src/client/xmlrpc/actions.rs` | 308 | `854184804924` |
| `src/client/xmlrpc/mod.rs` | 831 | `755d60d838a7` |
| `src/client/xmlrpc/response_guard.rs` | 284 | `c17a9337281f` |
| `src/client/xmpp/CLAUDE.md` | 425 | `5308c06c1a45` |
| `src/client/xmpp/actions.rs` | 418 | `f4f99baef5cb` |
| `src/client/xmpp/mod.rs` | 800 | `56c4e3183ddd` |
| `src/client/zookeeper/CLAUDE.md` | 145 | `97a1ed0cda22` |
| `src/client/zookeeper/actions.rs` | 497 | `f9c0667aab9e` |
| `src/client/zookeeper/mod.rs` | 611 | `bb7af307e879` |
| `src/easy/http/actions.rs` | 439 | `cbc3cc61e434` |
| `src/easy/http/mod.rs` | 3 | `c53c9c308961` |
| `src/easy/mod.rs` | 11 | `32794a983014` |
| `src/pipe/mod.rs` | 419 | `338b87c3f35a` |
| `tests/client/amqp/CLAUDE.md` | 80 | `1b5074392817` |
| `tests/client/amqp/command_channel_test.rs` | 205 | `c4149f0b717f` |
| `tests/client/amqp/e2e_test.rs` | 176 | `2aecd3f8d6b3` |
| `tests/client/amqp/mod.rs` | 6 | `1c17539b4c38` |
| `tests/client/arp/CLAUDE.md` | 301 | `0ddfebf9c6b6` |
| `tests/client/arp/command_channel_test.rs` | 461 | `733a08664a4b` |
| `tests/client/arp/e2e_test.rs` | 255 | `8ce013acdd46` |
| `tests/client/arp/mod.rs` | 4 | `6077aff58afe` |
| `tests/client/bgp/CLAUDE.md` | 114 | `61ac3462618c` |
| `tests/client/bgp/command_channel_test.rs` | 229 | `005b42940c31` |
| `tests/client/bgp/e2e_test.rs` | 248 | `0a19a60d02f0` |
| `tests/client/bgp/hold_timer_test.rs` | 374 | `b4ca8084ffa8` |
| `tests/client/bgp/mod.rs` | 8 | `1306af247882` |
| `tests/client/bgp/update_reply_test.rs` | 408 | `b1366b55f36f` |
| `tests/client/bitcoin/CLAUDE.md` | 61 | `076a44df422b` |
| `tests/client/bitcoin/command_channel_test.rs` | 227 | `8cd995e21273` |
| `tests/client/bitcoin/e2e_test.rs` | 244 | `71ff550d86fe` |
| `tests/client/bitcoin/mod.rs` | 19 | `92546a276616` |
| `tests/client/bitcoin/rpc_auth_test.rs` | 256 | `15cd16ecd6d8` |
| `tests/client/bluetooth/CLAUDE.md` | 381 | `982704a05767` |
| `tests/client/bluetooth/command_channel_test.rs` | 210 | `1c7bb2635d80` |
| `tests/client/bluetooth/e2e_test.rs` | 301 | `d2abc5a3ac74` |
| `tests/client/bluetooth/mod.rs` | 4 | `7fca17c3681c` |
| `tests/client/bootp/CLAUDE.md` | 436 | `52ee31c28527` |
| `tests/client/bootp/command_channel_test.rs` | 169 | `63f71fbaebb3` |
| `tests/client/bootp/e2e_test.rs` | 265 | `609884d05edf` |
| `tests/client/bootp/mod.rs` | 4 | `dcd712b08d08` |
| `tests/client/cassandra/CLAUDE.md` | 190 | `1dfdb5a9a880` |
| `tests/client/cassandra/command_channel_test.rs` | 213 | `a722beb8d595` |
| `tests/client/cassandra/e2e_test.rs` | 499 | `48f556e039b7` |
| `tests/client/cassandra/mod.rs` | 4 | `f01114a94837` |
| `tests/client/coap/CLAUDE.md` | 46 | `dbcf2fa1dd29` |
| `tests/client/coap/mod.rs` | 6 | `3ce3ab91a735` |
| `tests/client/coap/real_server_test.rs` | 274 | `556c7b381dea` |
| `tests/client/coap/request_test.rs` | 51 | `a44c2aaa829a` |
| `tests/client/coap/transport_test.rs` | 429 | `e135de0d6c43` |
| `tests/client/couchdb/CLAUDE.md` | 140 | `0c2e2e6b823a` |
| `tests/client/couchdb/command_channel_test.rs` | 253 | `eacd5ab66af4` |
| `tests/client/couchdb/e2e_test.rs` | 580 | `a3c62cb44b89` |
| `tests/client/couchdb/mod.rs` | 7 | `7044299403d9` |
| `tests/client/datalink/CLAUDE.md` | 132 | `496a82253752` |
| `tests/client/datalink/action_test.rs` | 712 | `26ad2ac11eee` |
| `tests/client/datalink/command_channel_test.rs` | 345 | `c8617db97d82` |
| `tests/client/datalink/e2e_test.rs` | 379 | `c793fe26ba9b` |
| `tests/client/datalink/mod.rs` | 6 | `c410beba88b4` |
| `tests/client/dc/CLAUDE.md` | 296 | `e38204c223bc` |
| `tests/client/dc/command_channel_test.rs` | 174 | `14dad331849a` |
| `tests/client/dc/e2e_test.rs` | 223 | `3397959e9c9e` |
| `tests/client/dc/mod.rs` | 4 | `35ab072b7941` |
| `tests/client/dhcp/CLAUDE.md` | 329 | `979f624e9c10` |
| `tests/client/dhcp/command_channel_test.rs` | 173 | `b94a38c5009f` |
| `tests/client/dhcp/e2e_test.rs` | 385 | `c458fcdbc68b` |
| `tests/client/dhcp/mod.rs` | 5 | `51820ccf8806` |
| `tests/client/dns/CLAUDE.md` | 284 | `5252fdbbf651` |
| `tests/client/dns/command_channel_test.rs` | 210 | `8c734dfb2154` |
| `tests/client/dns/e2e_test.rs` | 328 | `c40a60c52cc0` |
| `tests/client/dns/mod.rs` | 5 | `97ab2d4d7d72` |
| `tests/client/doh/CLAUDE.md` | 315 | `f1c2bf48af2d` |
| `tests/client/doh/command_channel_test.rs` | 243 | `dfeae695a985` |
| `tests/client/doh/e2e_test.rs` | 555 | `e33d0f2d1c8e` |
| `tests/client/doh/mod.rs` | 4 | `4421ae94f6b4` |
| `tests/client/dot/CLAUDE.md` | 262 | `e0394e425a55` |
| `tests/client/dot/command_channel_test.rs` | 168 | `50c3060c90ec` |
| `tests/client/dot/e2e_test.rs` | 193 | `e213daa6eee2` |
| `tests/client/dot/mod.rs` | 4 | `b723021c3d7c` |
| `tests/client/dynamodb/CLAUDE.md` | 189 | `06fc308ef108` |
| `tests/client/dynamodb/command_channel_test.rs` | 404 | `e189ec7e6234` |
| `tests/client/dynamodb/e2e_test.rs` | 318 | `8ab5d90e14d9` |
| `tests/client/dynamodb/mod.rs` | 5 | `15c9f5d5ea45` |
| `tests/client/elasticsearch/CLAUDE.md` | 260 | `62679eca70f8` |
| `tests/client/elasticsearch/command_channel_test.rs` | 244 | `fa7978a8928e` |
| `tests/client/elasticsearch/e2e_test.rs` | 491 | `75bf68f87535` |
| `tests/client/elasticsearch/mod.rs` | 5 | `45b5f672e157` |
| `tests/client/etcd/CLAUDE.md` | 76 | `e729f899cf96` |
| `tests/client/etcd/command_channel_test.rs` | 233 | `69150cbd75a5` |
| `tests/client/etcd/e2e_test.rs` | 485 | `acf62eba3616` |
| `tests/client/etcd/mod.rs` | 6 | `e9820199ed24` |
| `tests/client/etcd/real_server_test.rs` | 178 | `f3e604190132` |
| `tests/client/finger/CLAUDE.md` | 80 | `838cbd31ee82` |
| `tests/client/finger/e2e_test.rs` | 498 | `26fa92fafd9b` |
| `tests/client/finger/mod.rs` | 2 | `85693194c197` |
| `tests/client/ftp/CLAUDE.md` | 59 | `6211ec956097` |
| `tests/client/ftp/command_channel_test.rs` | 172 | `40a8482d8e43` |
| `tests/client/ftp/mod.rs` | 4 | `ba16ddbde3d2` |
| `tests/client/ftp/test.rs` | 119 | `e5abff51de0f` |
| `tests/client/git/CLAUDE.md` | 316 | `2d29321d8b8b` |
| `tests/client/git/command_channel_test.rs` | 217 | `64cc6a44ae1e` |
| `tests/client/git/e2e_test.rs` | 162 | `73869c72f10b` |
| `tests/client/git/mod.rs` | 8 | `b2fcfad4b78f` |
| `tests/client/git/operation_events_test.rs` | 204 | `bf82685d4c4b` |
| `tests/client/git/sandbox_test.rs` | 812 | `758f836a6490` |
| `tests/client/gopher/CLAUDE.md` | 130 | `c328231652d1` |
| `tests/client/gopher/e2e_test.rs` | 576 | `ec0e015e44f4` |
| `tests/client/gopher/mod.rs` | 2 | `7e49fb3b226d` |
| `tests/client/grpc/CLAUDE.md` | 154 | `f2ecf639c933` |
| `tests/client/grpc/command_channel_test.rs` | 366 | `e54d93fc6601` |
| `tests/client/grpc/e2e_test.rs` | 223 | `32acf46adf9b` |
| `tests/client/grpc/mod.rs` | 6 | `5cacc9d37647` |
| `tests/client/helpers.rs` | 5 | `d0014d59c935` |
| `tests/client/http/CLAUDE.md` | 115 | `26d0e29db506` |
| `tests/client/http/command_channel_test.rs` | 199 | `13b8c647ee3a` |
| `tests/client/http/e2e_test.rs` | 251 | `6b9e97a038f8` |
| `tests/client/http/fetch_client_test.rs` | 293 | `72dd79da3f67` |
| `tests/client/http/mod.rs` | 10 | `a8e10ff742f2` |
| `tests/client/http/real_server_test.rs` | 183 | `043f05c93cd8` |
| `tests/client/http/transport_test.rs` | 312 | `e23e1f859ff8` |
| `tests/client/http2/CLAUDE.md` | 185 | `2fa09f870d2e` |
| `tests/client/http2/command_channel_test.rs` | 195 | `31b87f22342b` |
| `tests/client/http2/e2e_test.rs` | 372 | `d35658dd6c54` |
| `tests/client/http2/h2_transport_test.rs` | 134 | `2827eed6b2a6` |
| `tests/client/http2/mod.rs` | 6 | `93340df823ef` |
| `tests/client/http3/CLAUDE.md` | 306 | `94492c1ff461` |
| `tests/client/http3/command_channel_test.rs` | 144 | `6e1c9b0e3f0b` |
| `tests/client/http3/e2e_test.rs` | 358 | `1737d93db2a1` |
| `tests/client/http3/mod.rs` | 6 | `2c75e7a8b12a` |
| `tests/client/http_proxy/CLAUDE.md` | 200 | `86f8c8495ffb` |
| `tests/client/http_proxy/command_channel_test.rs` | 222 | `557b06c25fba` |
| `tests/client/http_proxy/e2e_test.rs` | 174 | `be4abab3362a` |
| `tests/client/http_proxy/mod.rs` | 7 | `c6c27c40f518` |
| `tests/client/http_proxy/target_port_range_test.rs` | 66 | `8d8c5459d084` |
| `tests/client/icmp/CLAUDE.md` | 150 | `6f39c1b1eba8` |
| `tests/client/icmp/action_codec_test.rs` | 249 | `02cd4e053726` |
| `tests/client/icmp/command_channel_test.rs` | 207 | `1e92edf1f749` |
| `tests/client/icmp/e2e_test.rs` | 104 | `9feeadf630fe` |
| `tests/client/icmp/mod.rs` | 6 | `e0ef2f80221f` |
| `tests/client/ident/CLAUDE.md` | 103 | `2e5ffaf8faca` |
| `tests/client/ident/e2e_test.rs` | 553 | `4bf1aae6c6f2` |
| `tests/client/ident/mod.rs` | 2 | `747988eea5c3` |
| `tests/client/igmp/CLAUDE.md` | 246 | `ec85b447a23b` |
| `tests/client/igmp/command_channel_test.rs` | 179 | `42641bed4743` |
| `tests/client/igmp/e2e_test.rs` | 262 | `398038c823f3` |
| `tests/client/igmp/mod.rs` | 4 | `f53df292ad45` |
| `tests/client/imap/CLAUDE.md` | 206 | `ee99b1297d83` |
| `tests/client/imap/command_channel_test.rs` | 223 | `d1eec6f7fe04` |
| `tests/client/imap/e2e_test.rs` | 655 | `8113ec6ab1b3` |
| `tests/client/imap/mod.rs` | 7 | `278f89fa5cc8` |
| `tests/client/imap/use_tls_refusal_test.rs` | 68 | `81846e76a879` |
| `tests/client/ipp/CLAUDE.md` | 244 | `57f472245271` |
| `tests/client/ipp/command_channel_test.rs` | 192 | `1a48291766ec` |
| `tests/client/ipp/document_encoding_test.rs` | 131 | `8d4122c87a88` |
| `tests/client/ipp/e2e_test.rs` | 346 | `f30f34d6d2b5` |
| `tests/client/ipp/mod.rs` | 8 | `5b8e5b894dad` |
| `tests/client/irc/CLAUDE.md` | 123 | `9d929686b5ec` |
| `tests/client/irc/command_channel_test.rs` | 179 | `3472232e9f02` |
| `tests/client/irc/e2e_test.rs` | 366 | `ea8aa9c6161a` |
| `tests/client/irc/framing_test.rs` | 267 | `2397ef8098c9` |
| `tests/client/irc/mod.rs` | 6 | `bbb54e6ceaf5` |
| `tests/client/isis/CLAUDE.md` | 394 | `3c31805f6117` |
| `tests/client/isis/capture_stop_test.rs` | 181 | `627b952ac4e7` |
| `tests/client/isis/command_channel_test.rs` | 184 | `fefb6b9be58d` |
| `tests/client/isis/e2e_test.rs` | 399 | `d9a57a4c444d` |
| `tests/client/isis/mod.rs` | 6 | `f8153d7af58a` |
| `tests/client/jsonrpc/CLAUDE.md` | 84 | `72ec20c978cb` |
| `tests/client/jsonrpc/command_channel_test.rs` | 197 | `be7ef1ed2dcd` |
| `tests/client/jsonrpc/e2e_test.rs` | 488 | `e8edd2b5ddfa` |
| `tests/client/jsonrpc/mod.rs` | 4 | `defe028c7a6c` |
| `tests/client/kafka/CLAUDE.md` | 111 | `25b3a99c8be8` |
| `tests/client/kafka/command_channel_test.rs` | 227 | `55e6f89109c4` |
| `tests/client/kafka/e2e_test.rs` | 419 | `1dcb41918308` |
| `tests/client/kafka/mod.rs` | 6 | `7c2f9d982f39` |
| `tests/client/kubernetes/CLAUDE.md` | 56 | `f0d99772816b` |
| `tests/client/kubernetes/command_channel_test.rs` | 313 | `b736d159646c` |
| `tests/client/kubernetes/e2e_test.rs` | 197 | `22f81a2a93d1` |
| `tests/client/kubernetes/mod.rs` | 5 | `46e90aa8d43d` |
| `tests/client/ldap/CLAUDE.md` | 90 | `60ee45e63d7a` |
| `tests/client/ldap/command_channel_test.rs` | 192 | `cec42b80474f` |
| `tests/client/ldap/mod.rs` | 4 | `502fcca3cee7` |
| `tests/client/ldap/real_server_test.rs` | 496 | `3a3196095733` |
| `tests/client/llmnr/CLAUDE.md` | 123 | `b2ff597edce6` |
| `tests/client/llmnr/e2e_test.rs` | 498 | `71e5b6329be3` |
| `tests/client/llmnr/mod.rs` | 2 | `eb655e710b56` |
| `tests/client/maven/CLAUDE.md` | 238 | `71fc7a50e6be` |
| `tests/client/maven/command_channel_test.rs` | 267 | `0b2b09bdb4a5` |
| `tests/client/maven/e2e_test.rs` | 197 | `695c5181d36a` |
| `tests/client/maven/mod.rs` | 5 | `c8bdb7e8558a` |
| `tests/client/mcp/CLAUDE.md` | 192 | `5925056d14fb` |
| `tests/client/mcp/command_channel_test.rs` | 265 | `0ada31ca523d` |
| `tests/client/mcp/e2e_test.rs` | 331 | `c1953935cbaf` |
| `tests/client/mcp/mod.rs` | 7 | `d8f9c5b5f3cc` |
| `tests/client/mdns/CLAUDE.md` | 207 | `0eff7133fc70` |
| `tests/client/mdns/command_channel_test.rs` | 161 | `219a75c94a82` |
| `tests/client/mdns/e2e_test.rs` | 249 | `c949b4fae43a` |
| `tests/client/mdns/mod.rs` | 4 | `4aa6bd752d46` |
| `tests/client/memcached/CLAUDE.md` | 50 | `f02877dc2986` |
| `tests/client/memcached/in_flight_test.rs` | 87 | `f92178a7cc04` |
| `tests/client/memcached/mod.rs` | 6 | `cdd6c650e4ff` |
| `tests/client/memcached/real_server_test.rs` | 329 | `c19789a2b000` |
| `tests/client/memcached/wire_test.rs` | 231 | `4e0d8b96a169` |
| `tests/client/mod.rs` | 208 | `4422bb699e85` |
| `tests/client/modbus/CLAUDE.md` | 41 | `ceadf84a29c7` |
| `tests/client/modbus/codec_test.rs` | 143 | `004bae971b5c` |
| `tests/client/modbus/mod.rs` | 6 | `c038a805b11e` |
| `tests/client/modbus/real_server_test.rs` | 343 | `83e6422a5e9e` |
| `tests/client/modbus/unanswered_test.rs` | 174 | `d0899d5fec0f` |
| `tests/client/mongodb/CLAUDE.md` | 470 | `be7b281f1d5d` |
| `tests/client/mongodb/command_channel_test.rs` | 193 | `d1b715c0f3a5` |
| `tests/client/mongodb/e2e_test.rs` | 369 | `92a43587b834` |
| `tests/client/mongodb/mod.rs` | 6 | `de366014576e` |
| `tests/client/mqtt/CLAUDE.md` | 107 | `f13aebac7b43` |
| `tests/client/mqtt/command_channel_test.rs` | 213 | `e02929fd2868` |
| `tests/client/mqtt/keepalive_test.rs` | 276 | `ef9da34b03cb` |
| `tests/client/mqtt/mod.rs` | 6 | `68e704fe12ef` |
| `tests/client/mqtt/real_server_test.rs` | 314 | `4076991430f9` |
| `tests/client/mssql/CLAUDE.md` | 147 | `e60a6c6550a1` |
| `tests/client/mssql/command_channel_test.rs` | 219 | `78f919649f17` |
| `tests/client/mssql/e2e_test.rs` | 268 | `d5a059658f00` |
| `tests/client/mssql/mod.rs` | 5 | `df00e2d7843f` |
| `tests/client/mysql/CLAUDE.md` | 92 | `d100c0d06bb0` |
| `tests/client/mysql/command_channel_test.rs` | 187 | `7628ec5819a6` |
| `tests/client/mysql/e2e_test.rs` | 432 | `9c6c1048b673` |
| `tests/client/mysql/mod.rs` | 6 | `9760d281120e` |
| `tests/client/mysql/real_server_test.rs` | 223 | `2c558585b1c6` |
| `tests/client/nats/CLAUDE.md` | 131 | `5faee177b667` |
| `tests/client/nats/e2e_test.rs` | 835 | `62bf8b28272d` |
| `tests/client/nats/mod.rs` | 5 | `f900550509cd` |
| `tests/client/netbios_ns/CLAUDE.md` | 144 | `28d7cdd85dbc` |
| `tests/client/netbios_ns/e2e_test.rs` | 720 | `b151082fe639` |
| `tests/client/netbios_ns/mod.rs` | 2 | `69d4d51536a6` |
| `tests/client/nfc/CLAUDE.md` | 93 | `043288a5ac82` |
| `tests/client/nfc/command_channel_test.rs` | 199 | `ff7a8e52dc66` |
| `tests/client/nfc/e2e_test.rs` | 460 | `5416685346cb` |
| `tests/client/nfc/mod.rs` | 4 | `cf87671ccd07` |
| `tests/client/nfs/CLAUDE.md` | 258 | `d2f0f20d5685` |
| `tests/client/nfs/command_channel_test.rs` | 200 | `bcdbab62e924` |
| `tests/client/nfs/e2e_test.rs` | 207 | `6dc3f6aa59b8` |
| `tests/client/nfs/mod.rs` | 4 | `e51c3c1e56a9` |
| `tests/client/nntp/CLAUDE.md` | 196 | `1e90d16c558b` |
| `tests/client/nntp/command_channel_test.rs` | 173 | `44ad748f439b` |
| `tests/client/nntp/e2e_test.rs` | 378 | `ba1f2ca6ab1a` |
| `tests/client/nntp/mod.rs` | 4 | `ad31b48ff1b3` |
| `tests/client/npm/CLAUDE.md` | 272 | `1faf8891de7f` |
| `tests/client/npm/command_channel_test.rs` | 357 | `506c90e8b531` |
| `tests/client/npm/e2e_test.rs` | 273 | `cebb2ee2f001` |
| `tests/client/npm/mod.rs` | 8 | `4f4a948754f4` |
| `tests/client/npm/registry_target_test.rs` | 143 | `6170d29d54b9` |
| `tests/client/ntp/CLAUDE.md` | 215 | `003a7ba9a02e` |
| `tests/client/ntp/command_channel_test.rs` | 166 | `0ad23d2b66af` |
| `tests/client/ntp/e2e_test.rs` | 183 | `c1e5ba10e3a5` |
| `tests/client/ntp/mod.rs` | 9 | `70512d2dc25f` |
| `tests/client/oauth2/CLAUDE.md` | 318 | `fd22bb39cac8` |
| `tests/client/oauth2/command_channel_test.rs` | 258 | `b88a8e546350` |
| `tests/client/oauth2/e2e_test.rs` | 421 | `5ceb963ebe8e` |
| `tests/client/oauth2/mod.rs` | 4 | `46f082653e5a` |
| `tests/client/ollama/CLAUDE.md` | 336 | `e15a17bbb52f` |
| `tests/client/ollama/command_channel_test.rs` | 254 | `590d776a2b46` |
| `tests/client/ollama/e2e_test.rs` | 532 | `3485a4a4752b` |
| `tests/client/ollama/endpoint_targeting_test.rs` | 246 | `133749e9cdfb` |
| `tests/client/ollama/mod.rs` | 6 | `4a2267817cdf` |
| `tests/client/openai/CLAUDE.md` | 254 | `c6ad01d6d36c` |
| `tests/client/openai/command_channel_test.rs` | 285 | `56f837af75db` |
| `tests/client/openai/e2e_test.rs` | 267 | `d10dc3ee4704` |
| `tests/client/openai/endpoint_and_limits_test.rs` | 233 | `b3d4a4b8446e` |
| `tests/client/openai/mod.rs` | 6 | `7542a010653b` |
| `tests/client/openapi/CLAUDE.md` | 227 | `e29e889b807a` |
| `tests/client/openapi/command_channel_test.rs` | 241 | `c32ca35302a7` |
| `tests/client/openapi/e2e_test.rs` | 223 | `393bfb72fbdb` |
| `tests/client/openapi/mod.rs` | 8 | `742299851579` |
| `tests/client/openapi/target_precedence_test.rs` | 245 | `26b2c9b8bdec` |
| `tests/client/openapi/test-api.yaml` | 116 | `a49a0792aa6d` |
| `tests/client/openidconnect/CLAUDE.md` | 67 | `22553f513045` |
| `tests/client/openidconnect/command_channel_test.rs` | 256 | `d0906f9ea330` |
| `tests/client/openidconnect/e2e_test.rs` | 118 | `6e801ba3cc0d` |
| `tests/client/openidconnect/mod.rs` | 4 | `b03bd5177fed` |
| `tests/client/ospf/CLAUDE.md` | 392 | `ca592aa7efee` |
| `tests/client/ospf/command_channel_test.rs` | 216 | `f382cc886e09` |
| `tests/client/ospf/e2e_test.rs` | 180 | `e381b0bd9a13` |
| `tests/client/ospf/mod.rs` | 4 | `4cbfe57fa1ea` |
| `tests/client/pop3/CLAUDE.md` | 216 | `2109539a92d0` |
| `tests/client/pop3/command_channel_test.rs` | 150 | `5980595e9fb9` |
| `tests/client/pop3/e2e_test.rs` | 207 | `eb89c5d993cf` |
| `tests/client/pop3/mod.rs` | 6 | `ccaed71bbcec` |
| `tests/client/pop3/use_tls_refusal_test.rs` | 65 | `a7ab16f4bf3e` |
| `tests/client/postgresql/CLAUDE.md` | 78 | `1c40f0f64447` |
| `tests/client/postgresql/command_channel_test.rs` | 187 | `04efb6651123` |
| `tests/client/postgresql/e2e_test.rs` | 110 | `f1c345b33544` |
| `tests/client/postgresql/mod.rs` | 6 | `247bdc547c40` |
| `tests/client/postgresql/real_server_test.rs` | 221 | `45527e4b7671` |
| `tests/client/pypi/CLAUDE.md` | 285 | `d4a7194148c9` |
| `tests/client/pypi/command_channel_test.rs` | 220 | `249984282d60` |
| `tests/client/pypi/e2e_test.rs` | 170 | `563909a3a456` |
| `tests/client/pypi/index_target_test.rs` | 130 | `70d90b4d0766` |
| `tests/client/pypi/mod.rs` | 10 | `41c2ed9239d0` |
| `tests/client/radius/CLAUDE.md` | 41 | `aa94db86116c` |
| `tests/client/radius/mod.rs` | 6 | `de1529aa61a3` |
| `tests/client/radius/real_server_test.rs` | 453 | `463ac0149508` |
| `tests/client/radius/request_test.rs` | 137 | `c9c25274573c` |
| `tests/client/radius/transport_test.rs` | 343 | `2386670484da` |
| `tests/client/redis/CLAUDE.md` | 91 | `7e97e1f6071c` |
| `tests/client/redis/command_channel_test.rs` | 166 | `2793ac10c645` |
| `tests/client/redis/e2e_test.rs` | 217 | `cd2333eef9d5` |
| `tests/client/redis/mod.rs` | 8 | `f495b870c9bb` |
| `tests/client/redis/real_server_test.rs` | 261 | `0addd82a1059` |
| `tests/client/redis/resp_reader_test.rs` | 192 | `91ca38147a11` |
| `tests/client/rip/CLAUDE.md` | 77 | `295c37af788c` |
| `tests/client/rip/command_channel_test.rs` | 179 | `29cf362a7a5b` |
| `tests/client/rip/e2e_test.rs` | 60 | `ca09c6ce7b55` |
| `tests/client/rip/llm_path_test.rs` | 191 | `ed769acc8dde` |
| `tests/client/rip/mod.rs` | 6 | `561ff5b96481` |
| `tests/client/rss/CLAUDE.md` | 84 | `cb4a01672969` |
| `tests/client/rss/command_channel_test.rs` | 197 | `4c392d6a55fe` |
| `tests/client/rss/e2e_test.rs` | 194 | `42f0b6e4cd4f` |
| `tests/client/rss/mod.rs` | 4 | `89b15d625893` |
| `tests/client/s3/CLAUDE.md` | 358 | `f6153ecc8c69` |
| `tests/client/s3/command_channel_test.rs` | 323 | `1ecaf2e54dcd` |
| `tests/client/s3/e2e_test.rs` | 166 | `542ac9f6424c` |
| `tests/client/s3/mod.rs` | 6 | `76dbbafdca46` |
| `tests/client/saml/CLAUDE.md` | 169 | `f02601297f6a` |
| `tests/client/saml/command_channel_test.rs` | 212 | `8a72e6e9a4b8` |
| `tests/client/saml/e2e_test.rs` | 111 | `bac048694b71` |
| `tests/client/saml/mod.rs` | 8 | `68a401457836` |
| `tests/client/saml/startup_params_test.rs` | 234 | `9a540ace0c23` |
| `tests/client/saml/status_code_test.rs` | 173 | `ae412c8af064` |
| `tests/client/sip/CLAUDE.md` | 356 | `3514c3db5af8` |
| `tests/client/sip/command_channel_test.rs` | 192 | `2469ca22ae2c` |
| `tests/client/sip/e2e_test.rs` | 375 | `fb5b5f626b60` |
| `tests/client/sip/hostile_response_test.rs` | 196 | `f26040e607ea` |
| `tests/client/sip/mod.rs` | 6 | `f8c4d716fe46` |
| `tests/client/smb/CLAUDE.md` | 407 | `deb4f5e0ce50` |
| `tests/client/smb/command_channel_test.rs` | 171 | `2deb97b58bbe` |
| `tests/client/smb/e2e_test.rs` | 147 | `d1b24e3eaefa` |
| `tests/client/smb/mod.rs` | 4 | `b5c0afb68b4a` |
| `tests/client/smtp/CLAUDE.md` | 186 | `dbb1bc4e0e58` |
| `tests/client/smtp/command_channel_test.rs` | 244 | `0cf8afe26e40` |
| `tests/client/smtp/e2e_test.rs` | 171 | `32900ca64ae1` |
| `tests/client/smtp/mod.rs` | 6 | `f40801429575` |
| `tests/client/smtp/startup_params_test.rs` | 294 | `bea596550340` |
| `tests/client/snmp/CLAUDE.md` | 272 | `fce325c92d15` |
| `tests/client/snmp/command_channel_test.rs` | 186 | `189775d37236` |
| `tests/client/snmp/e2e_test.rs` | 315 | `944c71d41d13` |
| `tests/client/snmp/mod.rs` | 4 | `c3560bd2cdc4` |
| `tests/client/socket_file/CLAUDE.md` | 102 | `63fc2298fbd1` |
| `tests/client/socket_file/command_channel_test.rs` | 146 | `a4dc88fed709` |
| `tests/client/socket_file/e2e_test.rs` | 264 | `c493ff6fa83f` |
| `tests/client/socket_file/mod.rs` | 6 | `a43210ff80c1` |
| `tests/client/socks5/CLAUDE.md` | 381 | `c4ecddbfabdf` |
| `tests/client/socks5/action_test.rs` | 391 | `aa2cd1849403` |
| `tests/client/socks5/command_channel_test.rs` | 193 | `870bda2b1f6e` |
| `tests/client/socks5/e2e_test.rs` | 312 | `751e5c6077ae` |
| `tests/client/socks5/mod.rs` | 7 | `96cbaaaf517c` |
| `tests/client/sqs/CLAUDE.md` | 219 | `0af822b0d10e` |
| `tests/client/sqs/command_channel_test.rs` | 256 | `c5217db1a6a2` |
| `tests/client/sqs/e2e_test.rs` | 231 | `57c0bad044a4` |
| `tests/client/sqs/mod.rs` | 7 | `d56dda6fae99` |
| `tests/client/ssdp/CLAUDE.md` | 137 | `a249f79cb7c4` |
| `tests/client/ssdp/e2e_test.rs` | 608 | `022cba3fd0fd` |
| `tests/client/ssdp/mod.rs` | 2 | `08840d5e2ded` |
| `tests/client/ssh/CLAUDE.md` | 88 | `ab2d6e22b489` |
| `tests/client/ssh/command_channel_test.rs` | 241 | `dee13f87344f` |
| `tests/client/ssh/mod.rs` | 4 | `475716b73eee` |
| `tests/client/ssh/real_server_test.rs` | 327 | `16db20540a21` |
| `tests/client/ssh_agent/CLAUDE.md` | 211 | `04162a454703` |
| `tests/client/ssh_agent/command_channel_test.rs` | 150 | `a3de9b2fc4f6` |
| `tests/client/ssh_agent/e2e_test.rs` | 249 | `49bf7d6dd743` |
| `tests/client/ssh_agent/mod.rs` | 4 | `213c2156432f` |
| `tests/client/stomp/CLAUDE.md` | 98 | `8bcbb722ca4a` |
| `tests/client/stomp/e2e_test.rs` | 573 | `6105da91d59e` |
| `tests/client/stomp/mod.rs` | 2 | `801fc68b8cc8` |
| `tests/client/stun/CLAUDE.md` | 62 | `df6525590d16` |
| `tests/client/stun/command_channel_test.rs` | 198 | `94393b7ea82c` |
| `tests/client/stun/e2e_test.rs` | 122 | `e3a943062233` |
| `tests/client/stun/mod.rs` | 5 | `a5ec36555f3e` |
| `tests/client/syslog/CLAUDE.md` | 79 | `5581b837d8c3` |
| `tests/client/syslog/command_channel_test.rs` | 252 | `8242ef99cd38` |
| `tests/client/syslog/e2e_test.rs` | 163 | `271d5e2914c5` |
| `tests/client/syslog/mod.rs` | 4 | `1fa2b674ec12` |
| `tests/client/tcp/CLAUDE.md` | 40 | `da7ca3957370` |
| `tests/client/tcp/e2e_test.rs` | 229 | `d08fd22036aa` |
| `tests/client/tcp/mod.rs` | 2 | `26256c99ab8c` |
| `tests/client/telnet/CLAUDE.md` | 170 | `5739449bc74a` |
| `tests/client/telnet/e2e_test.rs` | 305 | `2fa493d81366` |
| `tests/client/telnet/mod.rs` | 2 | `ea32e7e6cc08` |
| `tests/client/tftp/CLAUDE.md` | 75 | `0127623deb11` |
| `tests/client/tftp/command_channel_test.rs` | 178 | `9b07196c3fa3` |
| `tests/client/tftp/e2e_test.rs` | 255 | `74957cdaf923` |
| `tests/client/tftp/mod.rs` | 5 | `ebb20639224c` |
| `tests/client/tls/CLAUDE.md` | 173 | `646882929207` |
| `tests/client/tls/command_channel_test.rs` | 179 | `c050054ac824` |
| `tests/client/tls/e2e_test.rs` | 410 | `6bb2779d9f30` |
| `tests/client/tls/mod.rs` | 8 | `531f938f97fd` |
| `tests/client/tls/multi_turn_test.rs` | 147 | `e828d24b5ef5` |
| `tests/client/tor/CLAUDE.md` | 109 | `02376d38be1f` |
| `tests/client/tor/action_test.rs` | 391 | `dfce3c6810a0` |
| `tests/client/tor/apply_actions_test.rs` | 126 | `b29b3f587a6d` |
| `tests/client/tor/command_channel_test.rs` | 80 | `03d0bb353954` |
| `tests/client/tor/e2e_test.rs` | 159 | `0d8311e97114` |
| `tests/client/tor/mod.rs` | 16 | `8f5fe90d2114` |
| `tests/client/tor/test.rs` | 164 | `7ae94b50e839` |
| `tests/client/torrent_dht/CLAUDE.md` | 51 | `4c87abbe6007` |
| `tests/client/torrent_dht/command_channel_test.rs` | 231 | `22c306111240` |
| `tests/client/torrent_dht/e2e_test.rs` | 97 | `6932515b2e58` |
| `tests/client/torrent_dht/mod.rs` | 4 | `59a3e548831f` |
| `tests/client/torrent_peer/CLAUDE.md` | 53 | `6599f0b07fce` |
| `tests/client/torrent_peer/command_channel_test.rs` | 186 | `4f7359366311` |
| `tests/client/torrent_peer/e2e_test.rs` | 116 | `e8ebf6571623` |
| `tests/client/torrent_peer/mod.rs` | 5 | `d1b357d09c0b` |
| `tests/client/torrent_tracker/command_channel_test.rs` | 451 | `6f0aa5e17a89` |
| `tests/client/torrent_tracker/followup_chain_test.rs` | 178 | `b0fdbc8b5612` |
| `tests/client/torrent_tracker/mod.rs` | 5 | `d010262dcdd8` |
| `tests/client/turn/CLAUDE.md` | 228 | `899374b26980` |
| `tests/client/turn/command_channel_test.rs` | 236 | `fc47f63420ce` |
| `tests/client/turn/e2e_test.rs` | 299 | `d36c654d9b6b` |
| `tests/client/turn/mod.rs` | 6 | `8bf42bcfd978` |
| `tests/client/turn/response_parsing_test.rs` | 235 | `a184448de829` |
| `tests/client/udp/CLAUDE.md` | 210 | `5a940c16ad1d` |
| `tests/client/udp/command_channel_test.rs` | 177 | `c1d90f342e5b` |
| `tests/client/udp/e2e_test.rs` | 403 | `a6906a44c61a` |
| `tests/client/udp/mod.rs` | 5 | `0ae49bafa209` |
| `tests/client/usb/CLAUDE.md` | 204 | `c8c9106e2be7` |
| `tests/client/usb/command_channel_test.rs` | 168 | `2c6b8333c59b` |
| `tests/client/usb/e2e_test.rs` | 252 | `cd404c9f9168` |
| `tests/client/usb/mod.rs` | 4 | `cee565ae799c` |
| `tests/client/vnc/CLAUDE.md` | 205 | `22d097ceda3a` |
| `tests/client/vnc/command_channel_test.rs` | 164 | `563c7ad45d22` |
| `tests/client/vnc/coordinate_range_test.rs` | 114 | `3b2564b6804b` |
| `tests/client/vnc/e2e_test.rs` | 203 | `61fcd8e2c372` |
| `tests/client/vnc/mod.rs` | 6 | `bb2325a61544` |
| `tests/client/webdav/CLAUDE.md` | 109 | `6f7cbedf449a` |
| `tests/client/webdav/command_channel_test.rs` | 249 | `5110195cebe8` |
| `tests/client/webdav/e2e_test.rs` | 250 | `9aa86f2e2fae` |
| `tests/client/webdav/mod.rs` | 5 | `ecadb7bf5902` |
| `tests/client/webrtc/CLAUDE.md` | 336 | `4fdd18e0db8e` |
| `tests/client/webrtc/command_channel_test.rs` | 176 | `c6c36367401d` |
| `tests/client/webrtc/e2e_test.rs` | 151 | `b07d44d7afbd` |
| `tests/client/webrtc/mod.rs` | 4 | `7b7ea5c5cd87` |
| `tests/client/websocket/CLAUDE.md` | 97 | `e380932cfbf9` |
| `tests/client/websocket/command_channel_test.rs` | 198 | `d65c5cc19bbb` |
| `tests/client/websocket/e2e_test.rs` | 364 | `c1a16421078c` |
| `tests/client/websocket/keepalive_test.rs` | 239 | `605ac03edf06` |
| `tests/client/websocket/mod.rs` | 5 | `9a0b45e2cd92` |
| `tests/client/whois/CLAUDE.md` | 79 | `895c85baea15` |
| `tests/client/whois/command_channel_test.rs` | 169 | `9f1f92d0fb26` |
| `tests/client/whois/e2e_test.rs` | 159 | `6e294063698e` |
| `tests/client/whois/mod.rs` | 4 | `a9db3043d278` |
| `tests/client/wireguard/CLAUDE.md` | 206 | `11fe8ec8de12` |
| `tests/client/wireguard/command_channel_test.rs` | 178 | `b67e0355f066` |
| `tests/client/wireguard/e2e_test.rs` | 321 | `5de773baa296` |
| `tests/client/wireguard/mod.rs` | 4 | `3f758bb57455` |
| `tests/client/xmlrpc/command_channel_test.rs` | 199 | `4acd5a627edb` |
| `tests/client/xmlrpc/mod.rs` | 4 | `19da255faa27` |
| `tests/client/xmlrpc/response_guard_test.rs` | 223 | `c21a891a79d6` |
| `tests/client/xmpp/CLAUDE.md` | 280 | `dc32b2e346f7` |
| `tests/client/xmpp/command_channel_test.rs` | 152 | `971f2e71a2df` |
| `tests/client/xmpp/e2e_test.rs` | 190 | `76adab975c5a` |
| `tests/client/xmpp/mod.rs` | 6 | `cb9b8625b734` |
| `tests/client/xmpp/startup_params_test.rs` | 126 | `25e49522f8e7` |
| `tests/client/zookeeper/command_channel_test.rs` | 279 | `08221adec4ce` |
| `tests/client/zookeeper/mod.rs` | 2 | `261e3400e5c0` |

<a id="runtime"></a>
## CLI, state and protocol runtime review — 2026-10-01

**Coordinator completion note:** The listed startup/management/task/template/SQLite targets passed in the native regression set. sqlite_identifier_test ran; the broader sqlite_test target was suggested but was not separately executed. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and constraints

Second-wave review of `src/cli/**`, `src/state/**` and `src/protocol/**`, after the server review. Every Rust file in these directories participated in inventory and risk-pattern scans (panics, raw I/O, casts, time arithmetic, task creation/cancellation, parameter validation, registry lookup and dynamic SQL/log formatting). Focused manual reads followed the state/task, create/update and rendering paths described below. This report distinguishes those targeted reads from full functional verification.

- `src/cli`: 15 Rust files, 6,873 lines at the report snapshot.
- `src/state`: 11 Rust files, 5,483 lines at the report snapshot.
- `src/protocol`: 15 Rust files, 5,906 lines at the report snapshot.

No GPU, embedded model, public service or real LLM was run. The scheduler completion regression uses the project's **local `MockOllamaServer`** with one canned response, pinned model name, and scripting disabled. Other new tests are pure state/formatting/in-memory SQL or deterministic static HTTP on loopback. All Cargo builds/tests are coordinated by the root agent.

### Implemented changes

#### R1. Reject malformed parameter containers before creation or restart

**Source:** `src/protocol/spawn_context.rs`, `src/cli/management.rs`.

`StartupParams::new` only checked keys inside `if let Some(obj) = params.as_object()`. Arrays, booleans, numbers, strings and null bypassed validation and behaved like an empty parameter set when optional accessors were used. Separately, the management update's `merge_params` silently ignored a non-object overlay and returned the old parameters as a new object; the caller then treated the supplied update as restart-worthy and could drop an otherwise healthy connection for an invalid request.

The constructor now requires a JSON object and returns `StartupParamError::Invalid` naming `startup_params` for malformed containers. `merge_params` is fallible and rejects a non-object overlay before either server or client update mutates state. Valid object overlays keep their previous key-merge behavior; explicit null **field values inside an object** still retain their existing accessor semantics. An absent container belongs in the outer `Option`, rather than as a scalar value inside `StartupParams`.

**Tests:** `tests/startup_params_result_test.rs::parameter_container_must_be_an_object` covers six invalid JSON shapes plus an empty object; `tests/management_test.rs::non_object_startup_update_keeps_the_existing_server` attempts four malformed overlays while requiring the original static HTTP server ID and response to survive.

#### R2. Scheduled tasks use their allocated ID everywhere

**Source:** `src/state/app_state.rs::add_task`.

`add_task` allocated the storage-map key but left `ScheduledTask.id` at its caller-supplied value. Constructors in the tree pass zero or a random placeholder. The scheduler later updated status, recorded executions and removed completed tasks using this stale internal ID, which could miss the stored task or affect a different task if a placeholder happened to collide. This is a functional defect, not just display inconsistency: a completed task could remain scheduled indefinitely.

`add_task` now assigns the allocated ID back to the task before storing it. Name lookup, numeric lookup, task clones, execution bookkeeping and removal refer to the same identity.

**Test:** `allocated_task_id_controls_lookup_status_and_removal` passes a distinctive placeholder, compares returned and stored IDs, changes status through the stored ID and removes the task through that same ID.

#### R3. Concurrent scheduler ticks atomically claim work

**Source:** `src/state/app_state.rs::claim_due_tasks`, `src/cli/tasks.rs`.

The timer used a snapshot from `get_all_tasks()` and then separate `update_task_status` calls. Two concurrent timer drivers could both see `Scheduled`, independently mark the same task and both execute it. The scan also cloned future/completed tasks that would immediately be ignored.

The state API now selects only due scheduled tasks and marks them `Executing` while holding one write lock, returning owned clones to the timer. The timer spawns only this claimed set; network/model work still occurs after the state lock is released.

**Test:** sixteen concurrent claimers synchronize on a barrier around one due task, one future task and one completed task. Exactly one claimer receives the due task, a further tick receives nothing while it is executing, and the future task remains scheduled. The test has no model or socket.

#### R4. Recurring tasks stop at their execution limit

**Source:** `src/cli/tasks.rs::handle_task_success`, `src/cli/mod.rs`.

Success handling incremented the stored execution count but checked the pre-execution task snapshot against `max_executions`. A task with `max_executions: 1` therefore scheduled a second run. The comparison now includes the just-completed run using saturating addition on the snapshot count.

The existing tick wrapper is publicly re-exported from `cli` so an integration test can drive the production timer path; the entire internal task module remains private.

**Test:** `recurring_task_stops_after_its_first_allowed_execution` creates a recurring task with a one-run limit and a far-future interval, makes its first deadline due, drives one real scheduler tick against a local mock, waits for the explicit removal status, and asserts the task is absent. A second tick cannot call the mock again; exact mock call verification requires one request. This covers the R2 task-ID fix and the R4 completion fix together without a real model.

#### R5. Log templates replace only original template matches

**Source:** `src/protocol/log_template.rs`.

The old renderer iterated matches from the original template but repeatedly called `String::replace` on the evolving result. A peer's field value containing `{another_field}` was then interpreted again when that other field appeared later in the template. Repeated template occurrences could compound the rewriting. Log output no longer faithfully represented the input data, and each match rescanned/reallocated the complete growing string.

The renderer now uses one `Regex::replace_all` pass with a closure. Replacement strings are inserted literally, including dollar signs and braces. Each field still goes through `line_field`, so CR/LF and other terminal control characters remain sanitized.

**Test:** `tests/log_template_test.rs::field_values_containing_placeholders_remain_literal` mixes cross-referencing placeholder text, a repeated placeholder, `$1` and CRLF. It requires literal data values and sanitized control characters. Existing `log_template_injection_test` remains relevant regression coverage.

#### R6. SQLite introspection quotes legal table identifiers

**Source:** `src/state/sqlite.rs`.

Schema refresh and DML row-count refresh inserted table names from `sqlite_master` into single-quoted SQL without escaping. A legal table such as `"O'Brien"` could be created successfully, then cause the following metadata refresh to fail, reporting the overall operation as an error while the table already existed. Embedded double quotes and punctuation also need intentional identifier handling.

A private, feature-gated identifier helper wraps names in double quotes and doubles embedded double quotes. The same helper is used for `PRAGMA table_info`, initial `COUNT(*)` and DML count refresh. Values and arbitrary caller SQL are not rewritten.

**Test:** `tests/sqlite_identifier_test.rs` creates tables named `O'Brien`, `double"quote`, `semi;colon`, and `雪 table` in an in-memory database; inserts two rows, checks column/row metadata, deletes one row, rechecks the count and refreshes the complete schema. No filesystem database is created.

### Validation handoff and results

All changed Rust files were formatted individually with `rustfmt --edition 2021 --config skip_children=true`. `git diff --check` passed for the owned source/test paths. The complete accumulated source diff was manually re-read after the final changes, including the earlier server changes.

Cargo execution is centralized. The root agent received these target names and CPU-only feature requirements; the main review report records the actual execution outcomes:

| Target | New tests | Required feature | Runtime behavior |
|---|---:|---|---|
| `startup_params_result_test` | 1 | none | Pure parameter parsing. |
| `management_test` | 1 | `http` | In-process static loopback HTTP, no model. |
| `scheduled_task_claim_test` | 3 | none | Two pure state tests; one local mock HTTP server. |
| `log_template_test` | 1 | none | Pure string rendering. |
| `sqlite_identifier_test` | 1 | `sqlite` | In-memory SQL only. |

Related existing regression targets requested: `server_stop_cleans_scheduled_tasks_test`, `scheduled_task_actions_test`, `log_template_injection_test`, `sqlite_test`. Seven new runtime test functions were added. Together with eight new server test functions, this agent's two sections add fifteen focused regressions.

### Remaining observed risks and boundaries

#### Scheduling delay arithmetic can still overflow

**Confirmed locally with a standalone CPU-only standard-library program:**

```rust
fn main() {
    let now = std::time::Instant::now();
    println!("{}", now.checked_add(std::time::Duration::from_secs(u64::MAX)).is_some());
}
```

This printed `false` on the current native macOS environment. The unguarded `now + Duration::from_secs(u64::MAX)` form consequently panics. Relevant paths:

- `ScheduledTask::new_one_shot` and `new_recurring` in `src/state/task.rs`.
- `next_execution: Instant::now() + delay` in `src/cli/server_startup.rs`, `client_startup.rs` and management task construction.
- Recurring rescheduling in `src/cli/tasks.rs`.

A minimal in-process repository reproduction is `ScheduledTask::new_one_shot(TaskId::new(0), "overflow".into(), TaskScope::Global, u64::MAX, "noop".into(), None)`. A corresponding supplied `scheduled_tasks` definition with `delay_secs: 18446744073709551615` reaches the CLI builders. This report does **not** claim that constructor reproduction was executed against the full NetGet library; the standalone representability test and the source additions establish the arithmetic failure.

The root agent explicitly retained this as follow-up for this batch: a correct fix should define a scheduling validation policy, return an actionable error before creating/mutating an instance, and propagate it through direct task constructors and the LLM action path. Silently clamping a requested delay or executing it immediately would change the requested behavior. No broad fallible-constructor API migration was attempted in this batch.

#### Other evidence boundaries

- Atomic claiming prevents duplicate selection; it does not add cancellation ownership to already-running scheduled-task execution futures. A task removed after selection can still have in-flight work, and scope teardown requires separate cancellation analysis.
- Parameter-container validation does not promise every protocol-specific value is validated before a restart; many semantic checks live in the protocol spawn implementation. Existing valid-object behavior is preserved.
- Registry/dependency code was inspected structurally, but optional native libraries, hardware and all feature permutations were not loaded or built by this subagent.
- SQLite query classification still follows the existing statement-prefix logic. This change fixes identifier handling in metadata refreshes; it is not a SQL parser redesign or a bound on arbitrary query result size.
- Existing `easy_startup` has a limited client implementation and trusts generated action field conventions. This pass did not claim to complete that optional surface.

### Complete file coverage ledger

Every file below received inventory/risk-pattern scanning. Focused notes identify directly followed code paths; other entries are static triage, not assertions of full runtime correctness.

| File | Lines | Focus / disposition |
|---|---:|---|
| `src/cli/args.rs` | 935 | Reviewed lazy cached stdin/action-file handling; scanned numeric parsing and options. |
| `src/cli/banner.rs` | 194 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/cli/client_startup.rs` | 426 | Reviewed symmetric client startup/task construction and unchecked delay. |
| `src/cli/crash_restore.rs` | 92 | Scanned signal/termios unsafe ownership; no signal tests or terminal changes. |
| `src/cli/easy_startup.rs` | 164 | Read generated action execution, wrapper status, ID and port handling; no change. |
| `src/cli/input_state.rs` | 419 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/cli/management.rs` | 1,355 | Fixed malformed-overlay validation; followed hot/restart paths and scheduled-task construction. |
| `src/cli/mod.rs` | 780 | Re-exported existing tick wrapper for integration coverage; inspected module boundary. |
| `src/cli/model_select.rs` | 98 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/cli/non_interactive.rs` | 717 | Reviewed run-limit elapsed-time checks and timer/shutdown paths; no change. |
| `src/cli/server_startup.rs` | 830 | Read generic schema/privilege/dependency/startup paths; recorded unchecked scheduled delay. |
| `src/cli/setup.rs` | 196 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/cli/tasks.rs` | 410 | Fixed atomic timer claiming and one-run completion limit; inspected backoff and action dispatch. |
| `src/cli/terminal_cleanup.rs` | 4 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/cli/theme.rs` | 253 | Inspected terminal flag preservation and nonblocking flush; no terminal query run. |
| `src/protocol/binding_defaults.rs` | 96 | Read user override precedence; no change. |
| `src/protocol/client_registry.rs` | 882 | Inspected exact/normalized client lookup and feature error paths; no change. |
| `src/protocol/connect_context.rs` | 83 | Read client context and StartupParams propagation; no change. |
| `src/protocol/default_port.rs` | 173 | Inspected protocol defaults and privilege/in-use fallback; no sockets opened by review. |
| `src/protocol/dependencies.rs` | 502 | Inspected dynamic-library probe handle cleanup and native dependency checks; no probes run. |
| `src/protocol/docs.rs` | 124 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/dual.rs` | 117 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/easy_registry.rs` | 84 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/event_logger.rs` | 325 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/event_type.rs` | 472 | Inspected action declarations/default examples and event field conventions; no change. |
| `src/protocol/log_template.rs` | 285 | Fixed recursive replacement of input values; retained sanitization. |
| `src/protocol/metadata.rs` | 582 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/mod.rs` | 121 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/protocol/server_registry.rs` | 1,449 | Inspected exact/normalized lookup and feature-gated registry paths; no registration changes. |
| `src/protocol/spawn_context.rs` | 611 | Fixed object-shape validation; reviewed typed accessor error paths. |
| `src/state/app_state.rs` | 3,302 | Fixed task ID assignment and atomic claims; reviewed server/client task ownership, handles, intercepts and teardown. |
| `src/state/client.rs` | 343 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/state/client_handles.rs` | 65 | Read command queue/reply types and lifetime documentation; no change. |
| `src/state/easy.rs` | 136 | Inspected wrapper instance IDs/status and optional handle; no change. |
| `src/state/intercepts.rs` | 103 | Read dead-entry detection and oneshot ownership; no change. |
| `src/state/machine.rs` | 58 | Read generic map-backed state machine; no change. |
| `src/state/mod.rs` | 26 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/state/server.rs` | 483 | Read connection registration/removal/history and cleanup; no change. |
| `src/state/server_handles.rs` | 55 | Structural/risk-pattern scan; no demonstrated defect changed in this file. |
| `src/state/sqlite.rs` | 612 | Fixed identifier quoting; inspected metadata refresh, query dispatch and database-name protections. |
| `src/state/task.rs` | 300 | Read task definitions/constructors and execution counters; documented extreme-delay overflow. |

<a id="surfaces"></a>
## Surface review — 2026-10-01

**Coordinator completion note:** All 14 native compatibility-crate tests and all eight Node tests passed. Centralized dashboard_frame_test passed 17 tests and display_rendering_test passed four. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and operating constraints

Reviewed the native dashboard, shared UI state, CPU raster display implementation, browser shim crates, browser demo/test infrastructure, landing page, and npm launcher. No GPU, WebGPU adapter, model download, LLM inference, remote model endpoint, deployment, publication, or commit was used. Tests are CPU-only and either pure functions, in-memory transport, a synthetic terminal, or a harmless fixture child process.

This is an evidence-based improvement pass, not a claim of complete formal verification. Every source area below was inventoried and scanned; detailed behavioral inspection concentrated on input/rendering, raster bounds, browser timer/network semantics, browser answer conversion, streamed Telnet traffic, and executable resolution. Unchanged modules received interface/risk-pattern review, not exhaustive execution of every branch. The root coordinator owns whole-project Rust validation and the final consolidated report.

### Implemented changes

#### Native dashboard

1. **Keep long and multiline input visible.** The chat box previously rendered from the first line and column forever, even when editing the ninth line in a five-row box. The cursor disappeared past the right edge. It now selects a vertical viewport around the cursor and clips the horizontal viewport at grapheme boundaries. The prompt remains visible.
2. **Place input cursors in terminal cells.** InputState uses Unicode scalar indices, whereas wide CJK symbols occupy two cells and combining marks occupy none. Cursor placement now measures the prefix with ratatui's display-width rules. Horizontal clipping pads a partially clipped wide glyph and avoids splitting a grapheme.
3. **Avoid input-height truncation.** Input line counts are bounded before converting to u16; large pastes can no longer wrap the height through a narrowing cast.
4. **Wrap conversation text by display width.** Character-count chunking used to silently clip the latter half of wide-character lines. Conversations now wrap whole graphemes before the terminal width is exceeded; combining sequences stay intact.
5. **Preserve trailing newlines in text editors.** Opening and accepting an existing script/instruction previously removed trailing line endings because str::lines omits the final empty line. Splitting on newline preserves it, including repeated blank lines and CRLF content.
6. **Restore raw mode after terminal setup failures.** The terminal drop guard is now armed immediately after entering raw mode, before alternate-screen/mouse-capture setup can fail.

Native regressions were added to `tests/dashboard_frame_test.rs` for long/multiline input, wide and combining cursor placement, trailing newlines, and CJK conversation wrapping.

#### CPU display rendering

7. **Allow zero-dimension canvases.** Empty canvas dimensions return an empty image with the requested dimensions rather than panicking while creating a pixmap.
8. **Treat degenerate shapes as no-ops.** Zero-width/height rectangles, zero-radius circles, and any path rejected by tiny-skia no longer unwrap a missing path/rectangle.
9. **Prevent coordinate overflow.** Window offsets, nested commands, textbox origins and button-label coordinates use saturating arithmetic. Offscreen coordinates remain offscreen instead of wrapping into the canvas or panicking in debug builds.
10. **Reject invisible text early.** Zero-size fonts, fully transparent text, empty strings and offscreen origins return without shaping invalid or unnecessary text.
11. **Render multiline text and color glyphs correctly.** The renderer now uses cosmic-text's pixel callback, which applies each line's baseline and distinguishes grayscale masks from RGBA glyph images. The old loop treated each RGBA byte as another alpha pixel and placed every line at the same baseline.
12. **Respect text alpha and premultiplied destination alpha.** Source-over compositing applies both glyph coverage and requested color alpha; transparent pixmaps retain meaningful alpha instead of every touched pixel becoming opaque.
13. **Reuse glyph raster cache across calls to a TextRenderer.** SwashCache now belongs to the renderer instead of being recreated for each draw.
14. **Make ASCII art actually monospace.** AsciiRenderer requests the monospace family, bounds row coordinate arithmetic, and stops once subsequent rows are outside the image.
15. **Center button labels by Unicode scalar count rather than UTF-8 byte count.** This retains the existing approximate seven-pixel metric while removing a systematic non-ASCII bias.

New `tests/display_rendering_test.rs` covers empty surfaces, zero shapes, offscreen nested windows, transparent/half-transparent text, multiline baselines, and invalid font/origin inputs. This is software rasterization, not GPU rendering. The positive text fixture requires usable system fonts and fails rather than silently skipping if none render.

#### Browser tokio compatibility

16. **Respect signed host timer limits.** The locally installed gloo-timers implementation casts its u32 argument to i32. Delays over i32::MAX milliseconds previously became negative host timers and could repeatedly wake immediately. Each host timer chunk now clamps to i32::MAX.
17. **Preserve full requested deadlines.** Only host timer chunks are clamped; sleep/timeout deadlines no longer get shortened to the old maximum. An overflowing deadline saturates to the representable maximum instead of completing immediately.
18. **Round fractional milliseconds upward.** Positive sub-millisecond delays no longer become zero-delay timer churn.
19. **Skip missed interval ticks in constant time.** The previous loop stepped once per missed period; a suspended browser could do millions/billions of iterations. Modular duration arithmetic finds the next original schedule boundary directly.
20. **Make UDP try_recv_from read the actual queue.** It previously saw only a datagram buffered by readable/peek; data already queued by a sender still returned WouldBlock. The method now checks peeked data first and then tries the receiver without awaiting.
21. **Align connected try_recv with async recv.** Non-connected use reports NotConnected; packets from other peers are discarded until the connected peer's datagram is found or the queue is empty.

Pure timer math is in a small internal module shared by native regression tests through a path inclusion; this does not add testing code under src. UDP tests use in-memory channels, with no real network or browser.

#### Browser demo and answer composer

22. **Parse Telnet incrementally across TCP chunks.** A connection-scoped decoder retains IAC, option negotiation and subnegotiation state. Split command bytes are no longer lost or mistaken for visible text, and a missing option byte cannot generate a reply for invented option zero.
23. **Decode UTF-8 incrementally.** A connection-local streaming TextDecoder retains multibyte characters split across network callbacks. It flushes any remaining decoder state at close.
24. **Normalize split CRLF correctly.** Newline normalization remembers whether the preceding callback ended with CR, avoiding duplicate carriage returns.
25. **Preserve raw answer edits.** Clicking the already active raw tab no longer overwrites edits with the old form. Moving to Form is refused when conversion would change the JSON; the visitor keeps the raw text and receives an explanation.
26. **Reject lossy envelope conversion.** Raw-to-form conversion compares rebuilt JSON structurally, preserves property ordering independence, and rejects null/non-array action lists, removed optional values, missing required fields, and tool/action category changes that the form cannot preserve.
27. **Preserve literal __proto__ fields as data.** Form action and extras dictionaries use null prototypes, so JSON metadata keys do not invoke Object.prototype setters or disappear during serialization.
28. **Reject unsafe numeric integers in form fields.** Values beyond JavaScript's exact integer range now produce a field error directing the visitor to Raw JSON instead of silently rounding the wire value.

`web/test/telnet_test.mjs` tests every two-chunk split of a mixed negotiation/Unicode/subnegotiation stream, one-byte chunks, empty chunks and incomplete option negotiation. `web/test/composer_model_test.mjs` tests precise integers, faithful conversion and prototype-named JSON properties. These can run without a WASM bundle or browser.

#### npm launcher

29. **Separate downloaded caches by platform/architecture/libc.** The old cache used only package version, so Rosetta/native Node or a shared cache could execute the wrong architecture. Cache paths include the resolved platform key.
30. **Stream archive downloads with a deadline.** Downloading previously buffered the entire archive in memory and had no deadline. The launcher now pipes the response to disk and applies a two-minute abort signal to the fetch and stream.
31. **Reject extracted non-regular binary files.** A symlink/directory named netget no longer passes the binary check.
32. **Remove failed staging files.** The cache staging file is cleaned even if chmod/rename fails.
33. **Forward repeated termination signals while the child lives.** child.killed only means a signal was sent, not that the child exited. Signal forwarding now checks actual exit/signal status so a second termination attempt is not discarded.

`tests/npm_launcher_test.cjs` uses a harmless Node/shell child to assert argv/stdout/exit propagation and platform-keyed cache selection. It never runs NetGet or downloads anything. The cache fixture is Unix-specific and would skip on Windows; both tests ran here without skips.

### Verification completed by this agent

- `env CARGO_TARGET_DIR=/private/tmp/netget-audit-wasm-20261001 RUSTC_WRAPPER= CARGO_PROFILE_TEST_DEBUG=0 cargo test -p netget-tokio-wasm --test tcp_peek_test --test udp_receive_test --test time_math_test --locked --offline`: **14 passed**, 0 failed, 0 ignored. First build took 2m29s; actual tests completed without waiting.
- `node --test web/test/composer_model_test.mjs web/test/telnet_test.mjs`: **6 passed**, 0 failed, 0 skipped.
- `node --test tests/npm_launcher_test.cjs`: **2 passed**, 0 failed, 0 skipped.
- `node --check site/js/demo.js`, `node --check site/js/composer.js`: passed.
- `bash -n site/deploy.sh web/build.sh`: passed; deployment/build scripts were syntax checked, not executed.
- Targeted `rustfmt --edition 2021` and `git diff --check`: passed at this report checkpoint.
- Root Rust dashboard/display regression execution is coordinated by the root agent; its final result must be read from the consolidated report. No success is inferred from formatting alone.

One newly written composer test initially incorrectly expected a JSON string number to be rejected. Inspection showed that source strings become text fields and round-trip exactly; the test was corrected to require preservation. This did not relax existing repository expectations.

### Limits and deferred findings

- No GPU-backed demo, real browser model, real LLM endpoint, or GPU capability probe was run. Browser model management paths were inspected statically only.
- The existing full browser/Playwright smoke suites were not executed in this section because they can exercise GPU/model availability paths and require a built WASM bundle. New parser/model suites are independent and CPU-only.
- The new site module is inside versioned js assets, so the existing deployment packaging picks it up. No site deployment occurred; changes are local and reviewable.
- Font discovery still occurs when a new TextRenderer is created for each canvas text command; a render-scoped font context would avoid repeated discovery but requires wider ownership changes. The glyph cache is reused within each existing renderer.
- DisplayCanvas still has an infallible public render API for nonempty allocation failure; huge allocation requests need a deliberate fallible API/resource-limit design. Deep nested window trees still use recursive execution and clone nested commands while offsetting.
- Virtual UDP queues and TCP listener accept queues remain unbounded; explicit backpressure/loss policy should be designed before changing their semantics. Concurrent UDP peek/readiness interactions and recv_from filtering on connected sockets remain candidates for stronger parity tests.
- ActivityFeed cursor/scroll preservation when the bounded ring evicts old entries, and pruning per-card fold state after instances vanish, deserve further lifecycle tests.
- Some inactive legacy src/ui layout/event files still reference removed UI APIs; src/ui/mod.rs does not compile them. This pass did not remove historical files opportunistically.
- The npm fallback still trusts the release transport/artifact source and system archive extractor; it does not verify a release checksum/signature. Release manifest provenance should be implemented together with the packaging pipeline. Download timeout/staging failure and repeated-signal behavior were source reviewed but not fault-injection tested here.
- Windows archive extraction, cache replacement behavior and signal propagation were not executed on this macOS host.
- Existing docs carry historical claims that can drift (public/private repository state, protocol counts, feature availability). No external services were queried to refresh those claims.

### File inventory covered

The list below includes source, manifests, static assets, scripts, documentation and browser tests in the owned roots (generated demo/pkg, pycache and other build products excluded). New files from this pass are included. Detailed inspection covered the changed areas and their immediate callers; the remaining entries received inventory/interface/risk scanning, not a guarantee of branch-complete review.

- `src/tui/CLAUDE.md`
- `src/tui/actions.rs`
- `src/tui/activity.rs`
- `src/tui/app.rs`
- `src/tui/cards.rs`
- `src/tui/chat.rs`
- `src/tui/command_exec.rs`
- `src/tui/commands.rs`
- `src/tui/driver.rs`
- `src/tui/event_loop.rs`
- `src/tui/hit.rs`
- `src/tui/keymap.rs`
- `src/tui/metrics.rs`
- `src/tui/mod.rs`
- `src/tui/modal/composer.rs`
- `src/tui/modal/confirm.rs`
- `src/tui/modal/form.rs`
- `src/tui/modal/help.rs`
- `src/tui/modal/intercept.rs`
- `src/tui/modal/mod.rs`
- `src/tui/modal/protocol_picker.rs`
- `src/tui/modal/request_detail.rs`
- `src/tui/modal/routing.rs`
- `src/tui/modal/text_editor.rs`
- `src/tui/modal_keys.rs`
- `src/tui/projection.rs`
- `src/tui/rail.rs`
- `src/tui/render/cards.rs`
- `src/tui/render/chat.rs`
- `src/tui/render/mod.rs`
- `src/tui/render/overlay.rs`
- `src/tui/render/rail.rs`
- `src/tui/render/status_bar.rs`
- `src/tui/render/stream.rs`
- `src/tui/theme.rs`
- `src/tui/uimsg.rs`
- `src/tui/wireshark.rs`
- `src/ui/app.rs`
- `src/ui/events.rs`
- `src/ui/layout.rs`
- `src/ui/mod.rs`
- `src/display/ascii.rs`
- `src/display/canvas.rs`
- `src/display/mod.rs`
- `src/display/text.rs`
- `src/display/types.rs`
- `crates/netget-crossterm-wasm/Cargo.toml`
- `crates/netget-crossterm-wasm/src/lib.rs`
- `crates/netget-tokio-wasm/Cargo.toml`
- `crates/netget-tokio-wasm/src/fs.rs`
- `crates/netget-tokio-wasm/src/lib.rs`
- `crates/netget-tokio-wasm/src/net.rs`
- `crates/netget-tokio-wasm/src/process.rs`
- `crates/netget-tokio-wasm/src/runtime.rs`
- `crates/netget-tokio-wasm/src/signal.rs`
- `crates/netget-tokio-wasm/src/task.rs`
- `crates/netget-tokio-wasm/src/time.rs`
- `crates/netget-tokio-wasm/src/time_math.rs`
- `crates/netget-tokio-wasm/tests/tcp_peek_test.rs`
- `crates/netget-tokio-wasm/tests/time_math_test.rs`
- `crates/netget-tokio-wasm/tests/udp_receive_test.rs`
- `crates/netget-web/Cargo.toml`
- `crates/netget-web/src/backend.rs`
- `crates/netget-web/src/input.rs`
- `crates/netget-web/src/lib.rs`
- `web/README.md`
- `web/build.sh`
- `web/test/composer_model_test.mjs`
- `web/test/page_composer.py`
- `web/test/smoke.mjs`
- `web/test/telnet_test.mjs`
- `site/CLAUDE.md`
- `site/css/demo.css`
- `site/css/style.css`
- `site/deploy.sh`
- `site/favicon.svg`
- `site/index.html`
- `site/js/composer.js`
- `site/js/demo.js`
- `site/js/main.js`
- `site/js/telnet.js`
- `site/js/thinking.js`
- `npm/netget/README.md`
- `npm/netget/bin/netget.js`
- `npm/netget/package.json`

<a id="automation"></a>
## Automation/MCP review — 2026-10-01

**Coordinator completion note:** Centralized validation passed agent_queue_fifo_test (2), scripting_highlight_test (2), scripting_manager_test (8), scripting_resident_test (15), and mcp_startup_config_test (11). The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope

Second review wave covered every source module under `src/mcp_stdio/` and `src/scripting/`, their local CLAUDE documentation and relevant root integration tests. The root coordinator additionally transferred the FIFO notification writer in `src/llm/agent_queue.rs` and a new dedicated regression file. No GPU, model endpoint, model download, deployment, publication or commit was run.

The review inspected startup configuration, tool validation/routing, transport EOF draining, FIFO notifications, process creation and cancellation, interpreter detection, resident process ownership, script response parsing, static interpolation and syntax highlighting. Source modules were all inventoried and read at least at interface/risk points; this is not branch-complete verification of every MCP tool/protocol combination. The root coordinator runs the full native regression pass; test execution status below intentionally distinguishes completed local checks from pending coordinated checks.

### Implemented changes and evidence

#### 1. Resident request cancellation no longer leaves an unread response for the next event

Previously a resident round-trip borrowed a `ResidentIo` stored inside a mutex-protected Option. Cancelling the future released the mutex but left the interpreter alive in the registry, potentially still computing the old response. The next event could write its own request and consume the old reply as its answer.

The round-trip now takes ownership of the child and pipes from the slot for the duration of the exchange. Only a completed exchange returns them to the slot. Cancellation drops the owned child with `kill_on_drop(true)`, leaves the slot empty, and the next registry lookup replaces the dead resident. Successful responses and ordinary handler errors preserve the process and its module state as before.

Regression: `resident_cancelled_exchange_cannot_supply_the_next_events_reply`. A CPU Python script writes a local marker before sleeping; the test waits for that exact marker, cancels the first event, and demands a fresh fast event return its own identity and reset counter. The test does not sleep to guess when cancellation is safe.

#### 2. Resident event deadlines include queue wait

Previously `round_trip` awaited its IO mutex before starting the supplied timeout. A request with a 50ms budget could wait behind a 30s handler and then receive another 50ms. Error cleanup also waited for that mutex again when checking whether the resident was alive.

The new deadline is established before acquiring the mutex and reused for the exchange. A timed-out queued request returns without interrupting the event already running. Dead-process checks use try_lock; a held mutex denotes an in-flight event and cannot stretch the expired request's return time.

Regression: `resident_queue_wait_is_inside_the_events_timeout`, with a marker-confirmed slow first event and a short-budget second one. All spawned test tasks/processes are cancelled or shut down before assertions that could fail.

Independent integration review caught an extreme-budget regression in the first implementation: directly adding `Duration::MAX` to an Instant can panic. The deadline now uses checked_add and returns a descriptive error when the clock cannot represent it. `resident_extreme_timeout_is_an_error_without_panicking` exercises that rejection and then proves the next normal event still runs on an untouched resident counter.

#### 3. Invalid resident return values are errors

The Python, JavaScript and Perl harnesses printed a diagnostic for unsupported return values (such as scalar 42), then emitted `{"actions":[]}`. The caller therefore treated a failed handler as a successful intentional silence. All three now emit an error object, which the existing response parser rejects and routes into existing failure/fallback handling. Returning None/null/undefined still means an intentional empty response.

Regression: `resident_invalid_return_is_an_error_without_losing_process_state` drives actual Python, Node and Perl/JSON::PP interpreters; the first invalid return must fail, and the next valid event proves the same resident counter survives. Required runtimes are asserted, not silently skipped.

#### 4. JavaScript resident handlers can be async

The JavaScript harness now awaits `handle(...)`. Previously a Promise was classified as an unsupported object and silently converted into no actions. Rejections now enter the existing handler-error catch path; successful async responses retain their action list.

Regression: `resident_javascript_awaits_async_handlers`, whose fixture resolves a Promise and returns a known action after a short host timer. This runs Node CPU code only.

#### 5. MCP notification paths must really be FIFOs

`ensure_fifo` previously returned success for any existing path. A caller supplying a regular file could have request identifiers written over its initial bytes; a directory or symlink was also accepted despite the documented named-pipe contract. Startup now uses symlink_metadata, accepts only real FIFOs, rejects regular files/directories/symlinks with an actionable error, and preserves normal absent-path creation.

Regressions in `mcp_startup_config_test.rs`: existing files, directories and symlinks are refused while file contents remain intact; a real FIFO is created and reused successfully. Services use `--llm-agent`, so no model is contacted.

#### 6. FIFO verification survives path replacement after startup

Startup checks alone do not close the race: a FIFO pathname may later be replaced. The transferred agent queue writer now opens with `O_NONBLOCK | O_NOFOLLOW`, then checks the opened descriptor's metadata is a FIFO before writing. Checking the descriptor, rather than rechecking the pathname, prevents a rename race from redirecting the write to an ordinary file.

`tests/agent_queue_fifo_test.rs` tests replacing a configured FIFO with a file and then a symlink; neither target is modified and both requests remain queued. A real FIFO still receives the exact request id. These are local filesystem/in-memory queue tests, with no network or model.

#### 7. MCP HTTP binds IPv6 correctly and reports the actual port

The HTTP entry point previously formatted `host:port` directly, producing an invalid unbracketed address when `--listen-addr` was an IPv6 literal such as `::1`. It now passes the host and port as a tuple to Tokio and logs `listener.local_addr()`, which includes proper IPv6 formatting and the actual assigned port when zero was requested.

This edit is confined to the `mcp-http` feature branch. The coordinator must record whether that feature was compiled; no HTTP transport runtime test is claimed in this report.

#### 8. Avoid repeated highlighter resource loading

SyntaxSet and ThemeSet are now cached with OnceLock. They previously reloaded/deserialized the complete bundled syntax/theme resources for every highlighted script. Per-call HighlightLines state remains separate, preserving parser state isolation. Existing `scripting_highlight_test` is the appropriate behavioral regression; no new implementation-mirroring test was added.

#### 9. Avoid allocation in script event matching

`ScriptConfig::handles_context` now compares borrowed strings in one iterator rather than allocating `"all"` and the event type on every check. Matching semantics are unchanged; existing scripting manager tests cover dispatch selection.

#### 10. Keep documentation consistent with implemented behavior

Updated scripting documentation with cancellation ownership, queue-inclusive deadlines, async JavaScript and invalid-result behavior. Updated MCP documentation with startup/open-time FIFO checks. Removed the stale tools.rs comment claiming scheduled tasks were TUI-only even though the MCP ticker already exists.

### Validation ownership/status

- Targeted `rustfmt --edition 2021` on all edited native files: passed.
- `git diff --check`: passed at this report checkpoint.
- Root-coordinated CPU targets requested: `scripting_resident_test`, `scripting_highlight_test`, `scripting_manager_test`, `mcp_startup_config_test`, `agent_queue_fifo_test`; the final consolidated report is authoritative for compiled/tested results.
- `mcp-http` feature compile requested separately for the tuple binding change.
- The resident tests use actual lightweight interpreters, not LLMs. Existing tests in the broader resident suite contain skip-when-runtime-missing gates; the newly added runtime-dependent regressions explicitly fail if their required interpreter is absent.
- No source-level success is presented as a passed runtime test. No model fallback was invoked to validate failure paths.

### Deferred, substantive findings

1. **Interpreter probe timeout does not cover every pipe-drain scenario.** environment.rs polls child exit before draining stdout/stderr. A verbose fake --version command can fill a pipe and be killed as unavailable; a child that exits while a descendant keeps a pipe open can make wait_with_output block after the nominal deadline. A robust concurrent/bounded collection helper deserves dedicated child/descendant fixtures.
2. **Script output is unbounded.** Per-event stdout/stderr use read_to_end, resident stdout uses read_line, resident stderr uses lines. A noisy trusted script can consume substantial memory inside the timeout. Limits need an explicit compatibility decision and tests for data exceeding the chosen bounds; no arbitrary output ceiling was added during stabilization.
3. **Only immediate interpreter children are killed.** Scripts remain deliberately trusted and unsandboxed. Descendant process-group cleanup and OS resource limits are separate design changes; cancellation fixes do not claim to sandbox scripts or reap all descendants.
4. **Go temporary scripts are predictable and cancellation cleanup is incomplete.** The pid+sequence filename avoids same-process collisions, but the write does not use exclusive creation and cleanup is only reached after the child await. A cancelled Go invocation can leave the source file. A private temp-directory RAII design would address both and should be tested with a real/fake Go child.
5. **File-backed script loading is synchronous.** ScriptSource::get_code performs std::fs::read_to_string before async execution deadlines. A special file or very slow filesystem can block the caller; the FilePath trust model and async loading/bounds need a deliberate change.
6. **MCP background tasks intentionally outlive service objects.** Reaper and task-ticker handles are detached and capture AppState. This fits process-lifetime CLI use but can retain state in repeated in-process embeddings/tests; a shared-state cancellation lifecycle could improve that use case.
7. **Static interpolation recurses through JSON and can expand data.** Parsing already imposes serde nesting limits for normal input, but programmatically constructed values and repeated whole-event interpolation can grow output significantly. No global interpolation byte/node budget exists.
8. **Script entry-point detection is heuristic.** defines_handle strips # comments in every language and searches string snippets rather than parsing code; strings/comments/unusual formatting can confuse it. No parser rewrite was attempted.
9. **MCP control validation is action-name validation.** check_action_types ensures offered action names, while parameter semantics remain the protocol executor's job. This is the documented boundary; no new universal schema checker was invented.
10. **FIFO parent-directory trust is unchanged.** O_NOFOLLOW protects the final component and fstat protects the written descriptor's type. This does not promise secure traversal of attacker-controlled parent directories or ownership authentication of another FIFO; the configured path remains trusted local configuration.

### Source coverage inventory

- `src/mcp_stdio/mod.rs`: STDIO/HTTP transport lifecycle and binding (edited HTTP bind).
- `src/mcp_stdio/tools.rs`: parameter deserialization, startup configuration, queue/FIFO setup, reaper/ticker and tool dispatch (edited FIFO setup/comment).
- `src/mcp_stdio/control.rs`: vocabulary unions, action-name validation, intercept ownership and outcome descriptions (reviewed; no change).
- `src/mcp_stdio/docs.rs`: registry-derived MCP docs, startup/action/event descriptions and parameter schemas (interface/risk review; no change).
- `src/mcp_stdio/drain.rs`: outstanding request registration, Notify ordering, send result removal and one EOF drain deadline (reviewed; no change).
- `src/scripting/mod.rs`: module/export inventory (reviewed; no change).
- `src/scripting/types.rs`: source loading, event routing, context schemas and response parse shapes (allocation fix).
- `src/scripting/manager.rs`: selection, mode/runtime construction and error fallback routing (reviewed; no change).
- `src/scripting/event_handler.rs`: handler configuration/validation, event matching, reference finding/path walking and recursive interpolation (reviewed; no change).
- `src/scripting/environment.rs`: cached interpreter detection, spawn/poll/deadline/output collection (reviewed; deferred pipe collection flaw).
- `src/scripting/executor.rs`: async subprocess IO, timeout, kill/reap, language wrappers and Go file lifecycle (reviewed; deferred bounds/temp cleanup).
- `src/scripting/resident.rs`: scope keys, process ownership, queue/exchange deadlines, registry cleanup, all three harnesses (edited as described).
- `src/scripting/highlight.rs`: bundled syntax/theme loading and per-call parsing (cached resources).
- `src/llm/agent_queue.rs`: transferred FIFO notification write boundary only (open flags and descriptor validation).

Native integration test changes are in `tests/scripting_resident_test.rs`, `tests/mcp_startup_config_test.rs` and new `tests/agent_queue_fifo_test.rs`.

<a id="infrastructure"></a>
## Test infrastructure, examples, prompts, schema and vendor review — 2026-10-01

**Coordinator completion note:** test_infrastructure_review_test passed 12 executions including shared helper tests; build-script fixtures passed five. Formatting, reachability and source ratchets passed as described above. The section below preserves its original review checkpoint wording; any pending-validation statement refers to that earlier checkpoint, and the consolidated validation table above is authoritative.


### Scope and constraints

167 files inventoried, including helper libraries, evaluation framework, live-model suite definitions, examples, prompt templates, etcd protobufs and vendored hyper. Every file participated in the text/inventory sweep; focused manual review covered helper mode selection, deadlines, process management, examples, eval probe lifecycle and the local vendor patch. This is a static audit, not a claim of full execution or equal manual depth across upstream vendor code.

No GPU/model workloads, model availability probes, live protocol suites, package installation or external peer sessions were run. Root owns Cargo verification. The new regression target is explicitly CPU-only.

### Changes implemented

| File(s) | Defect | Improvement | Evidence |
|---|---|---|---|
| `tests/helpers/common.rs`, `netget.rs`, `llm_live.rs` | Presence of `NETGET_USE_OLLAMA` selected real inference, including empty string,0,false. | Shared opt-in parser accepts1,true,yes,on (case-insensitive, trimmed); everything else stays off. | Pure regression covers unset,empty,negative choices,typo and affirmative values; no environment mutation. |
| `tests/helpers/common.rs` | Binary resolver checked Cargo executable location only at runtime; Cargo typically supplies it at compile time, allowing fallback to an unrelated newer debug/release binary. | Use `option_env!("CARGO_BIN_EXE_netget")` before manual fallback; keep explicit runtime override. Missing Cargo-built binary produces a clear error. | Regression compares selected executable to Cargo compile-time path. |
| `tests/helpers/common.rs` | Retry total timeout did not bound a single pending condition or a long backoff sleep. Duration multiplication could overflow. | Bound each attempt by remaining total time, clamp sleep to remaining time and double delay with checked arithmetic. | Pending future,20-second requested sleep against30ms budget, and transient-failure recovery tests. |
| `examples/external_protocol/src/lib.rs` | Example implemented common methods on Server although they belong to Protocol; used legacy metadata and omitted required fields/methods. Spawned untracked listener/peer tasks. | Implement current Protocol and Server traits, ProtocolMetadataV2, startup examples,group and log_template; register all server tasks with AppState; label Experimental; return on listener failure. | Root regression includes this exact source,checks action encoding/startup shape,and performs loopback echo followed by server removal and peer EOF. |
| `examples/external_protocol/Cargo.toml` | Example inherited the entire default protocol dependency tree. | Disable NetGet default features for its public-API demonstration. | Standalone manifest check delegated to root; root source inclusion checks API compatibility. |
| `examples/external_protocol/README.md` | Advertised nonexistent script paths,obsolete traits/maturity states,dynamic loading,and a dependency cycle. | Document actual embedding API,current root commands,deterministic behavior,registration requirements and limitations. | Cross-read with source/current traits. |
| `examples/test_doc_gen.rs` | Doc/template errors printed but process still exited successfully. | Return anyhow::Result and propagate failures through main. | Compile-check delegated to root; no model call required. |

### New regression target

`tests/test_infrastructure_review_test.rs`:7 CPU-only tests. Five cover shared helper selection/deadlines; two compile the actual external example and check its action/lifecycle behavior. The loopback echo test constructs an OllamaClient only because SpawnContext requires one; neither echo implementation nor test calls it.

Suggested centralized verification (force live-model variables absent):

```sh
env -u NETGET_USE_OLLAMA -u NETGET_LLM_TEST_MODEL -u OLLAMA_MODEL \
  ./cargo-isolated.sh test --offline --no-default-features --features tcp,http \
  --test test_infrastructure_review_test -- --test-threads=100
./cargo-isolated.sh check --offline --manifest-path examples/external_protocol/Cargo.toml
```

No result is asserted here until the root agent finishes those commands. Formatting and `git diff --check` were run locally.

### Static validation and useful findings

- All43 `.rs` suite files other than `mod.rs` in `tests/llm_live` are declared in its module tree; no orphan suite file found. Live entry points use the shared gating framework. No live case was executed.
- Compared every retained vendored hyper file to the locally cached crates.io hyper1.7.0 source. Differences are **only** `Cargo.toml`, `README.md`, `src/common/date.rs`, matching the documented wasm Date.now patch. Native code is preserved. No upstream vendor code was changed.
- Read the etcd KV service/message schema surface and field numbering,including recursive transaction request/response oneofs and Compare range_end tag64; no schema edits proposed without service wire interoperability evidence.
- Read prompt template inventory and network-request composition. The network-request path intentionally omits setup-only scripting instructions; no prompt-quality change was made based on static intuition without evaluation evidence.
- The sample external crate is intentionally not runtime loaded. It is a deterministic echo tutorial, not a complete LLM event protocol; advertised encoder behavior and listener behavior are described separately in its README.

### Remaining findings / boundaries

1. Eval probe writes all stdin before starting its output-read loop and before enforcing the main deadline. A child that never reads stdin,or fills stdout while waiting for input,can stall the harness. A complete fix should drive input/output concurrently and preserve hold_stdin semantics,with subprocess regressions; no live model needed.
2. Eval probe output buffers and its final drain are time-limited but not byte-limited. A chatty child can allocate heavily before a deadline. Choosing a retention cap needs explicit truncated-output reporting so scoring never mistakes truncated output for a model error.
3. Eval probe binary_available tests is_file rather than executability,and PATH parsing uses Unix colon splitting. Cross-platform process discovery can give misleading availability diagnoses.
4. Live real-model tests intentionally skip without affirmative opt-in and are evaluation tools rather than protocol-regression evidence. The gate fix reduces accidental opt-in; it does not imply all tests in the repository are CPU-safe if .with_ollama() is explicitly invoked.
5. get_available_port/replace_port_placeholders still bind then drop reservations,creating a race; fixing centrally requires keeping guards alive through process startup or using actual port0 bound-address discovery.
6. Helpers have historical docs and timing heuristics that remain broader than this targeted pass. Existing test readiness/mocked expectations must be revalidated before broad timing changes.
7. The vendor comparison establishes local patch scope,not upstream security currency or absence of vulnerabilities. No dependency upgrade was attempted.
8. Proto schemas were inspected statically; no live etcd peer or protoc compatibility job was run by this reviewer.
9. Prompt and live-suite coverage is a definitions/documentation review; no claim about model quality or reproducibility can be inferred without live evaluation,which the user expressly excluded.

### Coverage ledger

| Area | Files | Lines | Review depth |
|---|---:|---:|---|
| `tests/helpers` | 23 | 13537 | Focused: mode selection,binary resolution,retries,child ownership;remaining files static sweep |
| `tests/eval` | 9 | 5880 | Focused static: probe process I/O,classification/reporting contracts;no live runs |
| `tests/llm_live` | 44 | 14130 | Suite/module inventory,gate and framework review;no live runs |
| `examples` | 6 | 10107 | Focused source/API/documentation modernization |
| `prompts` | 18 | 1050 | Template composition and placeholder inventory;no model-quality claims |
| `proto` | 2 | 301 | Static service/message/tag review |
| `vendor` | 65 | 21553 | All-file local upstream comparison plus focused wasm date patch review |

### File inventory

| File | Lines | SHA-256 prefix |
|---|---:|---|
| `examples/external_protocol/.gitignore` | 1 | `34a04005bcaf` |
| `examples/external_protocol/Cargo.lock` | 9836 | `e30a362c24ad` |
| `examples/external_protocol/Cargo.toml` | 18 | `d96f012d01b8` |
| `examples/external_protocol/README.md` | 41 | `c50454cfd886` |
| `examples/external_protocol/src/lib.rs` | 151 | `831606aa5e48` |
| `examples/test_doc_gen.rs` | 60 | `3a0ce3adaf1b` |
| `prompts/easy_request/http.hbs` | 64 | `32db1be51985` |
| `prompts/easy_request/main.hbs` | 34 | `e029dd50ac7e` |
| `prompts/feedback/main.hbs` | 11 | `57c0fb1ef1f4` |
| `prompts/feedback/partials/instructions.hbs` | 42 | `b632a63ced5a` |
| `prompts/feedback/task.hbs` | 4 | `4bb4039325d5` |
| `prompts/network_request/main.hbs` | 46 | `fa8db5c2e467` |
| `prompts/network_request/partials/instructions.hbs` | 29 | `6ecf38ea777a` |
| `prompts/network_request/task.hbs` | 5 | `fdeea8fc5b6d` |
| `prompts/shared/partials/actions.hbs` | 62 | `a6f80597513b` |
| `prompts/shared/partials/base_stack_docs.hbs` | 4 | `76fbf0fad404` |
| `prompts/shared/partials/current_state.hbs` | 36 | `03f333d7d8cc` |
| `prompts/shared/partials/memory.hbs` | 12 | `7d6cd52a9f59` |
| `prompts/shared/partials/response_format.hbs` | 133 | `71702088e85c` |
| `prompts/shared/partials/role.hbs` | 3 | `720c396dce46` |
| `prompts/shared/partials/scripting.hbs` | 425 | `5cf462abe95c` |
| `prompts/user_input/main.hbs` | 27 | `e4408209edc9` |
| `prompts/user_input/partials/instructions.hbs` | 82 | `e1fee7914862` |
| `prompts/user_input/task.hbs` | 31 | `3da902cb5d3d` |
| `proto/etcd/kv.proto` | 41 | `fb2ff44e5f4b` |
| `proto/etcd/rpc.proto` | 260 | `c5918aff3cd2` |
| `tests/eval/CLAUDE.md` | 294 | `02d3b6223e37` |
| `tests/eval/case.rs` | 306 | `e7b28d9900da` |
| `tests/eval/classify.rs` | 682 | `5d4d18d3e152` |
| `tests/eval/mod.rs` | 53 | `5bd2d3a43eaa` |
| `tests/eval/probe.rs` | 270 | `7365c9411f21` |
| `tests/eval/probe_check.rs` | 1085 | `caee8982007c` |
| `tests/eval/report.rs` | 579 | `0ab222495ff9` |
| `tests/eval/runner.rs` | 556 | `be4314d9f82d` |
| `tests/eval/suites.rs` | 2055 | `7e5f6d3b2c73` |
| `tests/helpers/child_guard.rs` | 384 | `f1899c8c99bd` |
| `tests/helpers/client.rs` | 524 | `46e9417802f4` |
| `tests/helpers/common.rs` | 527 | `2d16c238fe6b` |
| `tests/helpers/event_trigger.rs` | 339 | `efcc9ec23d5c` |
| `tests/helpers/example_test_framework.rs` | 412 | `e067159c4777` |
| `tests/helpers/http_bounds.rs` | 665 | `147e2b061557` |
| `tests/helpers/inbound_limit.rs` | 281 | `78a7568496d8` |
| `tests/helpers/llm_live.rs` | 691 | `16a2642915aa` |
| `tests/helpers/llm_live_case.rs` | 465 | `236311b4d214` |
| `tests/helpers/mock.rs` | 3 | `2c118103f78d` |
| `tests/helpers/mock_action_names.rs` | 148 | `d43a408e95ca` |
| `tests/helpers/mock_builder.rs` | 380 | `d4f5fc6e771d` |
| `tests/helpers/mock_config.rs` | 762 | `f3cc62297d92` |
| `tests/helpers/mock_matcher.rs` | 402 | `19175ac399bb` |
| `tests/helpers/mock_ollama.rs` | 1307 | `8e75aec6c0d5` |
| `tests/helpers/mod.rs` | 40 | `1c734c61e663` |
| `tests/helpers/netget.rs` | 1449 | `ee4a39303dec` |
| `tests/helpers/ollama_test_builder.rs` | 1208 | `eee9466080e1` |
| `tests/helpers/pcap_oracle.rs` | 1147 | `08b0d2be18b4` |
| `tests/helpers/real_server.rs` | 764 | `de894b2c692a` |
| `tests/helpers/server.rs` | 705 | `2d681bb18986` |
| `tests/helpers/usbip_bounds.rs` | 290 | `a3597d2afbed` |
| `tests/helpers/usbip_client.rs` | 644 | `da0a7bc11fc4` |
| `tests/llm_live/CLAUDE.md` | 138 | `7950faf9c920` |
| `tests/llm_live/bigdata.rs` | 631 | `e6f93fbaab2e` |
| `tests/llm_live/ble_profiles.rs` | 584 | `cfe39477d11c` |
| `tests/llm_live/bluetooth_ble.rs` | 268 | `9707e949c318` |
| `tests/llm_live/couchdb.rs` | 180 | `d550fbf33f50` |
| `tests/llm_live/datastores.rs` | 1156 | `e3bfa6048d89` |
| `tests/llm_live/dns.rs` | 92 | `9decd1559aa8` |
| `tests/llm_live/dns_secure.rs` | 208 | `7854a91511f2` |
| `tests/llm_live/elasticsearch.rs` | 144 | `9a779383276f` |
| `tests/llm_live/federation.rs` | 357 | `b376041ac22e` |
| `tests/llm_live/ftp.rs` | 49 | `2f573bad5dea` |
| `tests/llm_live/http.rs` | 164 | `dfb30a40f050` |
| `tests/llm_live/http_apis.rs` | 1843 | `bc17dac7bf4c` |
| `tests/llm_live/imap.rs` | 138 | `7879661ae1b3` |
| `tests/llm_live/irc.rs` | 131 | `1fd877990081` |
| `tests/llm_live/jsonrpc.rs` | 74 | `86f8a4573652` |
| `tests/llm_live/memcached.rs` | 53 | `22f6f6ccb4ea` |
| `tests/llm_live/mod.rs` | 94 | `f77f7a4bdba2` |
| `tests/llm_live/netservices.rs` | 921 | `07e6e335a463` |
| `tests/llm_live/nfc.rs` | 216 | `964d11892438` |
| `tests/llm_live/nntp.rs` | 144 | `462c762ac53b` |
| `tests/llm_live/ntp.rs` | 74 | `c0f054c28624` |
| `tests/llm_live/openai.rs` | 217 | `9b4a4a4fcbcd` |
| `tests/llm_live/p2p.rs` | 503 | `c2f3f49c8d25` |
| `tests/llm_live/pop3.rs` | 50 | `8ec89234adde` |
| `tests/llm_live/rawnet.rs` | 245 | `0d8c0ba93908` |
| `tests/llm_live/realtime.rs` | 627 | `ba139d3eb258` |
| `tests/llm_live/redis.rs` | 109 | `3fdda1656a94` |
| `tests/llm_live/remote_access.rs` | 475 | `18a11b1219e7` |
| `tests/llm_live/routing.rs` | 558 | `594879721fe1` |
| `tests/llm_live/rss.rs` | 50 | `87e1c329cfb2` |
| `tests/llm_live/rtsp.rs` | 409 | `239005917110` |
| `tests/llm_live/sip.rs` | 370 | `03358366cfac` |
| `tests/llm_live/smtp.rs` | 56 | `b6021af5950d` |
| `tests/llm_live/socks5.rs` | 184 | `23cac975e30f` |
| `tests/llm_live/streams.rs` | 1153 | `0f82c652d81d` |
| `tests/llm_live/stun.rs` | 84 | `44f803aa1a28` |
| `tests/llm_live/tcp.rs` | 136 | `2fd3b2ed4feb` |
| `tests/llm_live/telnet.rs` | 140 | `dbd6e5009aad` |
| `tests/llm_live/udp.rs` | 69 | `7dbf03071605` |
| `tests/llm_live/usb.rs` | 636 | `a0fe0af8b49a` |
| `tests/llm_live/vpn.rs` | 207 | `3753724a1ce2` |
| `tests/llm_live/whois.rs` | 51 | `4bea51de5948` |
| `tests/llm_live/xmlrpc.rs` | 142 | `a061ffbf6d40` |
| `vendor/hyper/Cargo.toml` | 263 | `893c7bae9528` |
| `vendor/hyper/LICENSE` | 19 | `8f2eee700f56` |
| `vendor/hyper/README.md` | 118 | `60ec18cc4119` |
| `vendor/hyper/src/body/incoming.rs` | 628 | `c472cf4f29f9` |
| `vendor/hyper/src/body/length.rs` | 129 | `fcf245cd9d46` |
| `vendor/hyper/src/body/mod.rs` | 50 | `6e029d258d08` |
| `vendor/hyper/src/cfg.rs` | 44 | `de5fee5bba45` |
| `vendor/hyper/src/client/conn/http1.rs` | 611 | `7f5b1ebf50dd` |
| `vendor/hyper/src/client/conn/http2.rs` | 718 | `fac786e1348c` |
| `vendor/hyper/src/client/conn/mod.rs` | 22 | `9a3a11f287ac` |
| `vendor/hyper/src/client/dispatch.rs` | 523 | `2b660505c780` |
| `vendor/hyper/src/client/mod.rs` | 22 | `3428a487d81d` |
| `vendor/hyper/src/client/tests.rs` | 261 | `de0001609ef0` |
| `vendor/hyper/src/common/buf.rs` | 150 | `6ffe7941d14e` |
| `vendor/hyper/src/common/date.rs` | 157 | `947b43820a22` |
| `vendor/hyper/src/common/either.rs` | 46 | `cf162a408741` |
| `vendor/hyper/src/common/future.rs` | 30 | `dbeb3a936470` |
| `vendor/hyper/src/common/io/compat.rs` | 150 | `e3e9333b8c18` |
| `vendor/hyper/src/common/io/mod.rs` | 7 | `1f9002411f8a` |
| `vendor/hyper/src/common/io/rewind.rs` | 162 | `2a3f3d7d1ade` |
| `vendor/hyper/src/common/mod.rs` | 21 | `cf2ef9e25cde` |
| `vendor/hyper/src/common/task.rs` | 45 | `9d027a9c9c65` |
| `vendor/hyper/src/common/time.rs` | 79 | `6073390d9395` |
| `vendor/hyper/src/common/watch.rs` | 73 | `0530dbb42bdd` |
| `vendor/hyper/src/error.rs` | 679 | `ded435e7d5ea` |
| `vendor/hyper/src/ext/h1_reason_phrase.rs` | 221 | `296ecdcb206e` |
| `vendor/hyper/src/ext/informational.rs` | 86 | `83a9b2a9cd70` |
| `vendor/hyper/src/ext/mod.rs` | 295 | `5ecbf5bf2900` |
| `vendor/hyper/src/ffi/body.rs` | 302 | `614955cfca93` |
| `vendor/hyper/src/ffi/client.rs` | 274 | `f3e7b519d972` |
| `vendor/hyper/src/ffi/error.rs` | 96 | `dd269cd749cf` |
| `vendor/hyper/src/ffi/http_types.rs` | 703 | `a1addfbd00ec` |
| `vendor/hyper/src/ffi/io.rs` | 198 | `94455b259bdb` |
| `vendor/hyper/src/ffi/macros.rs` | 53 | `8e1fe5824429` |
| `vendor/hyper/src/ffi/mod.rs` | 99 | `80639b0ff428` |
| `vendor/hyper/src/ffi/task.rs` | 549 | `feb1a51ed32b` |
| `vendor/hyper/src/headers.rs` | 159 | `43305ee388d5` |
| `vendor/hyper/src/lib.rs` | 139 | `a3405c478bc3` |
| `vendor/hyper/src/mock.rs` | 235 | `8b455312be74` |
| `vendor/hyper/src/proto/h1/conn.rs` | 1530 | `c8ad31c4039a` |
| `vendor/hyper/src/proto/h1/decode.rs` | 1236 | `cea41a3b77ce` |
| `vendor/hyper/src/proto/h1/dispatch.rs` | 808 | `073a2bf94418` |
| `vendor/hyper/src/proto/h1/encode.rs` | 660 | `0ec088e6d766` |
| `vendor/hyper/src/proto/h1/io.rs` | 967 | `d83c99b59dc2` |
| `vendor/hyper/src/proto/h1/mod.rs` | 113 | `179bbde1399e` |
| `vendor/hyper/src/proto/h1/role.rs` | 3098 | `210ad28ef2e3` |
| `vendor/hyper/src/proto/h2/client.rs` | 746 | `1112af53bdb5` |
| `vendor/hyper/src/proto/h2/mod.rs` | 446 | `1791ddbf5599` |
| `vendor/hyper/src/proto/h2/ping.rs` | 510 | `180dfd283127` |
| `vendor/hyper/src/proto/h2/server.rs` | 545 | `7cdf48b9b873` |
| `vendor/hyper/src/proto/mod.rs` | 73 | `075880551f7a` |
| `vendor/hyper/src/rt/bounds.rs` | 109 | `3c75b9039a57` |
| `vendor/hyper/src/rt/io.rs` | 405 | `096573f6f586` |
| `vendor/hyper/src/rt/mod.rs` | 48 | `db927b56ddc6` |
| `vendor/hyper/src/rt/timer.rs` | 127 | `14e28bb4f46d` |
| `vendor/hyper/src/server/conn/http1.rs` | 551 | `f040ce86f0ea` |
| `vendor/hyper/src/server/conn/http2.rs` | 312 | `6bebea3f057d` |
| `vendor/hyper/src/server/conn/mod.rs` | 20 | `b2393dc0d68c` |
| `vendor/hyper/src/server/mod.rs` | 9 | `ffe7729eba25` |
| `vendor/hyper/src/service/http.rs` | 65 | `74b6a556f77b` |
| `vendor/hyper/src/service/mod.rs` | 30 | `de143e994e00` |
| `vendor/hyper/src/service/service.rs` | 112 | `ad742e754791` |
| `vendor/hyper/src/service/util.rs` | 82 | `7d2fcf870172` |
| `vendor/hyper/src/trace.rs` | 128 | `a766c472433c` |
| `vendor/hyper/src/upgrade.rs` | 407 | `02107e8607fa` |

<a id="inventory"></a>
## Complete tracked-file inventory

Every tracked path at the inventory checkpoint appears below. Ownership labels identify section assignment, **not a promise of equal-depth manual review**. `root` includes shared core/build/CI plus the test-infrastructure second wave; second-wave agent identities and inventory group names differ. New files from this batch are listed in the changed-file ledger above. Binary/undecodable files may have no text line count. The machine-readable inventory also contains byte counts and checkpoint hashes.

| Tracked path | Assigned section | Text lines at checkpoint |
|---|---|---:|
| `.cargo/config.toml` | root | 45 |
| `.claude/settings.json` | root | 26 |
| `.github/scripts/check-module-reachability.sh` | root | 140 |
| `.github/unreachable-modules.txt` | root | 30 |
| `.github/workflows/ci.yml` | root | 1397 |
| `.github/workflows/fuzz.yml` | root | 151 |
| `.github/workflows/nightly-eval.yml` | root | 131 |
| `.github/workflows/nightly-soak.yml` | root | 115 |
| `.github/workflows/release.yml` | root | 181 |
| `.gitignore` | root | 49 |
| `.idea/.gitignore` | root | 8 |
| `.idea/modules.xml` | root | 8 |
| `.idea/netget.iml` | root | 17 |
| `.idea/vcs.xml` | root | 6 |
| `.mcp.json.example` | root | 18 |
| `ARCHITECTURE.md` | root | 639 |
| `CLAUDE.md` | root | 2352 |
| `CLIENT_PROTOCOL_FEASIBILITY.md` | root | 2894 |
| `Cargo.lock` | root | 17754 |
| `Cargo.toml` | root | 1282 |
| `EVAL_RESULTS.md` | root | 872 |
| `IMPROVEMENTS.md` | root | 1587 |
| `LICENSE` | root | 661 |
| `LICENSE_ANALYSIS.md` | root | 193 |
| `METADATA_EXAMPLES.md` | root | 587 |
| `PROTOCOL_MIGRATION_GUIDE.md` | root | 672 |
| `PROTOCOL_QUALITY.md` | root | 1626 |
| `PROTOCOL_ROADMAP.md` | root | 850 |
| `README.md` | root | 644 |
| `SYSTEM_DEPENDENCIES_macOS.md` | root | 236 |
| `TERMUX_INSTALL.md` | root | 669 |
| `am_i_claude_code_for_web.sh` | root | 83 |
| `build-termux.sh` | root | 339 |
| `build.rs` | root | 15 |
| `cargo-isolated-kill.sh` | root | 64 |
| `cargo-isolated.sh` | root | 77 |
| `cargo.sh` | root | 148 |
| `crates/netget-crossterm-wasm/Cargo.toml` | surfaces_review | 17 |
| `crates/netget-crossterm-wasm/src/lib.rs` | surfaces_review | 406 |
| `crates/netget-tokio-wasm/Cargo.toml` | surfaces_review | 30 |
| `crates/netget-tokio-wasm/src/fs.rs` | surfaces_review | 142 |
| `crates/netget-tokio-wasm/src/lib.rs` | surfaces_review | 39 |
| `crates/netget-tokio-wasm/src/net.rs` | surfaces_review | 816 |
| `crates/netget-tokio-wasm/src/process.rs` | surfaces_review | 189 |
| `crates/netget-tokio-wasm/src/runtime.rs` | surfaces_review | 128 |
| `crates/netget-tokio-wasm/src/signal.rs` | surfaces_review | 8 |
| `crates/netget-tokio-wasm/src/task.rs` | surfaces_review | 186 |
| `crates/netget-tokio-wasm/src/time.rs` | surfaces_review | 348 |
| `crates/netget-tokio-wasm/tests/tcp_peek_test.rs` | surfaces_review | 185 |
| `crates/netget-web/Cargo.toml` | surfaces_review | 102 |
| `crates/netget-web/src/backend.rs` | surfaces_review | 219 |
| `crates/netget-web/src/input.rs` | surfaces_review | 157 |
| `crates/netget-web/src/lib.rs` | surfaces_review | 819 |
| `docs/CLAUDE_CODE_WEB_LIMITATIONS.md` | root | 383 |
| `docs/E2E_EXAMPLE_TESTS_PLAN.md` | root | 337 |
| `docs/EMBEDDED_LLM_PLAN.md` | root | 1061 |
| `docs/MYSQL_TOOL_CALL_TESTS.md` | root | 541 |
| `docs/README_SSH_AGENT.md` | root | 232 |
| `docs/SSH_AGENT_IMPLEMENTATION_STRATEGY.md` | root | 474 |
| `docs/SSH_AGENT_PROTOCOL_RESEARCH.md` | root | 688 |
| `docs/SSH_AGENT_QUICK_REFERENCE.md` | root | 240 |
| `docs/TESTING_WITH_MOCKS.md` | root | 642 |
| `docs/TOOL_CALLS.md` | root | 460 |
| `docs/TOOL_CALLS_QUICKSTART.md` | root | 217 |
| `docs/WEB_SEARCH_INTEGRATION_TESTS.md` | root | 312 |
| `docs/agent-enhancement/README.md` | root | 170 |
| `docs/agent-enhancement/implementation-guide.md` | root | 490 |
| `docs/agent-enhancement/phase-1-conversation-history.md` | root | 351 |
| `docs/agent-enhancement/phase-2-prompt-template-system.md` | root | 459 |
| `docs/agent-enhancement/phase-3-event-instructions.md` | root | 442 |
| `docs/agent-enhancement/phase-5-test-framework.md` | root | 561 |
| `docs/archive/ANDROID_NATIVE_PLAN.md` | root | 374 |
| `docs/archive/CLIENT_IMPLEMENTATION_PLAN.md` | root | 1283 |
| `docs/archive/COLOR_SCHEME.md` | root | 170 |
| `docs/archive/INTERFACE_PROTOCOL_ARCHITECTURE.md` | root | 1483 |
| `docs/archive/MACOS_SUPPORT.md` | root | 358 |
| `docs/archive/MOCK_IMPLEMENTATION_GUIDE.md` | root | 273 |
| `docs/archive/ORACLE_PROTOCOL_PLAN.md` | root | 1784 |
| `docs/archive/README.md` | root | 8 |
| `docs/archive/TEST_MODELS_README.md` | root | 312 |
| `docs/archive/USB_PROTOCOL_ROADMAP.md` | root | 549 |
| `docs/chain_of_thought_plan.md` | root | 540 |
| `docs/sccache/README.md` | root | 91 |
| `docs/sccache/SCCACHE_QUICKSTART.md` | root | 363 |
| `docs/sccache/SCCACHE_REMOTE_EXPLORATION.md` | root | 350 |
| `eval-results/latest.json` | root | 8793 |
| `examples/external_protocol/.gitignore` | root | 1 |
| `examples/external_protocol/Cargo.lock` | root | 9836 |
| `examples/external_protocol/Cargo.toml` | root | 18 |
| `examples/external_protocol/README.md` | root | 135 |
| `examples/external_protocol/src/lib.rs` | root | 180 |
| `examples/test_doc_gen.rs` | root | 59 |
| `fuzz/.gitignore` | root | 30 |
| `fuzz/Cargo.toml` | root | 298 |
| `fuzz/README.md` | root | 278 |
| `fuzz/corpus/amqp_field_table/client_properties` | root | 1 |
| `fuzz/corpus/amqp_field_table/depth_bomb` | root | — |
| `fuzz/corpus/amqp_field_table/empty` | root | 1 |
| `fuzz/corpus/amqp_field_table/nested_table` | root | 1 |
| `fuzz/corpus/bencode_structure/at_depth_limit` | root | 1 |
| `fuzz/corpus/bencode_structure/depth_bomb` | root | 1 |
| `fuzz/corpus/bencode_structure/empty_string` | root | 1 |
| `fuzz/corpus/bencode_structure/int` | root | 1 |
| `fuzz/corpus/bencode_structure/krpc_find_node` | root | 1 |
| `fuzz/corpus/bencode_structure/krpc_ping` | root | 1 |
| `fuzz/corpus/bencode_structure/list` | root | 1 |
| `fuzz/corpus/bencode_structure/negative_int` | root | 1 |
| `fuzz/corpus/bencode_structure/nested` | root | 1 |
| `fuzz/corpus/bgp_message/keepalive` | root | — |
| `fuzz/corpus/bgp_message/notification` | root | — |
| `fuzz/corpus/bgp_message/open` | root | — |
| `fuzz/corpus/bgp_message/update_ipv4` | root | — |
| `fuzz/corpus/bgp_message/update_max_len` | root | — |
| `fuzz/corpus/bson_document/at_depth_limit` | root | — |
| `fuzz/corpus/bson_document/code_with_scope` | root | 2 |
| `fuzz/corpus/bson_document/depth_bomb` | root | — |
| `fuzz/corpus/bson_document/every_type` | root | — |
| `fuzz/corpus/bson_document/find_with_filter` | root | 1 |
| `fuzz/corpus/bson_document/hello` | root | 1 |
| `fuzz/corpus/bson_document/huge_declared_len` | root | — |
| `fuzz/corpus/bson_document/insert_array` | root | 1 |
| `fuzz/corpus/cdp_frame/full_frame` | root | — |
| `fuzz/corpus/cdp_frame/payload` | root | — |
| `fuzz/corpus/coap_message/empty_ack` | root | 1 |
| `fuzz/corpus/coap_message/get_wellknown` | root | — |
| `fuzz/corpus/coap_message/option_delta_ext13` | root | — |
| `fuzz/corpus/coap_message/option_delta_ext14` | root | — |
| `fuzz/corpus/coap_message/post_payload` | root | — |
| `fuzz/corpus/dns_message/a_query` | root | 1 |
| `fuzz/corpus/dns_message/a_response` | root | — |
| `fuzz/corpus/dns_message/compression_pointer_loop` | root | — |
| `fuzz/corpus/gearman_packet/admin_status` | root | 1 |
| `fuzz/corpus/gearman_packet/can_do` | root | 1 |
| `fuzz/corpus/gearman_packet/echo_req` | root | 1 |
| `fuzz/corpus/gearman_packet/grab_job_all` | root | 1 |
| `fuzz/corpus/gearman_packet/huge_declared_size` | root | — |
| `fuzz/corpus/gearman_packet/nul_bomb` | root | 1 |
| `fuzz/corpus/gearman_packet/option_exceptions` | root | 2 |
| `fuzz/corpus/gearman_packet/submit_job` | root | 1 |
| `fuzz/corpus/gearman_packet/submit_job_bg` | root | 1 |
| `fuzz/corpus/gearman_packet/submit_job_high` | root | 2 |
| `fuzz/corpus/gearman_packet/work_complete_res` | root | 2 |
| `fuzz/corpus/hsrp_message/v1_hello` | root | — |
| `fuzz/corpus/hsrp_message/v2_hello` | root | — |
| `fuzz/corpus/ldap_filter/at_depth_limit` | root | — |
| `fuzz/corpus/ldap_filter/bind_simple` | root | — |
| `fuzz/corpus/ldap_filter/depth_bomb` | root | — |
| `fuzz/corpus/ldap_filter/search_and_or_not` | root | — |
| `fuzz/corpus/ldap_filter/search_equality` | root | — |
| `fuzz/corpus/ldap_filter/search_present` | root | — |
| `fuzz/corpus/ldap_filter/search_substrings` | root | — |
| `fuzz/corpus/lldp_frame/full_frame` | root | — |
| `fuzz/corpus/lldp_frame/lldpdu` | root | 3 |
| `fuzz/corpus/m3ua_message/aspup` | root | 1 |
| `fuzz/corpus/m3ua_message/data` | root | 1 |
| `fuzz/corpus/modbus_adu/byte_count_mismatch` | root | 3 |
| `fuzz/corpus/modbus_adu/declared_longer_than_sent` | root | — |
| `fuzz/corpus/modbus_adu/max_adu` | root | — |
| `fuzz/corpus/modbus_adu/not_modbus` | root | 2 |
| `fuzz/corpus/modbus_adu/over_max_adu` | root | — |
| `fuzz/corpus/modbus_adu/read_coils` | root | 1 |
| `fuzz/corpus/modbus_adu/read_coils_max` | root | — |
| `fuzz/corpus/modbus_adu/read_holding` | root | 1 |
| `fuzz/corpus/modbus_adu/read_registers_max` | root | — |
| `fuzz/corpus/modbus_adu/two_adus` | root | 1 |
| `fuzz/corpus/modbus_adu/write_coils_max` | root | — |
| `fuzz/corpus/modbus_adu/write_registers_max` | root | — |
| `fuzz/corpus/modbus_adu/write_single` | root | — |
| `fuzz/corpus/modbus_adu/zero_length` | root | 1 |
| `fuzz/corpus/nats_frame/blank_line_bomb` | root | 32769 |
| `fuzz/corpus/nats_frame/connect` | root | 1 |
| `fuzz/corpus/nats_frame/hpub` | root | 5 |
| `fuzz/corpus/nats_frame/ping` | root | 1 |
| `fuzz/corpus/nats_frame/pub` | root | 2 |
| `fuzz/corpus/nats_frame/sub` | root | 1 |
| `fuzz/corpus/nats_frame/unsub` | root | 1 |
| `fuzz/corpus/ndef_message/text_record` | root | — |
| `fuzz/corpus/ndef_message/two_records` | root | — |
| `fuzz/corpus/ndef_message/uri_record` | root | — |
| `fuzz/corpus/nfc_apdu/case1` | root | 1 |
| `fuzz/corpus/nfc_apdu/extended` | root | — |
| `fuzz/corpus/nfc_apdu/read_binary` | root | — |
| `fuzz/corpus/nfc_apdu/select_ndef` | root | — |
| `fuzz/corpus/nfs_record_guard/many_fragments` | root | — |
| `fuzz/corpus/nfs_record_guard/oversized_announce` | root | — |
| `fuzz/corpus/nfs_record_guard/single_small` | root | — |
| `fuzz/corpus/nfs_record_guard/two_fragments` | root | — |
| `fuzz/corpus/nostr_message/at_message_bound` | root | 1 |
| `fuzz/corpus/nostr_message/close` | root | 1 |
| `fuzz/corpus/nostr_message/count_unsupported` | root | 1 |
| `fuzz/corpus/nostr_message/depth_bomb` | root | 1 |
| `fuzz/corpus/nostr_message/event_contested_escapes` | root | 1 |
| `fuzz/corpus/nostr_message/event_nak` | root | 1 |
| `fuzz/corpus/nostr_message/event_tampered` | root | 1 |
| `fuzz/corpus/nostr_message/long_subscription_id` | root | 1 |
| `fuzz/corpus/nostr_message/req` | root | 1 |
| `fuzz/corpus/nostr_message/req_tags_and_times` | root | 1 |
| `fuzz/corpus/nostr_message/too_many_filters` | root | 1 |
| `fuzz/corpus/nsq_frame/auth` | root | 2 |
| `fuzz/corpus/nsq_frame/consumer_session` | root | 3 |
| `fuzz/corpus/nsq_frame/dpub` | root | 2 |
| `fuzz/corpus/nsq_frame/fin_req_touch` | root | 5 |
| `fuzz/corpus/nsq_frame/identify_depth_bomb` | root | 2 |
| `fuzz/corpus/nsq_frame/line_bomb` | root | 1 |
| `fuzz/corpus/nsq_frame/message_frame` | root | — |
| `fuzz/corpus/nsq_frame/mpub` | root | 2 |
| `fuzz/corpus/nsq_frame/mpub_count_bomb` | root | — |
| `fuzz/corpus/nsq_frame/mpub_declared_huge` | root | 2 |
| `fuzz/corpus/nsq_frame/pub` | root | 2 |
| `fuzz/corpus/nsq_frame/pub_declared_huge` | root | — |
| `fuzz/corpus/nsq_frame/pub_declared_negative` | root | — |
| `fuzz/corpus/nsq_frame/pub_one_past_the_limit` | root | 2 |
| `fuzz/corpus/nsq_frame/response_frame` | root | 1 |
| `fuzz/corpus/ntlmssp_token/authenticate_field_past_end` | root | — |
| `fuzz/corpus/ntlmssp_token/authenticate_odd_utf16` | root | — |
| `fuzz/corpus/ntlmssp_token/authenticate_oem` | root | — |
| `fuzz/corpus/ntlmssp_token/authenticate_truncated` | root | 1 |
| `fuzz/corpus/ntlmssp_token/bare_authenticate_guest` | root | — |
| `fuzz/corpus/ntlmssp_token/bare_negotiate` | root | — |
| `fuzz/corpus/ntlmssp_token/der_depth_bomb` | root | — |
| `fuzz/corpus/ntlmssp_token/kerberos_only` | root | — |
| `fuzz/corpus/ntlmssp_token/spnego_authenticate_anonymous` | root | — |
| `fuzz/corpus/ntlmssp_token/spnego_negotiate` | root | — |
| `fuzz/corpus/packstream_message/at_depth_limit` | root | — |
| `fuzz/corpus/packstream_message/begin` | root | — |
| `fuzz/corpus/packstream_message/begin_chunked` | root | — |
| `fuzz/corpus/packstream_message/bytes32_huge` | root | — |
| `fuzz/corpus/packstream_message/bytes32_huge_chunked` | root | — |
| `fuzz/corpus/packstream_message/depth_bomb` | root | — |
| `fuzz/corpus/packstream_message/depth_bomb_chunked` | root | — |
| `fuzz/corpus/packstream_message/goodbye` | root | — |
| `fuzz/corpus/packstream_message/goodbye_chunked` | root | — |
| `fuzz/corpus/packstream_message/hello` | root | — |
| `fuzz/corpus/packstream_message/hello_chunked` | root | — |
| `fuzz/corpus/packstream_message/list32_huge` | root | — |
| `fuzz/corpus/packstream_message/list32_huge_chunked` | root | — |
| `fuzz/corpus/packstream_message/logon` | root | — |
| `fuzz/corpus/packstream_message/logon_chunked` | root | — |
| `fuzz/corpus/packstream_message/map32_huge` | root | — |
| `fuzz/corpus/packstream_message/map32_huge_chunked` | root | — |
| `fuzz/corpus/packstream_message/map_depth_bomb` | root | — |
| `fuzz/corpus/packstream_message/pipelined_run_pull` | root | — |
| `fuzz/corpus/packstream_message/pull` | root | — |
| `fuzz/corpus/packstream_message/pull_chunked` | root | — |
| `fuzz/corpus/packstream_message/pull_qid` | root | — |
| `fuzz/corpus/packstream_message/pull_qid_chunked` | root | — |
| `fuzz/corpus/packstream_message/reset` | root | — |
| `fuzz/corpus/packstream_message/reset_chunked` | root | — |
| `fuzz/corpus/packstream_message/route` | root | — |
| `fuzz/corpus/packstream_message/route_chunked` | root | — |
| `fuzz/corpus/packstream_message/run` | root | — |
| `fuzz/corpus/packstream_message/run_chunked` | root | — |
| `fuzz/corpus/packstream_message/string32_huge` | root | — |
| `fuzz/corpus/packstream_message/string32_huge_chunked` | root | — |
| `fuzz/corpus/packstream_message/struct16_huge` | root | — |
| `fuzz/corpus/packstream_message/struct16_huge_chunked` | root | — |
| `fuzz/corpus/packstream_message/struct_depth_bomb` | root | — |
| `fuzz/corpus/packstream_message/unterminated_chunks` | root | — |
| `fuzz/corpus/radius_packet/access_request` | root | 8 |
| `fuzz/corpus/radius_packet/accounting_request` | root | 1 |
| `fuzz/corpus/resp_frame/at_depth_limit` | root | 33 |
| `fuzz/corpus/resp_frame/depth_bomb` | root | 65537 |
| `fuzz/corpus/resp_frame/huge_declared_bulk` | root | 2 |
| `fuzz/corpus/resp_frame/huge_declared_len` | root | 1 |
| `fuzz/corpus/resp_frame/incomplete_bulk` | root | 3 |
| `fuzz/corpus/resp_frame/ping` | root | 3 |
| `fuzz/corpus/resp_frame/pipelined` | root | 8 |
| `fuzz/corpus/resp_frame/reply_shapes` | root | 9 |
| `fuzz/corpus/resp_frame/set` | root | 7 |
| `fuzz/corpus/smb2_request/chain_length_bomb` | root | — |
| `fuzz/corpus/smb2_request/close` | root | — |
| `fuzz/corpus/smb2_request/compound_stat` | root | — |
| `fuzz/corpus/smb2_request/create_delete_on_close` | root | — |
| `fuzz/corpus/smb2_request/create_file` | root | — |
| `fuzz/corpus/smb2_request/create_name_past_end` | root | — |
| `fuzz/corpus/smb2_request/create_odd_name_len` | root | — |
| `fuzz/corpus/smb2_request/create_root` | root | — |
| `fuzz/corpus/smb2_request/echo` | root | — |
| `fuzz/corpus/smb2_request/flush` | root | — |
| `fuzz/corpus/smb2_request/logoff` | root | — |
| `fuzz/corpus/smb2_request/negotiate` | root | — |
| `fuzz/corpus/smb2_request/negotiate_dialect_count_bomb` | root | — |
| `fuzz/corpus/smb2_request/next_command_past_end` | root | — |
| `fuzz/corpus/smb2_request/next_command_short` | root | — |
| `fuzz/corpus/smb2_request/next_command_unaligned` | root | — |
| `fuzz/corpus/smb2_request/query_directory` | root | — |
| `fuzz/corpus/smb2_request/query_directory_name_past_end` | root | — |
| `fuzz/corpus/smb2_request/query_info_all` | root | — |
| `fuzz/corpus/smb2_request/query_info_fs` | root | — |
| `fuzz/corpus/smb2_request/query_info_out_len_bomb` | root | — |
| `fuzz/corpus/smb2_request/read` | root | — |
| `fuzz/corpus/smb2_request/read_length_bomb` | root | — |
| `fuzz/corpus/smb2_request/session_setup_blob_offset_past_end` | root | — |
| `fuzz/corpus/smb2_request/session_setup_blob_past_end` | root | — |
| `fuzz/corpus/smb2_request/session_setup_guest` | root | — |
| `fuzz/corpus/smb2_request/session_setup_spnego_authenticate` | root | — |
| `fuzz/corpus/smb2_request/session_setup_spnego_negotiate` | root | — |
| `fuzz/corpus/smb2_request/smb1_negotiate` | root | — |
| `fuzz/corpus/smb2_request/tree_connect` | root | — |
| `fuzz/corpus/smb2_request/tree_connect_path_past_end` | root | — |
| `fuzz/corpus/smb2_request/write` | root | — |
| `fuzz/corpus/smb2_request/write_length_bomb` | root | — |
| `fuzz/corpus/smb2_request/write_offset_bomb` | root | — |
| `fuzz/corpus/snmp_ber/at_depth_limit` | root | — |
| `fuzz/corpus/snmp_ber/depth_bomb` | root | — |
| `fuzz/corpus/snmp_ber/getrequest_private` | root | — |
| `fuzz/corpus/snmp_ber/getrequest_public` | root | — |
| `fuzz/corpus/stomp_frame/blank_line_bomb` | root | 32772 |
| `fuzz/corpus/stomp_frame/connect` | root | 5 |
| `fuzz/corpus/stomp_frame/escaped_header` | root | 5 |
| `fuzz/corpus/stomp_frame/heartbeat` | root | 1 |
| `fuzz/corpus/stomp_frame/send_no_len` | root | 4 |
| `fuzz/corpus/stomp_frame/send_with_len` | root | 5 |
| `fuzz/corpus/stomp_frame/subscribe` | root | 6 |
| `fuzz/corpus/svn_tuple/at_depth_limit` | root | 1 |
| `fuzz/corpus/svn_tuple/auth_anonymous` | root | 1 |
| `fuzz/corpus/svn_tuple/client_greeting` | root | 1 |
| `fuzz/corpus/svn_tuple/counted_string_with_newline` | root | 2 |
| `fuzz/corpus/svn_tuple/depth_bomb` | root | 1 |
| `fuzz/corpus/svn_tuple/get_dir` | root | 1 |
| `fuzz/corpus/svn_tuple/get_latest_rev` | root | 1 |
| `fuzz/corpus/svn_tuple/two_commands` | root | 1 |
| `fuzz/corpus/xmlrpc_value/at_depth_limit` | root | 1 |
| `fuzz/corpus/xmlrpc_value/depth_bomb` | root | 1 |
| `fuzz/corpus/xmlrpc_value/every_scalar` | root | 1 |
| `fuzz/corpus/xmlrpc_value/int_param` | root | 1 |
| `fuzz/corpus/xmlrpc_value/struct_and_array` | root | 1 |
| `fuzz/corpus/zabbix_packet/compressed` | root | — |
| `fuzz/corpus/zabbix_packet/depth_bomb` | root | 1 |
| `fuzz/corpus/zabbix_packet/huge_declared_large` | root | 1 |
| `fuzz/corpus/zabbix_packet/huge_declared_len` | root | — |
| `fuzz/corpus/zabbix_packet/large_header` | root | 1 |
| `fuzz/corpus/zabbix_packet/other_request` | root | 1 |
| `fuzz/corpus/zabbix_packet/response` | root | 1 |
| `fuzz/corpus/zabbix_packet/sender_batch` | root | — |
| `fuzz/corpus/zabbix_packet/sender_one_value` | root | 1 |
| `fuzz/fuzz_targets/amqp_field_table.rs` | root | 39 |
| `fuzz/fuzz_targets/bencode_structure.rs` | root | 37 |
| `fuzz/fuzz_targets/bgp_message.rs` | root | 40 |
| `fuzz/fuzz_targets/bson_document.rs` | root | 56 |
| `fuzz/fuzz_targets/cdp_frame.rs` | root | 29 |
| `fuzz/fuzz_targets/coap_message.rs` | root | 49 |
| `fuzz/fuzz_targets/dns_message.rs` | root | 44 |
| `fuzz/fuzz_targets/gearman_packet.rs` | root | 51 |
| `fuzz/fuzz_targets/hsrp_message.rs` | root | 18 |
| `fuzz/fuzz_targets/ldap_filter.rs` | root | 57 |
| `fuzz/fuzz_targets/lldp_frame.rs` | root | 20 |
| `fuzz/fuzz_targets/m3ua_message.rs` | root | 19 |
| `fuzz/fuzz_targets/modbus_adu.rs` | root | 98 |
| `fuzz/fuzz_targets/nats_frame.rs` | root | 52 |
| `fuzz/fuzz_targets/ndef_message.rs` | root | 35 |
| `fuzz/fuzz_targets/nfc_apdu.rs` | root | 15 |
| `fuzz/fuzz_targets/nfs_record_guard.rs` | root | 52 |
| `fuzz/fuzz_targets/nostr_message.rs` | root | 88 |
| `fuzz/fuzz_targets/nsq_frame.rs` | root | 73 |
| `fuzz/fuzz_targets/ntlmssp_token.rs` | root | 108 |
| `fuzz/fuzz_targets/packstream_message.rs` | root | 66 |
| `fuzz/fuzz_targets/radius_packet.rs` | root | 34 |
| `fuzz/fuzz_targets/resp_frame.rs` | root | 68 |
| `fuzz/fuzz_targets/smb2_request.rs` | root | 114 |
| `fuzz/fuzz_targets/snmp_ber.rs` | root | 31 |
| `fuzz/fuzz_targets/stomp_frame.rs` | root | 43 |
| `fuzz/fuzz_targets/svn_tuple.rs` | root | 62 |
| `fuzz/fuzz_targets/xmlrpc_value.rs` | root | 34 |
| `fuzz/fuzz_targets/zabbix_packet.rs` | root | 39 |
| `fuzz/seed_corpus.py` | root | 990 |
| `lines-of-code.sh` | root | 232 |
| `npm/netget/README.md` | surfaces_review | 49 |
| `npm/netget/bin/netget.js` | surfaces_review | 179 |
| `npm/netget/package.json` | surfaces_review | 40 |
| `prompts/easy_request/http.hbs` | root | 64 |
| `prompts/easy_request/main.hbs` | root | 34 |
| `prompts/feedback/main.hbs` | root | 11 |
| `prompts/feedback/partials/instructions.hbs` | root | 42 |
| `prompts/feedback/task.hbs` | root | 4 |
| `prompts/network_request/main.hbs` | root | 46 |
| `prompts/network_request/partials/instructions.hbs` | root | 29 |
| `prompts/network_request/task.hbs` | root | 5 |
| `prompts/shared/partials/actions.hbs` | root | 62 |
| `prompts/shared/partials/base_stack_docs.hbs` | root | 4 |
| `prompts/shared/partials/current_state.hbs` | root | 36 |
| `prompts/shared/partials/memory.hbs` | root | 12 |
| `prompts/shared/partials/response_format.hbs` | root | 133 |
| `prompts/shared/partials/role.hbs` | root | 3 |
| `prompts/shared/partials/scripting.hbs` | root | 425 |
| `prompts/user_input/main.hbs` | root | 27 |
| `prompts/user_input/partials/instructions.hbs` | root | 82 |
| `prompts/user_input/task.hbs` | root | 31 |
| `proto/etcd/kv.proto` | root | 41 |
| `proto/etcd/rpc.proto` | root | 260 |
| `run-eval.sh` | root | 234 |
| `scripts/archive/README.md` | root | 7 |
| `scripts/archive/add_is_tool_field.sh` | root | 36 |
| `scripts/archive/add_mocks_helper.py` | root | 109 |
| `scripts/archive/add_test_timeouts.py` | root | 198 |
| `scripts/archive/apply_test_timeouts.sh` | root | 150 |
| `scripts/archive/fix_all_e2e_references.sh` | root | 106 |
| `scripts/archive/fix_all_protocols.py` | root | 237 |
| `scripts/archive/fix_event_params.py` | root | 59 |
| `scripts/archive/fix_inline_action_defs.sh` | root | 35 |
| `scripts/archive/fix_param_def.py` | root | 80 |
| `scripts/archive/migrate_event_types.py` | root | 74 |
| `scripts/archive/update_test_feature_gates.sh` | root | 36 |
| `scripts/beta_evidence_table.py` | root | 842 |
| `scripts/npm/prepare-packages.mjs` | root | 137 |
| `scripts/sccache/cargo-sccache.sh` | root | 46 |
| `scripts/sccache/setup-sccache-r2.sh` | root | 88 |
| `scripts/sccache/setup-sccache-upstash.sh` | root | 78 |
| `site/CLAUDE.md` | surfaces_review | 86 |
| `site/css/demo.css` | surfaces_review | 413 |
| `site/css/style.css` | surfaces_review | 342 |
| `site/deploy.sh` | surfaces_review | 104 |
| `site/favicon.svg` | surfaces_review | 4 |
| `site/index.html` | surfaces_review | 298 |
| `site/js/composer.js` | surfaces_review | 478 |
| `site/js/demo.js` | surfaces_review | 1412 |
| `site/js/main.js` | surfaces_review | 41 |
| `site/js/thinking.js` | surfaces_review | 73 |
| `src/bin/netget.rs` | root | 45 |
| `src/cli/args.rs` | runtime_review | 935 |
| `src/cli/banner.rs` | runtime_review | 194 |
| `src/cli/client_startup.rs` | runtime_review | 426 |
| `src/cli/crash_restore.rs` | runtime_review | 92 |
| `src/cli/easy_startup.rs` | runtime_review | 164 |
| `src/cli/input_state.rs` | runtime_review | 419 |
| `src/cli/management.rs` | runtime_review | 1354 |
| `src/cli/mod.rs` | runtime_review | 780 |
| `src/cli/model_select.rs` | runtime_review | 98 |
| `src/cli/non_interactive.rs` | runtime_review | 717 |
| `src/cli/server_startup.rs` | runtime_review | 830 |
| `src/cli/setup.rs` | runtime_review | 196 |
| `src/cli/tasks.rs` | runtime_review | 429 |
| `src/cli/terminal_cleanup.rs` | runtime_review | 4 |
| `src/cli/theme.rs` | runtime_review | 253 |
| `src/client/amqp/CLAUDE.md` | client_review | 95 |
| `src/client/amqp/actions.rs` | client_review | 346 |
| `src/client/amqp/mod.rs` | client_review | 617 |
| `src/client/arp/CLAUDE.md` | client_review | 534 |
| `src/client/arp/actions.rs` | client_review | 459 |
| `src/client/arp/mod.rs` | client_review | 837 |
| `src/client/bgp/CLAUDE.md` | client_review | 196 |
| `src/client/bgp/actions.rs` | client_review | 505 |
| `src/client/bgp/mod.rs` | client_review | 1118 |
| `src/client/bitcoin/CLAUDE.md` | client_review | 364 |
| `src/client/bitcoin/actions.rs` | client_review | 634 |
| `src/client/bitcoin/mod.rs` | client_review | 667 |
| `src/client/bluetooth/CLAUDE.md` | client_review | 359 |
| `src/client/bluetooth/actions.rs` | client_review | 638 |
| `src/client/bluetooth/mod.rs` | client_review | 1190 |
| `src/client/bootp/CLAUDE.md` | client_review | 507 |
| `src/client/bootp/actions.rs` | client_review | 306 |
| `src/client/bootp/mod.rs` | client_review | 574 |
| `src/client/cassandra/CLAUDE.md` | client_review | 388 |
| `src/client/cassandra/actions.rs` | client_review | 352 |
| `src/client/cassandra/mod.rs` | client_review | 624 |
| `src/client/coap/CLAUDE.md` | client_review | 119 |
| `src/client/coap/actions.rs` | client_review | 651 |
| `src/client/coap/mod.rs` | client_review | 1021 |
| `src/client/command_support.rs` | client_review | 206 |
| `src/client/couchdb/CLAUDE.md` | client_review | 444 |
| `src/client/couchdb/actions.rs` | client_review | 662 |
| `src/client/couchdb/mod.rs` | client_review | 1793 |
| `src/client/datalink/CLAUDE.md` | client_review | 389 |
| `src/client/datalink/actions.rs` | client_review | 738 |
| `src/client/datalink/mod.rs` | client_review | 887 |
| `src/client/dc/CLAUDE.md` | client_review | 497 |
| `src/client/dc/actions.rs` | client_review | 791 |
| `src/client/dc/mod.rs` | client_review | 1930 |
| `src/client/dhcp/CLAUDE.md` | client_review | 394 |
| `src/client/dhcp/actions.rs` | client_review | 327 |
| `src/client/dhcp/mod.rs` | client_review | 807 |
| `src/client/dns/CLAUDE.md` | client_review | 405 |
| `src/client/dns/actions.rs` | client_review | 343 |
| `src/client/dns/mod.rs` | client_review | 718 |
| `src/client/doh/CLAUDE.md` | client_review | 459 |
| `src/client/doh/actions.rs` | client_review | 366 |
| `src/client/doh/mod.rs` | client_review | 757 |
| `src/client/dot/CLAUDE.md` | client_review | 333 |
| `src/client/dot/actions.rs` | client_review | 362 |
| `src/client/dot/mod.rs` | client_review | 740 |
| `src/client/dynamodb/CLAUDE.md` | client_review | 424 |
| `src/client/dynamodb/actions.rs` | client_review | 663 |
| `src/client/dynamodb/mod.rs` | client_review | 1036 |
| `src/client/elasticsearch/CLAUDE.md` | client_review | 355 |
| `src/client/elasticsearch/actions.rs` | client_review | 575 |
| `src/client/elasticsearch/mod.rs` | client_review | 1155 |
| `src/client/etcd/CLAUDE.md` | client_review | 459 |
| `src/client/etcd/actions.rs` | client_review | 375 |
| `src/client/etcd/mod.rs` | client_review | 636 |
| `src/client/finger/CLAUDE.md` | client_review | 161 |
| `src/client/finger/actions.rs` | client_review | 750 |
| `src/client/finger/mod.rs` | client_review | 874 |
| `src/client/ftp/CLAUDE.md` | client_review | 125 |
| `src/client/ftp/actions.rs` | client_review | 280 |
| `src/client/ftp/mod.rs` | client_review | 335 |
| `src/client/git/CLAUDE.md` | client_review | 487 |
| `src/client/git/actions.rs` | client_review | 802 |
| `src/client/git/mod.rs` | client_review | 1529 |
| `src/client/git/sandbox.rs` | client_review | 287 |
| `src/client/gopher/CLAUDE.md` | client_review | 229 |
| `src/client/gopher/actions.rs` | client_review | 675 |
| `src/client/gopher/mod.rs` | client_review | 960 |
| `src/client/grpc/CLAUDE.md` | client_review | 456 |
| `src/client/grpc/actions.rs` | client_review | 475 |
| `src/client/grpc/mod.rs` | client_review | 1277 |
| `src/client/http/CLAUDE.md` | client_review | 324 |
| `src/client/http/actions.rs` | client_review | 391 |
| `src/client/http/mod.rs` | client_review | 829 |
| `src/client/http2/CLAUDE.md` | client_review | 318 |
| `src/client/http2/actions.rs` | client_review | 366 |
| `src/client/http2/mod.rs` | client_review | 750 |
| `src/client/http3/CLAUDE.md` | client_review | 459 |
| `src/client/http3/actions.rs` | client_review | 426 |
| `src/client/http3/mod.rs` | client_review | 888 |
| `src/client/http_fetch/mod.rs` | client_review | 559 |
| `src/client/http_fetch/transport.rs` | client_review | 372 |
| `src/client/http_proxy/CLAUDE.md` | client_review | 216 |
| `src/client/http_proxy/actions.rs` | client_review | 516 |
| `src/client/http_proxy/mod.rs` | client_review | 791 |
| `src/client/icmp/CLAUDE.md` | client_review | 396 |
| `src/client/icmp/actions.rs` | client_review | 565 |
| `src/client/icmp/mod.rs` | client_review | 820 |
| `src/client/ident/CLAUDE.md` | client_review | 188 |
| `src/client/ident/actions.rs` | client_review | 540 |
| `src/client/ident/mod.rs` | client_review | 1020 |
| `src/client/igmp/CLAUDE.md` | client_review | 322 |
| `src/client/igmp/actions.rs` | client_review | 384 |
| `src/client/igmp/mod.rs` | client_review | 563 |
| `src/client/imap/CLAUDE.md` | client_review | 297 |
| `src/client/imap/actions.rs` | client_review | 543 |
| `src/client/imap/mod.rs` | client_review | 775 |
| `src/client/ipp/CLAUDE.md` | client_review | 219 |
| `src/client/ipp/actions.rs` | client_review | 470 |
| `src/client/ipp/mod.rs` | client_review | 902 |
| `src/client/irc/CLAUDE.md` | client_review | 250 |
| `src/client/irc/actions.rs` | client_review | 535 |
| `src/client/irc/mod.rs` | client_review | 614 |
| `src/client/isis/CLAUDE.md` | client_review | 272 |
| `src/client/isis/actions.rs` | client_review | 269 |
| `src/client/isis/mod.rs` | client_review | 501 |
| `src/client/jsonrpc/CLAUDE.md` | client_review | 395 |
| `src/client/jsonrpc/actions.rs` | client_review | 367 |
| `src/client/jsonrpc/mod.rs` | client_review | 944 |
| `src/client/kafka/CLAUDE.md` | client_review | 194 |
| `src/client/kafka/actions.rs` | client_review | 845 |
| `src/client/kafka/mod.rs` | client_review | 1404 |
| `src/client/kubernetes/CLAUDE.md` | client_review | 414 |
| `src/client/kubernetes/actions.rs` | client_review | 642 |
| `src/client/kubernetes/mod.rs` | client_review | 933 |
| `src/client/ldap/CLAUDE.md` | client_review | 288 |
| `src/client/ldap/actions.rs` | client_review | 624 |
| `src/client/ldap/mod.rs` | client_review | 824 |
| `src/client/llm_budget.rs` | client_review | 210 |
| `src/client/llmnr/CLAUDE.md` | client_review | 240 |
| `src/client/llmnr/actions.rs` | client_review | 783 |
| `src/client/llmnr/mod.rs` | client_review | 1078 |
| `src/client/maven/CLAUDE.md` | client_review | 278 |
| `src/client/maven/actions.rs` | client_review | 580 |
| `src/client/maven/mod.rs` | client_review | 1115 |
| `src/client/mcp/CLAUDE.md` | client_review | 394 |
| `src/client/mcp/actions.rs` | client_review | 445 |
| `src/client/mcp/mod.rs` | client_review | 838 |
| `src/client/mdns/CLAUDE.md` | client_review | 346 |
| `src/client/mdns/actions.rs` | client_review | 348 |
| `src/client/mdns/mod.rs` | client_review | 718 |
| `src/client/memcached/CLAUDE.md` | client_review | 107 |
| `src/client/memcached/actions.rs` | client_review | 812 |
| `src/client/memcached/mod.rs` | client_review | 556 |
| `src/client/memcached/wire.rs` | client_review | 500 |
| `src/client/mercurial/CLAUDE.md` | client_review | 1100 |
| `src/client/mod.rs` | client_review | 625 |
| `src/client/modbus/CLAUDE.md` | client_review | 106 |
| `src/client/modbus/actions.rs` | client_review | 611 |
| `src/client/modbus/mod.rs` | client_review | 621 |
| `src/client/mongodb/CLAUDE.md` | client_review | 491 |
| `src/client/mongodb/actions.rs` | client_review | 516 |
| `src/client/mongodb/mod.rs` | client_review | 759 |
| `src/client/mqtt/CLAUDE.md` | client_review | 235 |
| `src/client/mqtt/actions.rs` | client_review | 511 |
| `src/client/mqtt/mod.rs` | client_review | 751 |
| `src/client/mssql/CLAUDE.md` | client_review | 296 |
| `src/client/mssql/actions.rs` | client_review | 311 |
| `src/client/mssql/mod.rs` | client_review | 665 |
| `src/client/mysql/CLAUDE.md` | client_review | 471 |
| `src/client/mysql/actions.rs` | client_review | 393 |
| `src/client/mysql/mod.rs` | client_review | 653 |
| `src/client/nats/CLAUDE.md` | client_review | 206 |
| `src/client/nats/actions.rs` | client_review | 1109 |
| `src/client/nats/mod.rs` | client_review | 1090 |
| `src/client/netbios_ns/CLAUDE.md` | client_review | 214 |
| `src/client/netbios_ns/actions.rs` | client_review | 674 |
| `src/client/netbios_ns/mod.rs` | client_review | 933 |
| `src/client/netbios_ns/wire.rs` | client_review | 432 |
| `src/client/nfc/CLAUDE.md` | client_review | 241 |
| `src/client/nfc/actions.rs` | client_review | 689 |
| `src/client/nfc/mod.rs` | client_review | 1043 |
| `src/client/nfc/ndef.rs` | client_review | 700 |
| `src/client/nfs/CLAUDE.md` | client_review | 533 |
| `src/client/nfs/actions.rs` | client_review | 487 |
| `src/client/nfs/mod.rs` | client_review | 992 |
| `src/client/nntp/CLAUDE.md` | client_review | 232 |
| `src/client/nntp/actions.rs` | client_review | 508 |
| `src/client/nntp/mod.rs` | client_review | 643 |
| `src/client/npm/CLAUDE.md` | client_review | 441 |
| `src/client/npm/actions.rs` | client_review | 487 |
| `src/client/npm/mod.rs` | client_review | 1077 |
| `src/client/ntp/CLAUDE.md` | client_review | 275 |
| `src/client/ntp/actions.rs` | client_review | 259 |
| `src/client/ntp/mod.rs` | client_review | 543 |
| `src/client/oauth2/CLAUDE.md` | client_review | 262 |
| `src/client/oauth2/actions.rs` | client_review | 610 |
| `src/client/oauth2/mod.rs` | client_review | 1619 |
| `src/client/ollama/CLAUDE.md` | client_review | 371 |
| `src/client/ollama/actions.rs` | client_review | 459 |
| `src/client/ollama/mod.rs` | client_review | 1169 |
| `src/client/openai/CLAUDE.md` | client_review | 342 |
| `src/client/openai/actions.rs` | client_review | 493 |
| `src/client/openai/mod.rs` | client_review | 1120 |
| `src/client/openapi/CLAUDE.md` | client_review | 401 |
| `src/client/openapi/actions.rs` | client_review | 526 |
| `src/client/openapi/mod.rs` | client_review | 958 |
| `src/client/openidconnect/CLAUDE.md` | client_review | 494 |
| `src/client/openidconnect/actions.rs` | client_review | 609 |
| `src/client/openidconnect/mod.rs` | client_review | 1787 |
| `src/client/oracle/CLAUDE.md` | client_review | 917 |
| `src/client/ospf/CLAUDE.md` | client_review | 698 |
| `src/client/ospf/actions.rs` | client_review | 637 |
| `src/client/ospf/mod.rs` | client_review | 889 |
| `src/client/pop3/CLAUDE.md` | client_review | 224 |
| `src/client/pop3/actions.rs` | client_review | 294 |
| `src/client/pop3/mod.rs` | client_review | 454 |
| `src/client/postgresql/CLAUDE.md` | client_review | 288 |
| `src/client/postgresql/actions.rs` | client_review | 383 |
| `src/client/postgresql/mod.rs` | client_review | 627 |
| `src/client/pypi/CLAUDE.md` | client_review | 315 |
| `src/client/pypi/actions.rs` | client_review | 488 |
| `src/client/pypi/mod.rs` | client_review | 1039 |
| `src/client/radius/CLAUDE.md` | client_review | 112 |
| `src/client/radius/actions.rs` | client_review | 836 |
| `src/client/radius/mod.rs` | client_review | 711 |
| `src/client/radius/wire.rs` | client_review | 325 |
| `src/client/redis/CLAUDE.md` | client_review | 211 |
| `src/client/redis/actions.rs` | client_review | 315 |
| `src/client/redis/mod.rs` | client_review | 465 |
| `src/client/redis/resp.rs` | client_review | 449 |
| `src/client/rip/CLAUDE.md` | client_review | 294 |
| `src/client/rip/actions.rs` | client_review | 299 |
| `src/client/rip/mod.rs` | client_review | 672 |
| `src/client/rss/CLAUDE.md` | client_review | 120 |
| `src/client/rss/actions.rs` | client_review | 317 |
| `src/client/rss/mod.rs` | client_review | 573 |
| `src/client/s3/CLAUDE.md` | client_review | 384 |
| `src/client/s3/actions.rs` | client_review | 711 |
| `src/client/s3/mod.rs` | client_review | 897 |
| `src/client/saml/CLAUDE.md` | client_review | 293 |
| `src/client/saml/actions.rs` | client_review | 371 |
| `src/client/saml/mod.rs` | client_review | 922 |
| `src/client/sip/CLAUDE.md` | client_review | 572 |
| `src/client/sip/actions.rs` | client_review | 663 |
| `src/client/sip/mod.rs` | client_review | 980 |
| `src/client/smb/CLAUDE.md` | client_review | 389 |
| `src/client/smb/actions.rs` | client_review | 598 |
| `src/client/smb/mod.rs` | client_review | 831 |
| `src/client/smtp/CLAUDE.md` | client_review | 248 |
| `src/client/smtp/actions.rs` | client_review | 416 |
| `src/client/smtp/mod.rs` | client_review | 603 |
| `src/client/snmp/CLAUDE.md` | client_review | 493 |
| `src/client/snmp/README.md` | client_review | 109 |
| `src/client/snmp/actions.rs` | client_review | 482 |
| `src/client/snmp/mod.rs` | client_review | 1069 |
| `src/client/socket_file/CLAUDE.md` | client_review | 247 |
| `src/client/socket_file/actions.rs` | client_review | 378 |
| `src/client/socket_file/mod.rs` | client_review | 365 |
| `src/client/socks5/CLAUDE.md` | client_review | 357 |
| `src/client/socks5/actions.rs` | client_review | 471 |
| `src/client/socks5/mod.rs` | client_review | 387 |
| `src/client/sqs/CLAUDE.md` | client_review | 343 |
| `src/client/sqs/actions.rs` | client_review | 497 |
| `src/client/sqs/mod.rs` | client_review | 894 |
| `src/client/ssdp/CLAUDE.md` | client_review | 192 |
| `src/client/ssdp/actions.rs` | client_review | 790 |
| `src/client/ssdp/mod.rs` | client_review | 1029 |
| `src/client/ssh/CLAUDE.md` | client_review | 356 |
| `src/client/ssh/actions.rs` | client_review | 380 |
| `src/client/ssh/mod.rs` | client_review | 667 |
| `src/client/ssh_agent/CLAUDE.md` | client_review | 236 |
| `src/client/ssh_agent/actions.rs` | client_review | 402 |
| `src/client/ssh_agent/mod.rs` | client_review | 613 |
| `src/client/stomp/CLAUDE.md` | client_review | 292 |
| `src/client/stomp/actions.rs` | client_review | 886 |
| `src/client/stomp/mod.rs` | client_review | 840 |
| `src/client/stun/CLAUDE.md` | client_review | 289 |
| `src/client/stun/actions.rs` | client_review | 292 |
| `src/client/stun/mod.rs` | client_review | 513 |
| `src/client/svn/CLAUDE.md` | client_review | 1034 |
| `src/client/syslog/CLAUDE.md` | client_review | 216 |
| `src/client/syslog/actions.rs` | client_review | 312 |
| `src/client/syslog/mod.rs` | client_review | 458 |
| `src/client/tcp/CLAUDE.md` | client_review | 120 |
| `src/client/tcp/actions.rs` | client_review | 300 |
| `src/client/tcp/mod.rs` | client_review | 340 |
| `src/client/telnet/CLAUDE.md` | client_review | 255 |
| `src/client/telnet/actions.rs` | client_review | 342 |
| `src/client/telnet/mod.rs` | client_review | 537 |
| `src/client/tftp/CLAUDE.md` | client_review | 121 |
| `src/client/tftp/actions.rs` | client_review | 480 |
| `src/client/tftp/mod.rs` | client_review | 748 |
| `src/client/tls/CLAUDE.md` | client_review | 242 |
| `src/client/tls/actions.rs` | client_review | 346 |
| `src/client/tls/mod.rs` | client_review | 609 |
| `src/client/tor/CLAUDE.md` | client_review | 487 |
| `src/client/tor/actions.rs` | client_review | 558 |
| `src/client/tor/mod.rs` | client_review | 812 |
| `src/client/torrent_dht/CLAUDE.md` | client_review | 152 |
| `src/client/torrent_dht/actions.rs` | client_review | 360 |
| `src/client/torrent_dht/mod.rs` | client_review | 564 |
| `src/client/torrent_peer/CLAUDE.md` | client_review | 168 |
| `src/client/torrent_peer/actions.rs` | client_review | 394 |
| `src/client/torrent_peer/mod.rs` | client_review | 532 |
| `src/client/torrent_tracker/CLAUDE.md` | client_review | 195 |
| `src/client/torrent_tracker/actions.rs` | client_review | 316 |
| `src/client/torrent_tracker/mod.rs` | client_review | 905 |
| `src/client/turn/CLAUDE.md` | client_review | 417 |
| `src/client/turn/actions.rs` | client_review | 504 |
| `src/client/turn/mod.rs` | client_review | 1106 |
| `src/client/udp/CLAUDE.md` | client_review | 312 |
| `src/client/udp/actions.rs` | client_review | 336 |
| `src/client/udp/mod.rs` | client_review | 581 |
| `src/client/usb/CLAUDE.md` | client_review | 245 |
| `src/client/usb/actions.rs` | client_review | 624 |
| `src/client/usb/mod.rs` | client_review | 926 |
| `src/client/vnc/CLAUDE.md` | client_review | 273 |
| `src/client/vnc/actions.rs` | client_review | 569 |
| `src/client/vnc/mod.rs` | client_review | 1046 |
| `src/client/webdav/CLAUDE.md` | client_review | 292 |
| `src/client/webdav/actions.rs` | client_review | 642 |
| `src/client/webdav/mod.rs` | client_review | 830 |
| `src/client/webrtc/CLAUDE.md` | client_review | 554 |
| `src/client/webrtc/actions.rs` | client_review | 510 |
| `src/client/webrtc/mod.rs` | client_review | 1141 |
| `src/client/websocket/CLAUDE.md` | client_review | 132 |
| `src/client/websocket/actions.rs` | client_review | 627 |
| `src/client/websocket/mod.rs` | client_review | 910 |
| `src/client/whois/CLAUDE.md` | client_review | 301 |
| `src/client/whois/actions.rs` | client_review | 315 |
| `src/client/whois/mod.rs` | client_review | 600 |
| `src/client/wireguard/CLAUDE.md` | client_review | 441 |
| `src/client/wireguard/actions.rs` | client_review | 350 |
| `src/client/wireguard/mod.rs` | client_review | 789 |
| `src/client/xmlrpc/CLAUDE.md` | client_review | 360 |
| `src/client/xmlrpc/actions.rs` | client_review | 308 |
| `src/client/xmlrpc/mod.rs` | client_review | 831 |
| `src/client/xmlrpc/response_guard.rs` | client_review | 284 |
| `src/client/xmpp/CLAUDE.md` | client_review | 425 |
| `src/client/xmpp/actions.rs` | client_review | 418 |
| `src/client/xmpp/mod.rs` | client_review | 800 |
| `src/client/zookeeper/CLAUDE.md` | client_review | 145 |
| `src/client/zookeeper/actions.rs` | client_review | 497 |
| `src/client/zookeeper/mod.rs` | client_review | 611 |
| `src/display/ascii.rs` | surfaces_review | 68 |
| `src/display/canvas.rs` | surfaces_review | 506 |
| `src/display/mod.rs` | surfaces_review | 41 |
| `src/display/text.rs` | surfaces_review | 113 |
| `src/display/types.rs` | surfaces_review | 166 |
| `src/docs.rs` | root | 554 |
| `src/easy/http/actions.rs` | client_review | 439 |
| `src/easy/http/mod.rs` | client_review | 3 |
| `src/easy/mod.rs` | client_review | 11 |
| `src/events/errors.rs` | root | 256 |
| `src/events/handler.rs` | root | 2971 |
| `src/events/mod.rs` | root | 11 |
| `src/events/types.rs` | root | 387 |
| `src/lib.rs` | root | 37 |
| `src/llm/action_helper.rs` | root | 1096 |
| `src/llm/actions/client_trait.rs` | root | 319 |
| `src/llm/actions/common.rs` | root | 1768 |
| `src/llm/actions/easy_trait.rs` | root | 83 |
| `src/llm/actions/executor.rs` | root | 603 |
| `src/llm/actions/mod.rs` | root | 937 |
| `src/llm/actions/protocol_trait.rs` | root | 473 |
| `src/llm/actions/summary.rs` | root | 279 |
| `src/llm/actions/tools.rs` | root | 2706 |
| `src/llm/agent_queue.rs` | root | 257 |
| `src/llm/bridge.rs` | root | 221 |
| `src/llm/circuit_breaker.rs` | root | 324 |
| `src/llm/config.rs` | root | 267 |
| `src/llm/conversation.rs` | root | 1932 |
| `src/llm/conversation_state.rs` | root | 308 |
| `src/llm/default_instructions.rs` | root | 206 |
| `src/llm/embedded_inference.rs` | root | 291 |
| `src/llm/event_handler_executor.rs` | root | 667 |
| `src/llm/event_instructions.rs` | root | 130 |
| `src/llm/feedback.rs` | root | 264 |
| `src/llm/hybrid_manager.rs` | root | 294 |
| `src/llm/mod.rs` | root | 142 |
| `src/llm/model_selection.rs` | root | 277 |
| `src/llm/ollama_client.rs` | root | 2546 |
| `src/llm/prompt.rs` | root | 1345 |
| `src/llm/rate_limiter.rs` | root | 610 |
| `src/llm/reference_parser.rs` | root | 179 |
| `src/llm/response_handler.rs` | root | 58 |
| `src/llm/template_engine.rs` | root | 260 |
| `src/logging.rs` | root | 318 |
| `src/logging/emit.rs` | root | 193 |
| `src/logging/patterns.rs` | root | 83 |
| `src/mcp_stdio/CLAUDE.md` | automation_review | 413 |
| `src/mcp_stdio/control.rs` | automation_review | 182 |
| `src/mcp_stdio/docs.rs` | automation_review | 532 |
| `src/mcp_stdio/drain.rs` | automation_review | 173 |
| `src/mcp_stdio/mod.rs` | automation_review | 82 |
| `src/mcp_stdio/tools.rs` | automation_review | 2249 |
| `src/panic_log.rs` | root | 81 |
| `src/pipe/mod.rs` | client_review | 419 |
| `src/privilege.rs` | root | 578 |
| `src/protocol/binding_defaults.rs` | runtime_review | 96 |
| `src/protocol/client_registry.rs` | runtime_review | 882 |
| `src/protocol/connect_context.rs` | runtime_review | 83 |
| `src/protocol/default_port.rs` | runtime_review | 173 |
| `src/protocol/dependencies.rs` | runtime_review | 502 |
| `src/protocol/docs.rs` | runtime_review | 124 |
| `src/protocol/dual.rs` | runtime_review | 117 |
| `src/protocol/easy_registry.rs` | runtime_review | 84 |
| `src/protocol/event_logger.rs` | runtime_review | 325 |
| `src/protocol/event_type.rs` | runtime_review | 472 |
| `src/protocol/log_template.rs` | runtime_review | 288 |
| `src/protocol/metadata.rs` | runtime_review | 582 |
| `src/protocol/mod.rs` | runtime_review | 121 |
| `src/protocol/server_registry.rs` | runtime_review | 1449 |
| `src/protocol/spawn_context.rs` | runtime_review | 606 |
| `src/scripting/CLAUDE.md` | automation_review | 338 |
| `src/scripting/environment.rs` | automation_review | 235 |
| `src/scripting/event_handler.rs` | automation_review | 682 |
| `src/scripting/executor.rs` | automation_review | 557 |
| `src/scripting/highlight.rs` | automation_review | 60 |
| `src/scripting/manager.rs` | automation_review | 254 |
| `src/scripting/mod.rs` | automation_review | 31 |
| `src/scripting/resident.rs` | automation_review | 736 |
| `src/scripting/types.rs` | automation_review | 280 |
| `src/server/accept_bounded.rs` | server_review | 473 |
| `src/server/amqp/CLAUDE.md` | server_review | 342 |
| `src/server/amqp/actions.rs` | server_review | 1814 |
| `src/server/amqp/codec.rs` | server_review | 838 |
| `src/server/amqp/mod.rs` | server_review | 1562 |
| `src/server/arp/CLAUDE.md` | server_review | 535 |
| `src/server/arp/actions.rs` | server_review | 436 |
| `src/server/arp/mod.rs` | server_review | 570 |
| `src/server/beanstalkd/CLAUDE.md` | server_review | 176 |
| `src/server/beanstalkd/actions.rs` | server_review | 792 |
| `src/server/beanstalkd/mod.rs` | server_review | 960 |
| `src/server/beanstalkd/wire.rs` | server_review | 448 |
| `src/server/bgp/CLAUDE.md` | server_review | 299 |
| `src/server/bgp/actions.rs` | server_review | 797 |
| `src/server/bgp/mod.rs` | server_review | 1585 |
| `src/server/bgp/wire.rs` | server_review | 746 |
| `src/server/bitcoin/CLAUDE.md` | server_review | 368 |
| `src/server/bitcoin/actions.rs` | server_review | 711 |
| `src/server/bitcoin/mod.rs` | server_review | 1085 |
| `src/server/bluetooth_ble/CLAUDE.md` | server_review | 636 |
| `src/server/bluetooth_ble/actions.rs` | server_review | 617 |
| `src/server/bluetooth_ble/mod.rs` | server_review | 1494 |
| `src/server/bluetooth_ble_battery/CLAUDE.md` | server_review | 235 |
| `src/server/bluetooth_ble_battery/actions.rs` | server_review | 296 |
| `src/server/bluetooth_ble_battery/mod.rs` | server_review | 139 |
| `src/server/bluetooth_ble_beacon/CLAUDE.md` | server_review | 229 |
| `src/server/bluetooth_ble_beacon/actions.rs` | server_review | 633 |
| `src/server/bluetooth_ble_beacon/advertise.rs` | server_review | 242 |
| `src/server/bluetooth_ble_beacon/mod.rs` | server_review | 311 |
| `src/server/bluetooth_ble_beacon/payload.rs` | server_review | 667 |
| `src/server/bluetooth_ble_cycling/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_cycling/actions.rs` | server_review | 261 |
| `src/server/bluetooth_ble_cycling/mod.rs` | server_review | 59 |
| `src/server/bluetooth_ble_data_stream/CLAUDE.md` | server_review | 207 |
| `src/server/bluetooth_ble_data_stream/actions.rs` | server_review | 267 |
| `src/server/bluetooth_ble_data_stream/mod.rs` | server_review | 54 |
| `src/server/bluetooth_ble_environmental/CLAUDE.md` | server_review | 204 |
| `src/server/bluetooth_ble_environmental/actions.rs` | server_review | 284 |
| `src/server/bluetooth_ble_environmental/mod.rs` | server_review | 53 |
| `src/server/bluetooth_ble_file_transfer/CLAUDE.md` | server_review | 212 |
| `src/server/bluetooth_ble_file_transfer/actions.rs` | server_review | 282 |
| `src/server/bluetooth_ble_file_transfer/mod.rs` | server_review | 53 |
| `src/server/bluetooth_ble_gamepad/CLAUDE.md` | server_review | 170 |
| `src/server/bluetooth_ble_gamepad/actions.rs` | server_review | 313 |
| `src/server/bluetooth_ble_gamepad/mod.rs` | server_review | 73 |
| `src/server/bluetooth_ble_heart_rate/CLAUDE.md` | server_review | 234 |
| `src/server/bluetooth_ble_heart_rate/actions.rs` | server_review | 272 |
| `src/server/bluetooth_ble_heart_rate/mod.rs` | server_review | 126 |
| `src/server/bluetooth_ble_keyboard/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_keyboard/actions.rs` | server_review | 323 |
| `src/server/bluetooth_ble_keyboard/mod.rs` | server_review | 174 |
| `src/server/bluetooth_ble_mouse/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_mouse/actions.rs` | server_review | 316 |
| `src/server/bluetooth_ble_mouse/mod.rs` | server_review | 155 |
| `src/server/bluetooth_ble_presenter/CLAUDE.md` | server_review | 266 |
| `src/server/bluetooth_ble_presenter/actions.rs` | server_review | 367 |
| `src/server/bluetooth_ble_presenter/mod.rs` | server_review | 187 |
| `src/server/bluetooth_ble_proximity/CLAUDE.md` | server_review | 155 |
| `src/server/bluetooth_ble_proximity/actions.rs` | server_review | 293 |
| `src/server/bluetooth_ble_proximity/mod.rs` | server_review | 41 |
| `src/server/bluetooth_ble_remote/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_remote/actions.rs` | server_review | 320 |
| `src/server/bluetooth_ble_remote/mod.rs` | server_review | 204 |
| `src/server/bluetooth_ble_running/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_running/actions.rs` | server_review | 268 |
| `src/server/bluetooth_ble_running/mod.rs` | server_review | 59 |
| `src/server/bluetooth_ble_thermometer/CLAUDE.md` | server_review | 203 |
| `src/server/bluetooth_ble_thermometer/actions.rs` | server_review | 269 |
| `src/server/bluetooth_ble_thermometer/mod.rs` | server_review | 53 |
| `src/server/bluetooth_ble_weight_scale/CLAUDE.md` | server_review | 202 |
| `src/server/bluetooth_ble_weight_scale/actions.rs` | server_review | 262 |
| `src/server/bluetooth_ble_weight_scale/mod.rs` | server_review | 56 |
| `src/server/bolt/CLAUDE.md` | server_review | 257 |
| `src/server/bolt/actions.rs` | server_review | 677 |
| `src/server/bolt/messages.rs` | server_review | 250 |
| `src/server/bolt/mod.rs` | server_review | 1241 |
| `src/server/bolt/packstream.rs` | server_review | 492 |
| `src/server/bolt/values.rs` | server_review | 510 |
| `src/server/bootp/CLAUDE.md` | server_review | 388 |
| `src/server/bootp/actions.rs` | server_review | 568 |
| `src/server/bootp/mod.rs` | server_review | 395 |
| `src/server/can/CLAUDE.md` | server_review | 361 |
| `src/server/can/actions.rs` | server_review | 668 |
| `src/server/can/frame.rs` | server_review | 818 |
| `src/server/can/mod.rs` | server_review | 713 |
| `src/server/can/transport.rs` | server_review | 261 |
| `src/server/cassandra/CLAUDE.md` | server_review | 252 |
| `src/server/cassandra/actions.rs` | server_review | 823 |
| `src/server/cassandra/mod.rs` | server_review | 2202 |
| `src/server/cdp/CLAUDE.md` | server_review | 322 |
| `src/server/cdp/actions.rs` | server_review | 543 |
| `src/server/cdp/codec.rs` | server_review | 990 |
| `src/server/cdp/mod.rs` | server_review | 769 |
| `src/server/coap/CLAUDE.md` | server_review | 398 |
| `src/server/coap/actions.rs` | server_review | 723 |
| `src/server/coap/codec.rs` | server_review | 645 |
| `src/server/coap/mod.rs` | server_review | 637 |
| `src/server/connection.rs` | server_review | 86 |
| `src/server/couchdb/CLAUDE.md` | server_review | 564 |
| `src/server/couchdb/actions.rs` | server_review | 1128 |
| `src/server/couchdb/mod.rs` | server_review | 796 |
| `src/server/datalink/CLAUDE.md` | server_review | 584 |
| `src/server/datalink/actions.rs` | server_review | 362 |
| `src/server/datalink/mod.rs` | server_review | 375 |
| `src/server/db2/CLAUDE.md` | server_review | 195 |
| `src/server/db2/actions.rs` | server_review | 508 |
| `src/server/db2/drda.rs` | server_review | 418 |
| `src/server/db2/mod.rs` | server_review | 583 |
| `src/server/dc/CLAUDE.md` | server_review | 643 |
| `src/server/dc/actions.rs` | server_review | 816 |
| `src/server/dc/mod.rs` | server_review | 657 |
| `src/server/dhcp/CLAUDE.md` | server_review | 380 |
| `src/server/dhcp/actions.rs` | server_review | 830 |
| `src/server/dhcp/mod.rs` | server_review | 376 |
| `src/server/dhcpv6/CLAUDE.md` | server_review | 235 |
| `src/server/dhcpv6/actions.rs` | server_review | 1457 |
| `src/server/dhcpv6/mod.rs` | server_review | 480 |
| `src/server/dict/CLAUDE.md` | server_review | 171 |
| `src/server/dict/actions.rs` | server_review | 703 |
| `src/server/dict/mod.rs` | server_review | 727 |
| `src/server/dict/wire.rs` | server_review | 364 |
| `src/server/dns/CLAUDE.md` | server_review | 600 |
| `src/server/dns/actions.rs` | server_review | 948 |
| `src/server/dns/mod.rs` | server_review | 404 |
| `src/server/docker/CLAUDE.md` | server_review | 173 |
| `src/server/docker/actions.rs` | server_review | 743 |
| `src/server/docker/api.rs` | server_review | 865 |
| `src/server/docker/mod.rs` | server_review | 613 |
| `src/server/doh/CLAUDE.md` | server_review | 571 |
| `src/server/doh/actions.rs` | server_review | 259 |
| `src/server/doh/mod.rs` | server_review | 785 |
| `src/server/dot/CLAUDE.md` | server_review | 402 |
| `src/server/dot/actions.rs` | server_review | 216 |
| `src/server/dot/mod.rs` | server_review | 621 |
| `src/server/dynamo/CLAUDE.md` | server_review | 350 |
| `src/server/dynamo/actions.rs` | server_review | 303 |
| `src/server/dynamo/mod.rs` | server_review | 576 |
| `src/server/eapol/CLAUDE.md` | server_review | 376 |
| `src/server/eapol/actions.rs` | server_review | 823 |
| `src/server/eapol/codec.rs` | server_review | 685 |
| `src/server/eapol/mod.rs` | server_review | 1362 |
| `src/server/elasticsearch/CLAUDE.md` | server_review | 405 |
| `src/server/elasticsearch/actions.rs` | server_review | 881 |
| `src/server/elasticsearch/mod.rs` | server_review | 585 |
| `src/server/etcd/CLAUDE.md` | server_review | 288 |
| `src/server/etcd/actions.rs` | server_review | 527 |
| `src/server/etcd/mod.rs` | server_review | 1339 |
| `src/server/finger/CLAUDE.md` | server_review | 244 |
| `src/server/finger/actions.rs` | server_review | 713 |
| `src/server/finger/mod.rs` | server_review | 543 |
| `src/server/ftp/CLAUDE.md` | server_review | 250 |
| `src/server/ftp/actions.rs` | server_review | 681 |
| `src/server/ftp/mod.rs` | server_review | 906 |
| `src/server/gearman/CLAUDE.md` | server_review | 134 |
| `src/server/gearman/actions.rs` | server_review | 593 |
| `src/server/gearman/mod.rs` | server_review | 793 |
| `src/server/gearman/wire.rs` | server_review | 386 |
| `src/server/gemini/CLAUDE.md` | server_review | 178 |
| `src/server/gemini/actions.rs` | server_review | 632 |
| `src/server/gemini/mod.rs` | server_review | 470 |
| `src/server/gemini/wire.rs` | server_review | 426 |
| `src/server/git/CLAUDE.md` | server_review | 228 |
| `src/server/git/actions.rs` | server_review | 474 |
| `src/server/git/mod.rs` | server_review | 834 |
| `src/server/git/pack.rs` | server_review | 492 |
| `src/server/git/pktline.rs` | server_review | 100 |
| `src/server/gopher/CLAUDE.md` | server_review | 239 |
| `src/server/gopher/actions.rs` | server_review | 530 |
| `src/server/gopher/mod.rs` | server_review | 517 |
| `src/server/grpc/CLAUDE.md` | server_review | 296 |
| `src/server/grpc/actions.rs` | server_review | 433 |
| `src/server/grpc/mod.rs` | server_review | 1458 |
| `src/server/gtp/CLAUDE.md` | server_review | 336 |
| `src/server/gtp/actions.rs` | server_review | 1491 |
| `src/server/gtp/codec.rs` | server_review | 1463 |
| `src/server/gtp/mod.rs` | server_review | 1400 |
| `src/server/hls/CLAUDE.md` | server_review | 149 |
| `src/server/hls/actions.rs` | server_review | 341 |
| `src/server/hls/mod.rs` | server_review | 777 |
| `src/server/hsrp/CLAUDE.md` | server_review | 346 |
| `src/server/hsrp/actions.rs` | server_review | 879 |
| `src/server/hsrp/codec.rs` | server_review | 673 |
| `src/server/hsrp/mod.rs` | server_review | 574 |
| `src/server/http/CLAUDE.md` | server_review | 332 |
| `src/server/http/actions.rs` | server_review | 412 |
| `src/server/http/mod.rs` | server_review | 913 |
| `src/server/http2/CLAUDE.md` | server_review | 238 |
| `src/server/http2/actions.rs` | server_review | 514 |
| `src/server/http2/h2_server.rs` | server_review | 1198 |
| `src/server/http2/mod.rs` | server_review | 15 |
| `src/server/http2/push.rs` | server_review | 26 |
| `src/server/http_common/CLAUDE.md` | server_review | 170 |
| `src/server/http_common/actions.rs` | server_review | 89 |
| `src/server/http_common/handler.rs` | server_review | 835 |
| `src/server/http_common/mod.rs` | server_review | 13 |
| `src/server/icmp/CLAUDE.md` | server_review | 462 |
| `src/server/icmp/actions.rs` | server_review | 1079 |
| `src/server/icmp/mod.rs` | server_review | 887 |
| `src/server/ident/CLAUDE.md` | server_review | 209 |
| `src/server/ident/actions.rs` | server_review | 584 |
| `src/server/ident/mod.rs` | server_review | 642 |
| `src/server/igmp/CLAUDE.md` | server_review | 372 |
| `src/server/igmp/actions.rs` | server_review | 514 |
| `src/server/igmp/mod.rs` | server_review | 726 |
| `src/server/imap/CLAUDE.md` | server_review | 429 |
| `src/server/imap/actions.rs` | server_review | 1472 |
| `src/server/imap/mod.rs` | server_review | 1088 |
| `src/server/ipp/CLAUDE.md` | server_review | 345 |
| `src/server/ipp/actions.rs` | server_review | 914 |
| `src/server/ipp/mod.rs` | server_review | 746 |
| `src/server/ipsec/CLAUDE.md` | server_review | 248 |
| `src/server/ipsec/actions.rs` | server_review | 374 |
| `src/server/ipsec/mod.rs` | server_review | 458 |
| `src/server/irc/CLAUDE.md` | server_review | 543 |
| `src/server/irc/actions.rs` | server_review | 825 |
| `src/server/irc/mod.rs` | server_review | 571 |
| `src/server/irc/wire.rs` | server_review | 185 |
| `src/server/isis/CLAUDE.md` | server_review | 436 |
| `src/server/isis/actions.rs` | server_review | 680 |
| `src/server/isis/mod.rs` | server_review | 809 |
| `src/server/jsonrpc/CLAUDE.md` | server_review | 247 |
| `src/server/jsonrpc/actions.rs` | server_review | 377 |
| `src/server/jsonrpc/mod.rs` | server_review | 774 |
| `src/server/kafka/CLAUDE.md` | server_review | 313 |
| `src/server/kafka/actions.rs` | server_review | 749 |
| `src/server/kafka/mod.rs` | server_review | 1850 |
| `src/server/kubernetes/CLAUDE.md` | server_review | 323 |
| `src/server/kubernetes/actions.rs` | server_review | 686 |
| `src/server/kubernetes/discovery.rs` | server_review | 394 |
| `src/server/kubernetes/mod.rs` | server_review | 1069 |
| `src/server/kubernetes/table.rs` | server_review | 424 |
| `src/server/ldap/CLAUDE.md` | server_review | 309 |
| `src/server/ldap/actions.rs` | server_review | 1337 |
| `src/server/ldap/mod.rs` | server_review | 1517 |
| `src/server/lldp/CLAUDE.md` | server_review | 317 |
| `src/server/lldp/actions.rs` | server_review | 747 |
| `src/server/lldp/codec.rs` | server_review | 1087 |
| `src/server/lldp/mod.rs` | server_review | 866 |
| `src/server/llmnr/CLAUDE.md` | server_review | 282 |
| `src/server/llmnr/actions.rs` | server_review | 787 |
| `src/server/llmnr/mod.rs` | server_review | 801 |
| `src/server/m3ua/CLAUDE.md` | server_review | 335 |
| `src/server/m3ua/actions.rs` | server_review | 1028 |
| `src/server/m3ua/codec.rs` | server_review | 771 |
| `src/server/m3ua/mod.rs` | server_review | 1431 |
| `src/server/maven/CLAUDE.md` | server_review | 600 |
| `src/server/maven/actions.rs` | server_review | 624 |
| `src/server/maven/mod.rs` | server_review | 766 |
| `src/server/mcp/CLAUDE.md` | server_review | 277 |
| `src/server/mcp/actions.rs` | server_review | 713 |
| `src/server/mcp/jsonrpc.rs` | server_review | 263 |
| `src/server/mcp/mod.rs` | server_review | 1283 |
| `src/server/mdns/CLAUDE.md` | server_review | 312 |
| `src/server/mdns/actions.rs` | server_review | 326 |
| `src/server/mdns/mod.rs` | server_review | 510 |
| `src/server/memcached/CLAUDE.md` | server_review | 262 |
| `src/server/memcached/actions.rs` | server_review | 746 |
| `src/server/memcached/mod.rs` | server_review | 753 |
| `src/server/memcached/protocol.rs` | server_review | 566 |
| `src/server/mercurial/CLAUDE.md` | server_review | 206 |
| `src/server/mercurial/actions.rs` | server_review | 625 |
| `src/server/mercurial/mod.rs` | server_review | 833 |
| `src/server/mod.rs` | server_review | 1219 |
| `src/server/modbus/CLAUDE.md` | server_review | 487 |
| `src/server/modbus/actions.rs` | server_review | 931 |
| `src/server/modbus/codec.rs` | server_review | 702 |
| `src/server/modbus/mod.rs` | server_review | 1086 |
| `src/server/mongodb/CLAUDE.md` | server_review | 398 |
| `src/server/mongodb/actions.rs` | server_review | 632 |
| `src/server/mongodb/mod.rs` | server_review | 1140 |
| `src/server/mqtt/CLAUDE.md` | server_review | 312 |
| `src/server/mqtt/actions.rs` | server_review | 1309 |
| `src/server/mqtt/mod.rs` | server_review | 1447 |
| `src/server/mssql/CLAUDE.md` | server_review | 314 |
| `src/server/mssql/actions.rs` | server_review | 695 |
| `src/server/mssql/mod.rs` | server_review | 1456 |
| `src/server/mysql/CLAUDE.md` | server_review | 366 |
| `src/server/mysql/actions.rs` | server_review | 573 |
| `src/server/mysql/caching_sha2.rs` | server_review | 320 |
| `src/server/mysql/mod.rs` | server_review | 1248 |
| `src/server/mysql/packet_limit.rs` | server_review | 267 |
| `src/server/named_pipe/CLAUDE.md` | server_review | 110 |
| `src/server/named_pipe/actions.rs` | server_review | 377 |
| `src/server/named_pipe/mod.rs` | server_review | 435 |
| `src/server/nats/CLAUDE.md` | server_review | 305 |
| `src/server/nats/actions.rs` | server_review | 1022 |
| `src/server/nats/mod.rs` | server_review | 1180 |
| `src/server/ndp/CLAUDE.md` | server_review | 384 |
| `src/server/ndp/actions.rs` | server_review | 1074 |
| `src/server/ndp/codec.rs` | server_review | 1225 |
| `src/server/ndp/mod.rs` | server_review | 918 |
| `src/server/netbios_ns/CLAUDE.md` | server_review | 251 |
| `src/server/netbios_ns/actions.rs` | server_review | 878 |
| `src/server/netbios_ns/mod.rs` | server_review | 549 |
| `src/server/netbios_ns/packet.rs` | server_review | 801 |
| `src/server/nfc/CLAUDE.md` | server_review | 252 |
| `src/server/nfc/actions.rs` | server_review | 757 |
| `src/server/nfc/apdu.rs` | server_review | 269 |
| `src/server/nfc/mod.rs` | server_review | 923 |
| `src/server/nfs/CLAUDE.md` | server_review | 346 |
| `src/server/nfs/actions.rs` | server_review | 819 |
| `src/server/nfs/guard.rs` | server_review | 495 |
| `src/server/nfs/mod.rs` | server_review | 1109 |
| `src/server/nntp/CLAUDE.md` | server_review | 636 |
| `src/server/nntp/actions.rs` | server_review | 697 |
| `src/server/nntp/mod.rs` | server_review | 966 |
| `src/server/nostr/CLAUDE.md` | server_review | 225 |
| `src/server/nostr/actions.rs` | server_review | 820 |
| `src/server/nostr/http.rs` | server_review | 215 |
| `src/server/nostr/mod.rs` | server_review | 1080 |
| `src/server/nostr/subscriptions.rs` | server_review | 199 |
| `src/server/nostr/wire.rs` | server_review | 979 |
| `src/server/npm/CLAUDE.md` | server_review | 309 |
| `src/server/npm/actions.rs` | server_review | 468 |
| `src/server/npm/mod.rs` | server_review | 776 |
| `src/server/nsq/CLAUDE.md` | server_review | 144 |
| `src/server/nsq/actions.rs` | server_review | 734 |
| `src/server/nsq/mod.rs` | server_review | 1216 |
| `src/server/nsq/wire.rs` | server_review | 742 |
| `src/server/ntp/CLAUDE.md` | server_review | 471 |
| `src/server/ntp/actions.rs` | server_review | 663 |
| `src/server/ntp/mod.rs` | server_review | 481 |
| `src/server/oauth2/CLAUDE.md` | server_review | 280 |
| `src/server/oauth2/actions.rs` | server_review | 764 |
| `src/server/oauth2/mod.rs` | server_review | 1170 |
| `src/server/oci_registry/CLAUDE.md` | server_review | 287 |
| `src/server/oci_registry/actions.rs` | server_review | 1176 |
| `src/server/oci_registry/mod.rs` | server_review | 1181 |
| `src/server/ollama/CLAUDE.md` | server_review | 335 |
| `src/server/ollama/actions.rs` | server_review | 832 |
| `src/server/ollama/mod.rs` | server_review | 1347 |
| `src/server/openai/CLAUDE.md` | server_review | 281 |
| `src/server/openai/actions.rs` | server_review | 540 |
| `src/server/openai/mod.rs` | server_review | 545 |
| `src/server/openapi/CLAUDE.md` | server_review | 228 |
| `src/server/openapi/actions.rs` | server_review | 498 |
| `src/server/openapi/mod.rs` | server_review | 1120 |
| `src/server/openid/CLAUDE.md` | server_review | 247 |
| `src/server/openid/actions.rs` | server_review | 737 |
| `src/server/openid/mod.rs` | server_review | 883 |
| `src/server/openvpn/CLAUDE.md` | server_review | 290 |
| `src/server/openvpn/actions.rs` | server_review | 462 |
| `src/server/openvpn/keymethod.rs` | server_review | 237 |
| `src/server/openvpn/mod.rs` | server_review | 1113 |
| `src/server/openvpn/packet.rs` | server_review | 403 |
| `src/server/openvpn/peer.rs` | server_review | 162 |
| `src/server/openvpn/reliable.rs` | server_review | 270 |
| `src/server/openvpn/session.rs` | server_review | 450 |
| `src/server/openvpn/tls_channel.rs` | server_review | 115 |
| `src/server/oracle/CLAUDE.md` | server_review | 660 |
| `src/server/ospf/CLAUDE.md` | server_review | 824 |
| `src/server/ospf/actions.rs` | server_review | 1468 |
| `src/server/ospf/mod.rs` | server_review | 1218 |
| `src/server/otlp/CLAUDE.md` | server_review | 123 |
| `src/server/otlp/actions.rs` | server_review | 478 |
| `src/server/otlp/codec.rs` | server_review | 622 |
| `src/server/otlp/mod.rs` | server_review | 528 |
| `src/server/peer_support.rs` | server_review | 240 |
| `src/server/pop3/CLAUDE.md` | server_review | 378 |
| `src/server/pop3/actions.rs` | server_review | 790 |
| `src/server/pop3/mod.rs` | server_review | 1052 |
| `src/server/postgresql/CLAUDE.md` | server_review | 308 |
| `src/server/postgresql/actions.rs` | server_review | 654 |
| `src/server/postgresql/mod.rs` | server_review | 1092 |
| `src/server/prometheus/CLAUDE.md` | server_review | 117 |
| `src/server/prometheus/actions.rs` | server_review | 357 |
| `src/server/prometheus/exposition.rs` | server_review | 776 |
| `src/server/prometheus/mod.rs` | server_review | 514 |
| `src/server/proxy/CLAUDE.md` | server_review | 510 |
| `src/server/proxy/actions.rs` | server_review | 907 |
| `src/server/proxy/cert_cache.rs` | server_review | 312 |
| `src/server/proxy/filter.rs` | server_review | 661 |
| `src/server/proxy/mod.rs` | server_review | 1648 |
| `src/server/proxy/tls_mitm.rs` | server_review | 776 |
| `src/server/pty/CLAUDE.md` | server_review | 100 |
| `src/server/pty/actions.rs` | server_review | 402 |
| `src/server/pty/mod.rs` | server_review | 360 |
| `src/server/pypi/CLAUDE.md` | server_review | 591 |
| `src/server/pypi/actions.rs` | server_review | 347 |
| `src/server/pypi/mod.rs` | server_review | 680 |
| `src/server/quic/CLAUDE.md` | server_review | 296 |
| `src/server/quic/actions.rs` | server_review | 579 |
| `src/server/quic/mod.rs` | server_review | 793 |
| `src/server/radius/CLAUDE.md` | server_review | 170 |
| `src/server/radius/actions.rs` | server_review | 945 |
| `src/server/radius/mod.rs` | server_review | 541 |
| `src/server/radius/packet.rs` | server_review | 576 |
| `src/server/rawip/CLAUDE.md` | server_review | 251 |
| `src/server/rawip/actions.rs` | server_review | 475 |
| `src/server/rawip/mod.rs` | server_review | 1186 |
| `src/server/rdp/CLAUDE.md` | server_review | 203 |
| `src/server/rdp/actions.rs` | server_review | 495 |
| `src/server/rdp/mod.rs` | server_review | 550 |
| `src/server/redis/CLAUDE.md` | server_review | 306 |
| `src/server/redis/actions.rs` | server_review | 708 |
| `src/server/redis/mod.rs` | server_review | 682 |
| `src/server/reverse_shell/CLAUDE.md` | server_review | 209 |
| `src/server/reverse_shell/actions.rs` | server_review | 483 |
| `src/server/reverse_shell/mod.rs` | server_review | 619 |
| `src/server/rip/CLAUDE.md` | server_review | 519 |
| `src/server/rip/actions.rs` | server_review | 457 |
| `src/server/rip/mod.rs` | server_review | 370 |
| `src/server/rss/CLAUDE.md` | server_review | 424 |
| `src/server/rss/actions.rs` | server_review | 384 |
| `src/server/rss/mod.rs` | server_review | 670 |
| `src/server/rtp/CLAUDE.md` | server_review | 145 |
| `src/server/rtp/actions.rs` | server_review | 413 |
| `src/server/rtp/media.rs` | server_review | 445 |
| `src/server/rtp/mod.rs` | server_review | 744 |
| `src/server/rtsp/CLAUDE.md` | server_review | 202 |
| `src/server/rtsp/actions.rs` | server_review | 492 |
| `src/server/rtsp/mod.rs` | server_review | 978 |
| `src/server/s3/CLAUDE.md` | server_review | 517 |
| `src/server/s3/actions.rs` | server_review | 695 |
| `src/server/s3/mod.rs` | server_review | 942 |
| `src/server/saml_idp/CLAUDE.md` | server_review | 232 |
| `src/server/saml_idp/actions.rs` | server_review | 504 |
| `src/server/saml_idp/mod.rs` | server_review | 624 |
| `src/server/saml_sp/CLAUDE.md` | server_review | 223 |
| `src/server/saml_sp/actions.rs` | server_review | 655 |
| `src/server/saml_sp/mod.rs` | server_review | 613 |
| `src/server/server_trait.rs` | server_review | 14 |
| `src/server/sip/CLAUDE.md` | server_review | 799 |
| `src/server/sip/actions.rs` | server_review | 690 |
| `src/server/sip/mod.rs` | server_review | 774 |
| `src/server/smb/CLAUDE.md` | server_review | 835 |
| `src/server/smb/actions.rs` | server_review | 832 |
| `src/server/smb/auth.rs` | server_review | 272 |
| `src/server/smb/mod.rs` | server_review | 2341 |
| `src/server/smb/wire.rs` | server_review | 1076 |
| `src/server/smtp/CLAUDE.md` | server_review | 283 |
| `src/server/smtp/actions.rs` | server_review | 639 |
| `src/server/smtp/mod.rs` | server_review | 1052 |
| `src/server/snmp/CLAUDE.md` | server_review | 544 |
| `src/server/snmp/actions.rs` | server_review | 512 |
| `src/server/snmp/mod.rs` | server_review | 1204 |
| `src/server/snowflake/CLAUDE.md` | server_review | 241 |
| `src/server/snowflake/actions.rs` | server_review | 650 |
| `src/server/snowflake/mod.rs` | server_review | 947 |
| `src/server/socket_file/CLAUDE.md` | server_review | 197 |
| `src/server/socket_file/actions.rs` | server_review | 492 |
| `src/server/socket_file/mod.rs` | server_review | 980 |
| `src/server/socket_helpers.rs` | server_review | 146 |
| `src/server/socks5/CLAUDE.md` | server_review | 468 |
| `src/server/socks5/actions.rs` | server_review | 696 |
| `src/server/socks5/filter.rs` | server_review | 61 |
| `src/server/socks5/mod.rs` | server_review | 1323 |
| `src/server/spark/CLAUDE.md` | server_review | 165 |
| `src/server/spark/actions.rs` | server_review | 468 |
| `src/server/spark/mod.rs` | server_review | 557 |
| `src/server/sqs/CLAUDE.md` | server_review | 485 |
| `src/server/sqs/actions.rs` | server_review | 334 |
| `src/server/sqs/mod.rs` | server_review | 557 |
| `src/server/ssdp/CLAUDE.md` | server_review | 388 |
| `src/server/ssdp/actions.rs` | server_review | 940 |
| `src/server/ssdp/message.rs` | server_review | 323 |
| `src/server/ssdp/mod.rs` | server_review | 667 |
| `src/server/ssh/CLAUDE.md` | server_review | 457 |
| `src/server/ssh/actions.rs` | server_review | 904 |
| `src/server/ssh/mod.rs` | server_review | 1411 |
| `src/server/ssh/sftp_handler.rs` | server_review | 1106 |
| `src/server/ssh_agent/CLAUDE.md` | server_review | 264 |
| `src/server/ssh_agent/actions.rs` | server_review | 965 |
| `src/server/ssh_agent/mod.rs` | server_review | 1071 |
| `src/server/stdio/CLAUDE.md` | server_review | 123 |
| `src/server/stdio/actions.rs` | server_review | 437 |
| `src/server/stdio/mod.rs` | server_review | 275 |
| `src/server/stomp/CLAUDE.md` | server_review | 319 |
| `src/server/stomp/actions.rs` | server_review | 891 |
| `src/server/stomp/frame.rs` | server_review | 434 |
| `src/server/stomp/mod.rs` | server_review | 868 |
| `src/server/stp/CLAUDE.md` | server_review | 382 |
| `src/server/stp/actions.rs` | server_review | 1255 |
| `src/server/stp/codec.rs` | server_review | 667 |
| `src/server/stp/mod.rs` | server_review | 731 |
| `src/server/stun/CLAUDE.md` | server_review | 509 |
| `src/server/stun/actions.rs` | server_review | 757 |
| `src/server/stun/mod.rs` | server_review | 482 |
| `src/server/svn/CLAUDE.md` | server_review | 301 |
| `src/server/svn/actions.rs` | server_review | 1077 |
| `src/server/svn/mod.rs` | server_review | 957 |
| `src/server/svn/wire.rs` | server_review | 367 |
| `src/server/syslog/CLAUDE.md` | server_review | 453 |
| `src/server/syslog/actions.rs` | server_review | 415 |
| `src/server/syslog/mod.rs` | server_review | 313 |
| `src/server/tcp/CLAUDE.md` | server_review | 363 |
| `src/server/tcp/PANIC_AUDIT.md` | server_review | 325 |
| `src/server/tcp/actions.rs` | server_review | 531 |
| `src/server/tcp/mod.rs` | server_review | 1197 |
| `src/server/telnet/CLAUDE.md` | server_review | 280 |
| `src/server/telnet/actions.rs` | server_review | 479 |
| `src/server/telnet/mod.rs` | server_review | 890 |
| `src/server/tftp/CLAUDE.md` | server_review | 540 |
| `src/server/tftp/actions.rs` | server_review | 524 |
| `src/server/tftp/mod.rs` | server_review | 1378 |
| `src/server/tls/CLAUDE.md` | server_review | 575 |
| `src/server/tls/actions.rs` | server_review | 509 |
| `src/server/tls/mod.rs` | server_review | 1358 |
| `src/server/tls_cert_manager.rs` | server_review | 399 |
| `src/server/tor_relay/CLAUDE.md` | server_review | 550 |
| `src/server/tor_relay/actions.rs` | server_review | 446 |
| `src/server/tor_relay/circuit.rs` | server_review | 795 |
| `src/server/tor_relay/mod.rs` | server_review | 1886 |
| `src/server/tor_relay/stream.rs` | server_review | 443 |
| `src/server/torrent_dht/CLAUDE.md` | server_review | 366 |
| `src/server/torrent_dht/actions.rs` | server_review | 727 |
| `src/server/torrent_dht/mod.rs` | server_review | 516 |
| `src/server/torrent_peer/CLAUDE.md` | server_review | 493 |
| `src/server/torrent_peer/actions.rs` | server_review | 737 |
| `src/server/torrent_peer/mod.rs` | server_review | 829 |
| `src/server/torrent_tracker/CLAUDE.md` | server_review | 358 |
| `src/server/torrent_tracker/actions.rs` | server_review | 707 |
| `src/server/torrent_tracker/mod.rs` | server_review | 675 |
| `src/server/tuntap/CLAUDE.md` | server_review | 263 |
| `src/server/tuntap/actions.rs` | server_review | 907 |
| `src/server/tuntap/mod.rs` | server_review | 1070 |
| `src/server/tuntap/packet.rs` | server_review | 1582 |
| `src/server/turn/CLAUDE.md` | server_review | 315 |
| `src/server/turn/actions.rs` | server_review | 1127 |
| `src/server/turn/mod.rs` | server_review | 1788 |
| `src/server/udp/CLAUDE.md` | server_review | 357 |
| `src/server/udp/actions.rs` | server_review | 455 |
| `src/server/udp/mod.rs` | server_review | 388 |
| `src/server/usb/CLAUDE.md` | server_review | 156 |
| `src/server/usb/common.rs` | server_review | 121 |
| `src/server/usb/descriptors.rs` | server_review | 1092 |
| `src/server/usb/fido2/CLAUDE.md` | server_review | 320 |
| `src/server/usb/fido2/actions.rs` | server_review | 687 |
| `src/server/usb/fido2/approval.rs` | server_review | 357 |
| `src/server/usb/fido2/ctap2.rs` | server_review | 1010 |
| `src/server/usb/fido2/ctaphid.rs` | server_review | 584 |
| `src/server/usb/fido2/mod.rs` | server_review | 1129 |
| `src/server/usb/fido2/u2f.rs` | server_review | 564 |
| `src/server/usb/guard.rs` | server_review | 701 |
| `src/server/usb/keyboard/CLAUDE.md` | server_review | 400 |
| `src/server/usb/keyboard/actions.rs` | server_review | 908 |
| `src/server/usb/keyboard/handler.rs` | server_review | 269 |
| `src/server/usb/keyboard/mod.rs` | server_review | 711 |
| `src/server/usb/mod.rs` | server_review | 62 |
| `src/server/usb/mouse/CLAUDE.md` | server_review | 215 |
| `src/server/usb/mouse/actions.rs` | server_review | 914 |
| `src/server/usb/mouse/handler.rs` | server_review | 167 |
| `src/server/usb/mouse/mod.rs` | server_review | 575 |
| `src/server/usb/msc/CLAUDE.md` | server_review | 261 |
| `src/server/usb/msc/actions.rs` | server_review | 879 |
| `src/server/usb/msc/disk.rs` | server_review | 316 |
| `src/server/usb/msc/fat16.rs` | server_review | 283 |
| `src/server/usb/msc/handler.rs` | server_review | 705 |
| `src/server/usb/msc/mod.rs` | server_review | 639 |
| `src/server/usb/serial/CLAUDE.md` | server_review | 202 |
| `src/server/usb/serial/actions.rs` | server_review | 637 |
| `src/server/usb/serial/handler.rs` | server_review | 310 |
| `src/server/usb/serial/mod.rs` | server_review | 512 |
| `src/server/usb/smartcard/CLAUDE.md` | server_review | 283 |
| `src/server/usb/smartcard/actions.rs` | server_review | 767 |
| `src/server/usb/smartcard/apdu.rs` | server_review | 280 |
| `src/server/usb/smartcard/ccid.rs` | server_review | 284 |
| `src/server/usb/smartcard/handler.rs` | server_review | 413 |
| `src/server/usb/smartcard/mod.rs` | server_review | 816 |
| `src/server/vault/CLAUDE.md` | server_review | 112 |
| `src/server/vault/actions.rs` | server_review | 516 |
| `src/server/vault/api.rs` | server_review | 395 |
| `src/server/vault/mod.rs` | server_review | 572 |
| `src/server/vnc/CLAUDE.md` | server_review | 272 |
| `src/server/vnc/actions.rs` | server_review | 1011 |
| `src/server/vnc/mod.rs` | server_review | 1239 |
| `src/server/vrrp/CLAUDE.md` | server_review | 408 |
| `src/server/vrrp/actions.rs` | server_review | 1256 |
| `src/server/vrrp/codec.rs` | server_review | 695 |
| `src/server/vrrp/mod.rs` | server_review | 888 |
| `src/server/webdav/CLAUDE.md` | server_review | 284 |
| `src/server/webdav/actions.rs` | server_review | 952 |
| `src/server/webdav/mod.rs` | server_review | 766 |
| `src/server/webrtc/CLAUDE.md` | server_review | 299 |
| `src/server/webrtc/actions.rs` | server_review | 567 |
| `src/server/webrtc/mod.rs` | server_review | 1396 |
| `src/server/webrtc_signaling/CLAUDE.md` | server_review | 599 |
| `src/server/webrtc_signaling/actions.rs` | server_review | 478 |
| `src/server/webrtc_signaling/mod.rs` | server_review | 1074 |
| `src/server/websocket/CLAUDE.md` | server_review | 321 |
| `src/server/websocket/actions.rs` | server_review | 1670 |
| `src/server/websocket/mod.rs` | server_review | 1456 |
| `src/server/whois/CLAUDE.md` | server_review | 229 |
| `src/server/whois/actions.rs` | server_review | 571 |
| `src/server/whois/mod.rs` | server_review | 611 |
| `src/server/wireguard/CLAUDE.md` | server_review | 386 |
| `src/server/wireguard/actions.rs` | server_review | 713 |
| `src/server/wireguard/mod.rs` | server_review | 714 |
| `src/server/wol/CLAUDE.md` | server_review | 242 |
| `src/server/wol/actions.rs` | server_review | 628 |
| `src/server/wol/mod.rs` | server_review | 607 |
| `src/server/xmlrpc/CLAUDE.md` | server_review | 241 |
| `src/server/xmlrpc/actions.rs` | server_review | 655 |
| `src/server/xmlrpc/mod.rs` | server_review | 1006 |
| `src/server/xmpp/CLAUDE.md` | server_review | 573 |
| `src/server/xmpp/actions.rs` | server_review | 886 |
| `src/server/xmpp/mod.rs` | server_review | 559 |
| `src/server/yarn/CLAUDE.md` | server_review | 118 |
| `src/server/yarn/actions.rs` | server_review | 711 |
| `src/server/yarn/mod.rs` | server_review | 623 |
| `src/server/zabbix/CLAUDE.md` | server_review | 140 |
| `src/server/zabbix/actions.rs` | server_review | 390 |
| `src/server/zabbix/mod.rs` | server_review | 520 |
| `src/server/zabbix/wire.rs` | server_review | 272 |
| `src/server/zookeeper/CLAUDE.md` | server_review | 210 |
| `src/server/zookeeper/actions.rs` | server_review | 734 |
| `src/server/zookeeper/mod.rs` | server_review | 1178 |
| `src/settings.rs` | root | 171 |
| `src/state/app_state.rs` | runtime_review | 3277 |
| `src/state/client.rs` | runtime_review | 343 |
| `src/state/client_handles.rs` | runtime_review | 65 |
| `src/state/easy.rs` | runtime_review | 136 |
| `src/state/intercepts.rs` | runtime_review | 103 |
| `src/state/machine.rs` | runtime_review | 58 |
| `src/state/mod.rs` | runtime_review | 26 |
| `src/state/server.rs` | runtime_review | 483 |
| `src/state/server_handles.rs` | runtime_review | 55 |
| `src/state/sqlite.rs` | runtime_review | 605 |
| `src/state/task.rs` | runtime_review | 300 |
| `src/system_stats.rs` | root | 214 |
| `src/tui/CLAUDE.md` | surfaces_review | 174 |
| `src/tui/actions.rs` | surfaces_review | 678 |
| `src/tui/activity.rs` | surfaces_review | 530 |
| `src/tui/app.rs` | surfaces_review | 405 |
| `src/tui/cards.rs` | surfaces_review | 1291 |
| `src/tui/chat.rs` | surfaces_review | 178 |
| `src/tui/command_exec.rs` | surfaces_review | 151 |
| `src/tui/commands.rs` | surfaces_review | 171 |
| `src/tui/driver.rs` | surfaces_review | 119 |
| `src/tui/event_loop.rs` | surfaces_review | 268 |
| `src/tui/hit.rs` | surfaces_review | 157 |
| `src/tui/keymap.rs` | surfaces_review | 703 |
| `src/tui/metrics.rs` | surfaces_review | 128 |
| `src/tui/mod.rs` | surfaces_review | 181 |
| `src/tui/modal/composer.rs` | surfaces_review | 485 |
| `src/tui/modal/confirm.rs` | surfaces_review | 49 |
| `src/tui/modal/form.rs` | surfaces_review | 786 |
| `src/tui/modal/help.rs` | surfaces_review | 117 |
| `src/tui/modal/intercept.rs` | surfaces_review | 60 |
| `src/tui/modal/mod.rs` | surfaces_review | 328 |
| `src/tui/modal/protocol_picker.rs` | surfaces_review | 162 |
| `src/tui/modal/request_detail.rs` | surfaces_review | 84 |
| `src/tui/modal/routing.rs` | surfaces_review | 615 |
| `src/tui/modal/text_editor.rs` | surfaces_review | 104 |
| `src/tui/modal_keys.rs` | surfaces_review | 1125 |
| `src/tui/projection.rs` | surfaces_review | 298 |
| `src/tui/rail.rs` | surfaces_review | 114 |
| `src/tui/render/cards.rs` | surfaces_review | 220 |
| `src/tui/render/chat.rs` | surfaces_review | 131 |
| `src/tui/render/mod.rs` | surfaces_review | 160 |
| `src/tui/render/overlay.rs` | surfaces_review | 1125 |
| `src/tui/render/rail.rs` | surfaces_review | 130 |
| `src/tui/render/status_bar.rs` | surfaces_review | 137 |
| `src/tui/render/stream.rs` | surfaces_review | 261 |
| `src/tui/theme.rs` | surfaces_review | 74 |
| `src/tui/uimsg.rs` | surfaces_review | 29 |
| `src/tui/wireshark.rs` | surfaces_review | 858 |
| `src/ui/app.rs` | surfaces_review | 386 |
| `src/ui/events.rs` | surfaces_review | 122 |
| `src/ui/layout.rs` | surfaces_review | 513 |
| `src/ui/mod.rs` | surfaces_review | 7 |
| `src/utils/bencode.rs` | root | 218 |
| `src/utils/bson_depth.rs` | root | 247 |
| `src/utils/clock.rs` | root | 50 |
| `src/utils/line_reader.rs` | root | 94 |
| `src/utils/mod.rs` | root | 21 |
| `src/utils/redact.rs` | root | 78 |
| `src/utils/resp.rs` | root | 231 |
| `src/utils/sanitize.rs` | root | 79 |
| `src/utils/save_load.rs` | root | 206 |
| `src/utils/shutdown.rs` | root | 109 |
| `src/utils/sql.rs` | root | 60 |
| `src/utils/truncate.rs` | root | 82 |
| `src/utils/wire_failure.rs` | root | 88 |
| `test-e2e.sh` | root | 369 |
| `test-examples.sh` | root | 185 |
| `test-models.sh` | root | 783 |
| `test-snapshot.sh` | root | 238 |
| `test-unit.sh` | root | 140 |
| `tests/OLLAMA_MODEL_TESTING.md` | root | 523 |
| `tests/README.md` | root | 324 |
| `tests/accept_bounded_test.rs` | root | 304 |
| `tests/access_log_test.rs` | root | 193 |
| `tests/action_descriptions_baseline.txt` | root | 1131 |
| `tests/action_descriptions_test.rs` | root | 441 |
| `tests/action_normalization_test.rs` | root | 96 |
| `tests/action_response_toolcall_test.rs` | root | 71 |
| `tests/action_response_trailing_prose_test.rs` | root | 163 |
| `tests/action_summary_test.rs` | root | 50 |
| `tests/advertised_actions_test.rs` | root | 155 |
| `tests/affirmative_default_drift_test.rs` | root | 733 |
| `tests/base_stack_test.rs` | root | 387 |
| `tests/ble_uuid_test.rs` | root | 83 |
| `tests/broken_stdout_pipe_test.rs` | root | 193 |
| `tests/capture_startup_reports_failure_test.rs` | root | 325 |
| `tests/capture_stop_releases_capture_test.rs` | root | 381 |
| `tests/cli_args_test.rs` | root | 264 |
| `tests/client.rs` | root | 9 |
| `tests/client/amqp/CLAUDE.md` | client_review | 80 |
| `tests/client/amqp/command_channel_test.rs` | client_review | 205 |
| `tests/client/amqp/e2e_test.rs` | client_review | 176 |
| `tests/client/amqp/mod.rs` | client_review | 6 |
| `tests/client/arp/CLAUDE.md` | client_review | 301 |
| `tests/client/arp/command_channel_test.rs` | client_review | 461 |
| `tests/client/arp/e2e_test.rs` | client_review | 255 |
| `tests/client/arp/mod.rs` | client_review | 4 |
| `tests/client/bgp/CLAUDE.md` | client_review | 114 |
| `tests/client/bgp/command_channel_test.rs` | client_review | 229 |
| `tests/client/bgp/e2e_test.rs` | client_review | 248 |
| `tests/client/bgp/hold_timer_test.rs` | client_review | 374 |
| `tests/client/bgp/mod.rs` | client_review | 8 |
| `tests/client/bgp/update_reply_test.rs` | client_review | 408 |
| `tests/client/bitcoin/CLAUDE.md` | client_review | 61 |
| `tests/client/bitcoin/command_channel_test.rs` | client_review | 227 |
| `tests/client/bitcoin/e2e_test.rs` | client_review | 244 |
| `tests/client/bitcoin/mod.rs` | client_review | 19 |
| `tests/client/bitcoin/rpc_auth_test.rs` | client_review | 256 |
| `tests/client/bluetooth/CLAUDE.md` | client_review | 381 |
| `tests/client/bluetooth/command_channel_test.rs` | client_review | 210 |
| `tests/client/bluetooth/e2e_test.rs` | client_review | 301 |
| `tests/client/bluetooth/mod.rs` | client_review | 4 |
| `tests/client/bootp/CLAUDE.md` | client_review | 436 |
| `tests/client/bootp/command_channel_test.rs` | client_review | 169 |
| `tests/client/bootp/e2e_test.rs` | client_review | 265 |
| `tests/client/bootp/mod.rs` | client_review | 4 |
| `tests/client/cassandra/CLAUDE.md` | client_review | 190 |
| `tests/client/cassandra/command_channel_test.rs` | client_review | 213 |
| `tests/client/cassandra/e2e_test.rs` | client_review | 499 |
| `tests/client/cassandra/mod.rs` | client_review | 4 |
| `tests/client/coap/CLAUDE.md` | client_review | 46 |
| `tests/client/coap/mod.rs` | client_review | 6 |
| `tests/client/coap/real_server_test.rs` | client_review | 274 |
| `tests/client/coap/request_test.rs` | client_review | 51 |
| `tests/client/coap/transport_test.rs` | client_review | 429 |
| `tests/client/couchdb/CLAUDE.md` | client_review | 140 |
| `tests/client/couchdb/command_channel_test.rs` | client_review | 253 |
| `tests/client/couchdb/e2e_test.rs` | client_review | 580 |
| `tests/client/couchdb/mod.rs` | client_review | 7 |
| `tests/client/datalink/CLAUDE.md` | client_review | 132 |
| `tests/client/datalink/action_test.rs` | client_review | 712 |
| `tests/client/datalink/command_channel_test.rs` | client_review | 345 |
| `tests/client/datalink/e2e_test.rs` | client_review | 379 |
| `tests/client/datalink/mod.rs` | client_review | 6 |
| `tests/client/dc/CLAUDE.md` | client_review | 296 |
| `tests/client/dc/command_channel_test.rs` | client_review | 174 |
| `tests/client/dc/e2e_test.rs` | client_review | 223 |
| `tests/client/dc/mod.rs` | client_review | 4 |
| `tests/client/dhcp/CLAUDE.md` | client_review | 329 |
| `tests/client/dhcp/command_channel_test.rs` | client_review | 173 |
| `tests/client/dhcp/e2e_test.rs` | client_review | 385 |
| `tests/client/dhcp/mod.rs` | client_review | 5 |
| `tests/client/dns/CLAUDE.md` | client_review | 284 |
| `tests/client/dns/command_channel_test.rs` | client_review | 210 |
| `tests/client/dns/e2e_test.rs` | client_review | 328 |
| `tests/client/dns/mod.rs` | client_review | 5 |
| `tests/client/doh/CLAUDE.md` | client_review | 315 |
| `tests/client/doh/command_channel_test.rs` | client_review | 243 |
| `tests/client/doh/e2e_test.rs` | client_review | 555 |
| `tests/client/doh/mod.rs` | client_review | 4 |
| `tests/client/dot/CLAUDE.md` | client_review | 262 |
| `tests/client/dot/command_channel_test.rs` | client_review | 168 |
| `tests/client/dot/e2e_test.rs` | client_review | 193 |
| `tests/client/dot/mod.rs` | client_review | 4 |
| `tests/client/dynamodb/CLAUDE.md` | client_review | 189 |
| `tests/client/dynamodb/command_channel_test.rs` | client_review | 404 |
| `tests/client/dynamodb/e2e_test.rs` | client_review | 318 |
| `tests/client/dynamodb/mod.rs` | client_review | 5 |
| `tests/client/elasticsearch/CLAUDE.md` | client_review | 260 |
| `tests/client/elasticsearch/command_channel_test.rs` | client_review | 244 |
| `tests/client/elasticsearch/e2e_test.rs` | client_review | 491 |
| `tests/client/elasticsearch/mod.rs` | client_review | 5 |
| `tests/client/etcd/CLAUDE.md` | client_review | 76 |
| `tests/client/etcd/command_channel_test.rs` | client_review | 233 |
| `tests/client/etcd/e2e_test.rs` | client_review | 485 |
| `tests/client/etcd/mod.rs` | client_review | 6 |
| `tests/client/etcd/real_server_test.rs` | client_review | 178 |
| `tests/client/finger/CLAUDE.md` | client_review | 80 |
| `tests/client/finger/e2e_test.rs` | client_review | 498 |
| `tests/client/finger/mod.rs` | client_review | 2 |
| `tests/client/ftp/CLAUDE.md` | client_review | 59 |
| `tests/client/ftp/command_channel_test.rs` | client_review | 172 |
| `tests/client/ftp/mod.rs` | client_review | 4 |
| `tests/client/ftp/test.rs` | client_review | 119 |
| `tests/client/git/CLAUDE.md` | client_review | 316 |
| `tests/client/git/command_channel_test.rs` | client_review | 217 |
| `tests/client/git/e2e_test.rs` | client_review | 162 |
| `tests/client/git/mod.rs` | client_review | 8 |
| `tests/client/git/operation_events_test.rs` | client_review | 204 |
| `tests/client/git/sandbox_test.rs` | client_review | 812 |
| `tests/client/gopher/CLAUDE.md` | client_review | 130 |
| `tests/client/gopher/e2e_test.rs` | client_review | 576 |
| `tests/client/gopher/mod.rs` | client_review | 2 |
| `tests/client/grpc/CLAUDE.md` | client_review | 154 |
| `tests/client/grpc/command_channel_test.rs` | client_review | 366 |
| `tests/client/grpc/e2e_test.rs` | client_review | 223 |
| `tests/client/grpc/mod.rs` | client_review | 6 |
| `tests/client/helpers.rs` | client_review | 5 |
| `tests/client/http/CLAUDE.md` | client_review | 115 |
| `tests/client/http/command_channel_test.rs` | client_review | 199 |
| `tests/client/http/e2e_test.rs` | client_review | 251 |
| `tests/client/http/fetch_client_test.rs` | client_review | 293 |
| `tests/client/http/mod.rs` | client_review | 10 |
| `tests/client/http/real_server_test.rs` | client_review | 183 |
| `tests/client/http/transport_test.rs` | client_review | 312 |
| `tests/client/http2/CLAUDE.md` | client_review | 185 |
| `tests/client/http2/command_channel_test.rs` | client_review | 195 |
| `tests/client/http2/e2e_test.rs` | client_review | 372 |
| `tests/client/http2/h2_transport_test.rs` | client_review | 134 |
| `tests/client/http2/mod.rs` | client_review | 6 |
| `tests/client/http3/CLAUDE.md` | client_review | 306 |
| `tests/client/http3/command_channel_test.rs` | client_review | 144 |
| `tests/client/http3/e2e_test.rs` | client_review | 358 |
| `tests/client/http3/mod.rs` | client_review | 6 |
| `tests/client/http_proxy/CLAUDE.md` | client_review | 200 |
| `tests/client/http_proxy/command_channel_test.rs` | client_review | 222 |
| `tests/client/http_proxy/e2e_test.rs` | client_review | 174 |
| `tests/client/http_proxy/mod.rs` | client_review | 7 |
| `tests/client/http_proxy/target_port_range_test.rs` | client_review | 66 |
| `tests/client/icmp/CLAUDE.md` | client_review | 150 |
| `tests/client/icmp/action_codec_test.rs` | client_review | 249 |
| `tests/client/icmp/command_channel_test.rs` | client_review | 207 |
| `tests/client/icmp/e2e_test.rs` | client_review | 104 |
| `tests/client/icmp/mod.rs` | client_review | 6 |
| `tests/client/ident/CLAUDE.md` | client_review | 103 |
| `tests/client/ident/e2e_test.rs` | client_review | 553 |
| `tests/client/ident/mod.rs` | client_review | 2 |
| `tests/client/igmp/CLAUDE.md` | client_review | 246 |
| `tests/client/igmp/command_channel_test.rs` | client_review | 179 |
| `tests/client/igmp/e2e_test.rs` | client_review | 262 |
| `tests/client/igmp/mod.rs` | client_review | 4 |
| `tests/client/imap/CLAUDE.md` | client_review | 206 |
| `tests/client/imap/command_channel_test.rs` | client_review | 223 |
| `tests/client/imap/e2e_test.rs` | client_review | 655 |
| `tests/client/imap/mod.rs` | client_review | 7 |
| `tests/client/imap/use_tls_refusal_test.rs` | client_review | 68 |
| `tests/client/ipp/CLAUDE.md` | client_review | 244 |
| `tests/client/ipp/command_channel_test.rs` | client_review | 192 |
| `tests/client/ipp/document_encoding_test.rs` | client_review | 131 |
| `tests/client/ipp/e2e_test.rs` | client_review | 346 |
| `tests/client/ipp/mod.rs` | client_review | 8 |
| `tests/client/irc/CLAUDE.md` | client_review | 123 |
| `tests/client/irc/command_channel_test.rs` | client_review | 179 |
| `tests/client/irc/e2e_test.rs` | client_review | 366 |
| `tests/client/irc/framing_test.rs` | client_review | 267 |
| `tests/client/irc/mod.rs` | client_review | 6 |
| `tests/client/isis/CLAUDE.md` | client_review | 394 |
| `tests/client/isis/capture_stop_test.rs` | client_review | 181 |
| `tests/client/isis/command_channel_test.rs` | client_review | 184 |
| `tests/client/isis/e2e_test.rs` | client_review | 399 |
| `tests/client/isis/mod.rs` | client_review | 6 |
| `tests/client/jsonrpc/CLAUDE.md` | client_review | 84 |
| `tests/client/jsonrpc/command_channel_test.rs` | client_review | 197 |
| `tests/client/jsonrpc/e2e_test.rs` | client_review | 488 |
| `tests/client/jsonrpc/mod.rs` | client_review | 4 |
| `tests/client/kafka/CLAUDE.md` | client_review | 111 |
| `tests/client/kafka/command_channel_test.rs` | client_review | 227 |
| `tests/client/kafka/e2e_test.rs` | client_review | 419 |
| `tests/client/kafka/mod.rs` | client_review | 6 |
| `tests/client/kubernetes/CLAUDE.md` | client_review | 56 |
| `tests/client/kubernetes/command_channel_test.rs` | client_review | 313 |
| `tests/client/kubernetes/e2e_test.rs` | client_review | 197 |
| `tests/client/kubernetes/mod.rs` | client_review | 5 |
| `tests/client/ldap/CLAUDE.md` | client_review | 90 |
| `tests/client/ldap/command_channel_test.rs` | client_review | 192 |
| `tests/client/ldap/mod.rs` | client_review | 4 |
| `tests/client/ldap/real_server_test.rs` | client_review | 496 |
| `tests/client/llmnr/CLAUDE.md` | client_review | 123 |
| `tests/client/llmnr/e2e_test.rs` | client_review | 498 |
| `tests/client/llmnr/mod.rs` | client_review | 2 |
| `tests/client/maven/CLAUDE.md` | client_review | 238 |
| `tests/client/maven/command_channel_test.rs` | client_review | 267 |
| `tests/client/maven/e2e_test.rs` | client_review | 197 |
| `tests/client/maven/mod.rs` | client_review | 5 |
| `tests/client/mcp/CLAUDE.md` | client_review | 192 |
| `tests/client/mcp/command_channel_test.rs` | client_review | 265 |
| `tests/client/mcp/e2e_test.rs` | client_review | 331 |
| `tests/client/mcp/mod.rs` | client_review | 7 |
| `tests/client/mdns/CLAUDE.md` | client_review | 207 |
| `tests/client/mdns/command_channel_test.rs` | client_review | 161 |
| `tests/client/mdns/e2e_test.rs` | client_review | 249 |
| `tests/client/mdns/mod.rs` | client_review | 4 |
| `tests/client/memcached/CLAUDE.md` | client_review | 50 |
| `tests/client/memcached/in_flight_test.rs` | client_review | 87 |
| `tests/client/memcached/mod.rs` | client_review | 6 |
| `tests/client/memcached/real_server_test.rs` | client_review | 329 |
| `tests/client/memcached/wire_test.rs` | client_review | 231 |
| `tests/client/mod.rs` | client_review | 208 |
| `tests/client/modbus/CLAUDE.md` | client_review | 41 |
| `tests/client/modbus/codec_test.rs` | client_review | 143 |
| `tests/client/modbus/mod.rs` | client_review | 6 |
| `tests/client/modbus/real_server_test.rs` | client_review | 343 |
| `tests/client/modbus/unanswered_test.rs` | client_review | 174 |
| `tests/client/mongodb/CLAUDE.md` | client_review | 470 |
| `tests/client/mongodb/command_channel_test.rs` | client_review | 193 |
| `tests/client/mongodb/e2e_test.rs` | client_review | 369 |
| `tests/client/mongodb/mod.rs` | client_review | 6 |
| `tests/client/mqtt/CLAUDE.md` | client_review | 107 |
| `tests/client/mqtt/command_channel_test.rs` | client_review | 213 |
| `tests/client/mqtt/keepalive_test.rs` | client_review | 276 |
| `tests/client/mqtt/mod.rs` | client_review | 6 |
| `tests/client/mqtt/real_server_test.rs` | client_review | 314 |
| `tests/client/mssql/CLAUDE.md` | client_review | 147 |
| `tests/client/mssql/command_channel_test.rs` | client_review | 219 |
| `tests/client/mssql/e2e_test.rs` | client_review | 268 |
| `tests/client/mssql/mod.rs` | client_review | 5 |
| `tests/client/mysql/CLAUDE.md` | client_review | 92 |
| `tests/client/mysql/command_channel_test.rs` | client_review | 187 |
| `tests/client/mysql/e2e_test.rs` | client_review | 432 |
| `tests/client/mysql/mod.rs` | client_review | 6 |
| `tests/client/mysql/real_server_test.rs` | client_review | 223 |
| `tests/client/nats/CLAUDE.md` | client_review | 131 |
| `tests/client/nats/e2e_test.rs` | client_review | 835 |
| `tests/client/nats/mod.rs` | client_review | 5 |
| `tests/client/netbios_ns/CLAUDE.md` | client_review | 144 |
| `tests/client/netbios_ns/e2e_test.rs` | client_review | 720 |
| `tests/client/netbios_ns/mod.rs` | client_review | 2 |
| `tests/client/nfc/CLAUDE.md` | client_review | 93 |
| `tests/client/nfc/command_channel_test.rs` | client_review | 199 |
| `tests/client/nfc/e2e_test.rs` | client_review | 460 |
| `tests/client/nfc/mod.rs` | client_review | 4 |
| `tests/client/nfs/CLAUDE.md` | client_review | 258 |
| `tests/client/nfs/command_channel_test.rs` | client_review | 200 |
| `tests/client/nfs/e2e_test.rs` | client_review | 207 |
| `tests/client/nfs/mod.rs` | client_review | 4 |
| `tests/client/nntp/CLAUDE.md` | client_review | 196 |
| `tests/client/nntp/command_channel_test.rs` | client_review | 173 |
| `tests/client/nntp/e2e_test.rs` | client_review | 378 |
| `tests/client/nntp/mod.rs` | client_review | 4 |
| `tests/client/npm/CLAUDE.md` | client_review | 272 |
| `tests/client/npm/command_channel_test.rs` | client_review | 357 |
| `tests/client/npm/e2e_test.rs` | client_review | 273 |
| `tests/client/npm/mod.rs` | client_review | 8 |
| `tests/client/npm/registry_target_test.rs` | client_review | 143 |
| `tests/client/ntp/CLAUDE.md` | client_review | 215 |
| `tests/client/ntp/command_channel_test.rs` | client_review | 166 |
| `tests/client/ntp/e2e_test.rs` | client_review | 183 |
| `tests/client/ntp/mod.rs` | client_review | 9 |
| `tests/client/oauth2/CLAUDE.md` | client_review | 318 |
| `tests/client/oauth2/command_channel_test.rs` | client_review | 258 |
| `tests/client/oauth2/e2e_test.rs` | client_review | 421 |
| `tests/client/oauth2/mod.rs` | client_review | 4 |
| `tests/client/ollama/CLAUDE.md` | client_review | 336 |
| `tests/client/ollama/command_channel_test.rs` | client_review | 254 |
| `tests/client/ollama/e2e_test.rs` | client_review | 532 |
| `tests/client/ollama/endpoint_targeting_test.rs` | client_review | 246 |
| `tests/client/ollama/mod.rs` | client_review | 6 |
| `tests/client/openai/CLAUDE.md` | client_review | 254 |
| `tests/client/openai/command_channel_test.rs` | client_review | 285 |
| `tests/client/openai/e2e_test.rs` | client_review | 267 |
| `tests/client/openai/endpoint_and_limits_test.rs` | client_review | 233 |
| `tests/client/openai/mod.rs` | client_review | 6 |
| `tests/client/openapi/CLAUDE.md` | client_review | 227 |
| `tests/client/openapi/command_channel_test.rs` | client_review | 241 |
| `tests/client/openapi/e2e_test.rs` | client_review | 223 |
| `tests/client/openapi/mod.rs` | client_review | 8 |
| `tests/client/openapi/target_precedence_test.rs` | client_review | 245 |
| `tests/client/openapi/test-api.yaml` | client_review | 116 |
| `tests/client/openidconnect/CLAUDE.md` | client_review | 67 |
| `tests/client/openidconnect/command_channel_test.rs` | client_review | 256 |
| `tests/client/openidconnect/e2e_test.rs` | client_review | 118 |
| `tests/client/openidconnect/mod.rs` | client_review | 4 |
| `tests/client/ospf/CLAUDE.md` | client_review | 392 |
| `tests/client/ospf/command_channel_test.rs` | client_review | 216 |
| `tests/client/ospf/e2e_test.rs` | client_review | 180 |
| `tests/client/ospf/mod.rs` | client_review | 4 |
| `tests/client/pop3/CLAUDE.md` | client_review | 216 |
| `tests/client/pop3/command_channel_test.rs` | client_review | 150 |
| `tests/client/pop3/e2e_test.rs` | client_review | 207 |
| `tests/client/pop3/mod.rs` | client_review | 6 |
| `tests/client/pop3/use_tls_refusal_test.rs` | client_review | 65 |
| `tests/client/postgresql/CLAUDE.md` | client_review | 78 |
| `tests/client/postgresql/command_channel_test.rs` | client_review | 187 |
| `tests/client/postgresql/e2e_test.rs` | client_review | 110 |
| `tests/client/postgresql/mod.rs` | client_review | 6 |
| `tests/client/postgresql/real_server_test.rs` | client_review | 221 |
| `tests/client/pypi/CLAUDE.md` | client_review | 285 |
| `tests/client/pypi/command_channel_test.rs` | client_review | 220 |
| `tests/client/pypi/e2e_test.rs` | client_review | 170 |
| `tests/client/pypi/index_target_test.rs` | client_review | 130 |
| `tests/client/pypi/mod.rs` | client_review | 10 |
| `tests/client/radius/CLAUDE.md` | client_review | 41 |
| `tests/client/radius/mod.rs` | client_review | 6 |
| `tests/client/radius/real_server_test.rs` | client_review | 453 |
| `tests/client/radius/request_test.rs` | client_review | 137 |
| `tests/client/radius/transport_test.rs` | client_review | 343 |
| `tests/client/redis/CLAUDE.md` | client_review | 91 |
| `tests/client/redis/command_channel_test.rs` | client_review | 166 |
| `tests/client/redis/e2e_test.rs` | client_review | 217 |
| `tests/client/redis/mod.rs` | client_review | 8 |
| `tests/client/redis/real_server_test.rs` | client_review | 261 |
| `tests/client/redis/resp_reader_test.rs` | client_review | 192 |
| `tests/client/rip/CLAUDE.md` | client_review | 77 |
| `tests/client/rip/command_channel_test.rs` | client_review | 179 |
| `tests/client/rip/e2e_test.rs` | client_review | 60 |
| `tests/client/rip/llm_path_test.rs` | client_review | 191 |
| `tests/client/rip/mod.rs` | client_review | 6 |
| `tests/client/rss/CLAUDE.md` | client_review | 84 |
| `tests/client/rss/command_channel_test.rs` | client_review | 197 |
| `tests/client/rss/e2e_test.rs` | client_review | 194 |
| `tests/client/rss/mod.rs` | client_review | 4 |
| `tests/client/s3/CLAUDE.md` | client_review | 358 |
| `tests/client/s3/command_channel_test.rs` | client_review | 323 |
| `tests/client/s3/e2e_test.rs` | client_review | 166 |
| `tests/client/s3/mod.rs` | client_review | 6 |
| `tests/client/saml/CLAUDE.md` | client_review | 169 |
| `tests/client/saml/command_channel_test.rs` | client_review | 212 |
| `tests/client/saml/e2e_test.rs` | client_review | 111 |
| `tests/client/saml/mod.rs` | client_review | 8 |
| `tests/client/saml/startup_params_test.rs` | client_review | 234 |
| `tests/client/saml/status_code_test.rs` | client_review | 173 |
| `tests/client/sip/CLAUDE.md` | client_review | 356 |
| `tests/client/sip/command_channel_test.rs` | client_review | 192 |
| `tests/client/sip/e2e_test.rs` | client_review | 375 |
| `tests/client/sip/hostile_response_test.rs` | client_review | 196 |
| `tests/client/sip/mod.rs` | client_review | 6 |
| `tests/client/smb/CLAUDE.md` | client_review | 407 |
| `tests/client/smb/command_channel_test.rs` | client_review | 171 |
| `tests/client/smb/e2e_test.rs` | client_review | 147 |
| `tests/client/smb/mod.rs` | client_review | 4 |
| `tests/client/smtp/CLAUDE.md` | client_review | 186 |
| `tests/client/smtp/command_channel_test.rs` | client_review | 244 |
| `tests/client/smtp/e2e_test.rs` | client_review | 171 |
| `tests/client/smtp/mod.rs` | client_review | 6 |
| `tests/client/smtp/startup_params_test.rs` | client_review | 294 |
| `tests/client/snmp/CLAUDE.md` | client_review | 272 |
| `tests/client/snmp/command_channel_test.rs` | client_review | 186 |
| `tests/client/snmp/e2e_test.rs` | client_review | 315 |
| `tests/client/snmp/mod.rs` | client_review | 4 |
| `tests/client/socket_file/CLAUDE.md` | client_review | 102 |
| `tests/client/socket_file/command_channel_test.rs` | client_review | 146 |
| `tests/client/socket_file/e2e_test.rs` | client_review | 264 |
| `tests/client/socket_file/mod.rs` | client_review | 6 |
| `tests/client/socks5/CLAUDE.md` | client_review | 381 |
| `tests/client/socks5/action_test.rs` | client_review | 391 |
| `tests/client/socks5/command_channel_test.rs` | client_review | 193 |
| `tests/client/socks5/e2e_test.rs` | client_review | 312 |
| `tests/client/socks5/mod.rs` | client_review | 7 |
| `tests/client/sqs/CLAUDE.md` | client_review | 219 |
| `tests/client/sqs/command_channel_test.rs` | client_review | 256 |
| `tests/client/sqs/e2e_test.rs` | client_review | 231 |
| `tests/client/sqs/mod.rs` | client_review | 7 |
| `tests/client/ssdp/CLAUDE.md` | client_review | 137 |
| `tests/client/ssdp/e2e_test.rs` | client_review | 608 |
| `tests/client/ssdp/mod.rs` | client_review | 2 |
| `tests/client/ssh/CLAUDE.md` | client_review | 88 |
| `tests/client/ssh/command_channel_test.rs` | client_review | 241 |
| `tests/client/ssh/mod.rs` | client_review | 4 |
| `tests/client/ssh/real_server_test.rs` | client_review | 327 |
| `tests/client/ssh_agent/CLAUDE.md` | client_review | 211 |
| `tests/client/ssh_agent/command_channel_test.rs` | client_review | 150 |
| `tests/client/ssh_agent/e2e_test.rs` | client_review | 249 |
| `tests/client/ssh_agent/mod.rs` | client_review | 4 |
| `tests/client/stomp/CLAUDE.md` | client_review | 98 |
| `tests/client/stomp/e2e_test.rs` | client_review | 573 |
| `tests/client/stomp/mod.rs` | client_review | 2 |
| `tests/client/stun/CLAUDE.md` | client_review | 62 |
| `tests/client/stun/command_channel_test.rs` | client_review | 198 |
| `tests/client/stun/e2e_test.rs` | client_review | 122 |
| `tests/client/stun/mod.rs` | client_review | 5 |
| `tests/client/syslog/CLAUDE.md` | client_review | 79 |
| `tests/client/syslog/command_channel_test.rs` | client_review | 252 |
| `tests/client/syslog/e2e_test.rs` | client_review | 163 |
| `tests/client/syslog/mod.rs` | client_review | 4 |
| `tests/client/tcp/CLAUDE.md` | client_review | 40 |
| `tests/client/tcp/e2e_test.rs` | client_review | 229 |
| `tests/client/tcp/mod.rs` | client_review | 2 |
| `tests/client/telnet/CLAUDE.md` | client_review | 170 |
| `tests/client/telnet/e2e_test.rs` | client_review | 305 |
| `tests/client/telnet/mod.rs` | client_review | 2 |
| `tests/client/tftp/CLAUDE.md` | client_review | 75 |
| `tests/client/tftp/command_channel_test.rs` | client_review | 178 |
| `tests/client/tftp/e2e_test.rs` | client_review | 255 |
| `tests/client/tftp/mod.rs` | client_review | 5 |
| `tests/client/tls/CLAUDE.md` | client_review | 173 |
| `tests/client/tls/command_channel_test.rs` | client_review | 179 |
| `tests/client/tls/e2e_test.rs` | client_review | 410 |
| `tests/client/tls/mod.rs` | client_review | 8 |
| `tests/client/tls/multi_turn_test.rs` | client_review | 147 |
| `tests/client/tor/CLAUDE.md` | client_review | 109 |
| `tests/client/tor/action_test.rs` | client_review | 391 |
| `tests/client/tor/apply_actions_test.rs` | client_review | 126 |
| `tests/client/tor/command_channel_test.rs` | client_review | 80 |
| `tests/client/tor/e2e_test.rs` | client_review | 159 |
| `tests/client/tor/mod.rs` | client_review | 16 |
| `tests/client/tor/test.rs` | client_review | 164 |
| `tests/client/torrent_dht/CLAUDE.md` | client_review | 51 |
| `tests/client/torrent_dht/command_channel_test.rs` | client_review | 231 |
| `tests/client/torrent_dht/e2e_test.rs` | client_review | 97 |
| `tests/client/torrent_dht/mod.rs` | client_review | 4 |
| `tests/client/torrent_peer/CLAUDE.md` | client_review | 53 |
| `tests/client/torrent_peer/command_channel_test.rs` | client_review | 186 |
| `tests/client/torrent_peer/e2e_test.rs` | client_review | 116 |
| `tests/client/torrent_peer/mod.rs` | client_review | 5 |
| `tests/client/torrent_tracker/command_channel_test.rs` | client_review | 451 |
| `tests/client/torrent_tracker/followup_chain_test.rs` | client_review | 178 |
| `tests/client/torrent_tracker/mod.rs` | client_review | 5 |
| `tests/client/turn/CLAUDE.md` | client_review | 228 |
| `tests/client/turn/command_channel_test.rs` | client_review | 236 |
| `tests/client/turn/e2e_test.rs` | client_review | 299 |
| `tests/client/turn/mod.rs` | client_review | 6 |
| `tests/client/turn/response_parsing_test.rs` | client_review | 235 |
| `tests/client/udp/CLAUDE.md` | client_review | 210 |
| `tests/client/udp/command_channel_test.rs` | client_review | 177 |
| `tests/client/udp/e2e_test.rs` | client_review | 403 |
| `tests/client/udp/mod.rs` | client_review | 5 |
| `tests/client/usb/CLAUDE.md` | client_review | 204 |
| `tests/client/usb/command_channel_test.rs` | client_review | 168 |
| `tests/client/usb/e2e_test.rs` | client_review | 252 |
| `tests/client/usb/mod.rs` | client_review | 4 |
| `tests/client/vnc/CLAUDE.md` | client_review | 205 |
| `tests/client/vnc/command_channel_test.rs` | client_review | 164 |
| `tests/client/vnc/coordinate_range_test.rs` | client_review | 114 |
| `tests/client/vnc/e2e_test.rs` | client_review | 203 |
| `tests/client/vnc/mod.rs` | client_review | 6 |
| `tests/client/webdav/CLAUDE.md` | client_review | 109 |
| `tests/client/webdav/command_channel_test.rs` | client_review | 249 |
| `tests/client/webdav/e2e_test.rs` | client_review | 250 |
| `tests/client/webdav/mod.rs` | client_review | 5 |
| `tests/client/webrtc/CLAUDE.md` | client_review | 336 |
| `tests/client/webrtc/command_channel_test.rs` | client_review | 176 |
| `tests/client/webrtc/e2e_test.rs` | client_review | 151 |
| `tests/client/webrtc/mod.rs` | client_review | 4 |
| `tests/client/websocket/CLAUDE.md` | client_review | 97 |
| `tests/client/websocket/command_channel_test.rs` | client_review | 198 |
| `tests/client/websocket/e2e_test.rs` | client_review | 364 |
| `tests/client/websocket/keepalive_test.rs` | client_review | 239 |
| `tests/client/websocket/mod.rs` | client_review | 5 |
| `tests/client/whois/CLAUDE.md` | client_review | 79 |
| `tests/client/whois/command_channel_test.rs` | client_review | 169 |
| `tests/client/whois/e2e_test.rs` | client_review | 159 |
| `tests/client/whois/mod.rs` | client_review | 4 |
| `tests/client/wireguard/CLAUDE.md` | client_review | 206 |
| `tests/client/wireguard/command_channel_test.rs` | client_review | 178 |
| `tests/client/wireguard/e2e_test.rs` | client_review | 321 |
| `tests/client/wireguard/mod.rs` | client_review | 4 |
| `tests/client/xmlrpc/command_channel_test.rs` | client_review | 199 |
| `tests/client/xmlrpc/mod.rs` | client_review | 4 |
| `tests/client/xmlrpc/response_guard_test.rs` | client_review | 223 |
| `tests/client/xmpp/CLAUDE.md` | client_review | 280 |
| `tests/client/xmpp/command_channel_test.rs` | client_review | 152 |
| `tests/client/xmpp/e2e_test.rs` | client_review | 190 |
| `tests/client/xmpp/mod.rs` | client_review | 6 |
| `tests/client/xmpp/startup_params_test.rs` | client_review | 126 |
| `tests/client/zookeeper/command_channel_test.rs` | client_review | 279 |
| `tests/client/zookeeper/mod.rs` | client_review | 2 |
| `tests/client_event_routing_test.rs` | root | 282 |
| `tests/client_event_wiring_test.rs` | root | 524 |
| `tests/client_handle_test.rs` | root | 505 |
| `tests/client_llm_budget_test.rs` | root | 92 |
| `tests/client_provide_feedback_test.rs` | root | 249 |
| `tests/client_stop_releases_socket_test.rs` | root | 163 |
| `tests/codec_property_test.rs` | root | 4890 |
| `tests/connection_map_race_test.rs` | root | 640 |
| `tests/connection_soak_test.rs` | root | 849 |
| `tests/connectionless_audit_test.rs` | root | 271 |
| `tests/control_character_sanitizer_ratchet_test.rs` | root | 263 |
| `tests/dashboard_activity_test.rs` | root | 354 |
| `tests/dashboard_create_flow_test.rs` | root | 646 |
| `tests/dashboard_frame_test.rs` | root | 646 |
| `tests/dashboard_rail_test.rs` | root | 834 |
| `tests/dashboard_routing_test.rs` | root | 366 |
| `tests/dashboard_wireshark_test.rs` | root | 378 |
| `tests/database_name_validation_test.rs` | root | 214 |
| `tests/datalink_test.rs` | root | 21 |
| `tests/decision_tag_ratchet_test.rs` | root | 271 |
| `tests/default_port_resolution_test.rs` | root | 266 |
| `tests/detached_task_drift_test.rs` | root | 498 |
| `tests/doc_paths_exist_test.rs` | root | 455 |
| `tests/doc_test_counts_test.rs` | root | 453 |
| `tests/dual_protocol_test.rs` | root | 163 |
| `tests/e2e.rs` | root | 21 |
| `tests/e2e/http_test.rs` | root | 183 |
| `tests/e2e/mod.rs` | root | 12 |
| `tests/e2e/netget_wrapper.rs` | root | 337 |
| `tests/e2e/tcp_test.rs` | root | 145 |
| `tests/e2e_footer_test.rs` | root | 285 |
| `tests/embedded_inference_test.rs` | root | 44 |
| `tests/empty_static_handler_test.rs` | root | 445 |
| `tests/eval.rs` | root | 115 |
| `tests/eval/CLAUDE.md` | root | 294 |
| `tests/eval/case.rs` | root | 306 |
| `tests/eval/classify.rs` | root | 682 |
| `tests/eval/mod.rs` | root | 53 |
| `tests/eval/probe.rs` | root | 270 |
| `tests/eval/probe_check.rs` | root | 1085 |
| `tests/eval/report.rs` | root | 579 |
| `tests/eval/runner.rs` | root | 556 |
| `tests/eval/suites.rs` | root | 2055 |
| `tests/event_action_declarations_test.rs` | root | 636 |
| `tests/event_emit_sites_test.rs` | root | 295 |
| `tests/event_handler_config_rejection_test.rs` | root | 92 |
| `tests/event_handler_llm_instruction_test.rs` | root | 108 |
| `tests/event_handler_validation_test.rs` | root | 185 |
| `tests/event_logger_test.rs` | root | 81 |
| `tests/event_type_test.rs` | root | 49 |
| `tests/example_hex_drift_test.rs` | root | 713 |
| `tests/examples.rs` | root | 13 |
| `tests/examples/coverage_test.rs` | root | 231 |
| `tests/examples/dns_examples_test.rs` | root | 332 |
| `tests/examples/example_runnability_test.rs` | root | 616 |
| `tests/examples/http_examples_test.rs` | root | 445 |
| `tests/examples/mod.rs` | root | 57 |
| `tests/examples/protocol_examples_test.rs` | root | 1010 |
| `tests/examples/tcp_examples_test.rs` | root | 357 |
| `tests/executable_examples_test.rs` | root | 270 |
| `tests/fail_open_action_defaults_test.rs` | root | 239 |
| `tests/failure_mode_declaration_test.rs` | root | 432 |
| `tests/feedback_loop_test.rs` | root | 233 |
| `tests/fixtures/mysql_prompt.txt` | root | 8 |
| `tests/fixtures/schema.json` | root | 60 |
| `tests/fixtures/schema.sql` | root | 21 |
| `tests/fixtures/users_data.json` | root | 30 |
| `tests/footer_visual_test.rs` | root | 147 |
| `tests/handler_result_decides_the_bound_test.rs` | root | 391 |
| `tests/helpers/child_guard.rs` | root | 384 |
| `tests/helpers/client.rs` | root | 524 |
| `tests/helpers/common.rs` | root | 484 |
| `tests/helpers/event_trigger.rs` | root | 339 |
| `tests/helpers/example_test_framework.rs` | root | 412 |
| `tests/helpers/http_bounds.rs` | root | 665 |
| `tests/helpers/inbound_limit.rs` | root | 281 |
| `tests/helpers/llm_live.rs` | root | 691 |
| `tests/helpers/llm_live_case.rs` | root | 465 |
| `tests/helpers/mock.rs` | root | 3 |
| `tests/helpers/mock_action_names.rs` | root | 148 |
| `tests/helpers/mock_builder.rs` | root | 380 |
| `tests/helpers/mock_config.rs` | root | 762 |
| `tests/helpers/mock_matcher.rs` | root | 402 |
| `tests/helpers/mock_ollama.rs` | root | 1307 |
| `tests/helpers/mod.rs` | root | 40 |
| `tests/helpers/netget.rs` | root | 1449 |
| `tests/helpers/ollama_test_builder.rs` | root | 1208 |
| `tests/helpers/pcap_oracle.rs` | root | 1147 |
| `tests/helpers/real_server.rs` | root | 764 |
| `tests/helpers/server.rs` | root | 705 |
| `tests/helpers/usbip_bounds.rs` | root | 290 |
| `tests/helpers/usbip_client.rs` | root | 644 |
| `tests/http_request_filter_test.rs` | root | 214 |
| `tests/http_request_line_test.rs` | root | 117 |
| `tests/hybrid_manager_test.rs` | root | 31 |
| `tests/input_state_unicode_test.rs` | root | 307 |
| `tests/integration_toolcall.rs` | root | 18 |
| `tests/literal_ip_dns_bypass_test.rs` | root | 64 |
| `tests/llm_bridge_test.rs` | root | 520 |
| `tests/llm_circuit_breaker_test.rs` | root | 492 |
| `tests/llm_concurrency_default_test.rs` | root | 204 |
| `tests/llm_config_test.rs` | root | 31 |
| `tests/llm_endpoint_proxy_bypass_test.rs` | root | 195 |
| `tests/llm_live.rs` | root | 12 |
| `tests/llm_live/CLAUDE.md` | root | 138 |
| `tests/llm_live/bigdata.rs` | root | 631 |
| `tests/llm_live/ble_profiles.rs` | root | 584 |
| `tests/llm_live/bluetooth_ble.rs` | root | 268 |
| `tests/llm_live/couchdb.rs` | root | 180 |
| `tests/llm_live/datastores.rs` | root | 1156 |
| `tests/llm_live/dns.rs` | root | 92 |
| `tests/llm_live/dns_secure.rs` | root | 208 |
| `tests/llm_live/elasticsearch.rs` | root | 144 |
| `tests/llm_live/federation.rs` | root | 357 |
| `tests/llm_live/ftp.rs` | root | 49 |
| `tests/llm_live/http.rs` | root | 164 |
| `tests/llm_live/http_apis.rs` | root | 1843 |
| `tests/llm_live/imap.rs` | root | 138 |
| `tests/llm_live/irc.rs` | root | 131 |
| `tests/llm_live/jsonrpc.rs` | root | 74 |
| `tests/llm_live/memcached.rs` | root | 53 |
| `tests/llm_live/mod.rs` | root | 94 |
| `tests/llm_live/netservices.rs` | root | 921 |
| `tests/llm_live/nfc.rs` | root | 216 |
| `tests/llm_live/nntp.rs` | root | 144 |
| `tests/llm_live/ntp.rs` | root | 74 |
| `tests/llm_live/openai.rs` | root | 217 |
| `tests/llm_live/p2p.rs` | root | 503 |
| `tests/llm_live/pop3.rs` | root | 50 |
| `tests/llm_live/rawnet.rs` | root | 245 |
| `tests/llm_live/realtime.rs` | root | 627 |
| `tests/llm_live/redis.rs` | root | 109 |
| `tests/llm_live/remote_access.rs` | root | 475 |
| `tests/llm_live/routing.rs` | root | 558 |
| `tests/llm_live/rss.rs` | root | 50 |
| `tests/llm_live/rtsp.rs` | root | 409 |
| `tests/llm_live/sip.rs` | root | 370 |
| `tests/llm_live/smtp.rs` | root | 56 |
| `tests/llm_live/socks5.rs` | root | 184 |
| `tests/llm_live/streams.rs` | root | 1153 |
| `tests/llm_live/stun.rs` | root | 84 |
| `tests/llm_live/tcp.rs` | root | 136 |
| `tests/llm_live/telnet.rs` | root | 140 |
| `tests/llm_live/udp.rs` | root | 69 |
| `tests/llm_live/usb.rs` | root | 636 |
| `tests/llm_live/vpn.rs` | root | 207 |
| `tests/llm_live/whois.rs` | root | 51 |
| `tests/llm_live/xmlrpc.rs` | root | 142 |
| `tests/llm_live_coverage_test.rs` | root | 355 |
| `tests/llm_log_prefix_guard_test.rs` | root | 96 |
| `tests/llm_model_selection_test.rs` | root | 51 |
| `tests/llm_native_tools_test.rs` | root | 118 |
| `tests/llm_rate_limiter_test.rs` | root | 407 |
| `tests/llm_roundtrip_logging_test.rs` | root | 166 |
| `tests/llm_sampling_options_test.rs` | root | 150 |
| `tests/llm_stream_accumulation_test.rs` | root | 232 |
| `tests/llm_timeout_defaults_test.rs` | root | 66 |
| `tests/log_patterns_test.rs` | root | 130 |
| `tests/log_template_injection_test.rs` | root | 116 |
| `tests/log_template_test.rs` | root | 117 |
| `tests/logging_facade_test.rs` | root | 91 |
| `tests/logging_integration_test.rs` | root | 95 |
| `tests/logging_rotation_test.rs` | root | 203 |
| `tests/logging_unit_test.rs` | root | 105 |
| `tests/management_form_test.rs` | root | 365 |
| `tests/management_test.rs` | root | 285 |
| `tests/manual_intercept_test.rs` | root | 326 |
| `tests/max_inbound_bytes_bound_plus_one_test.rs` | root | 697 |
| `tests/max_inbound_bytes_declaration_test.rs` | root | 422 |
| `tests/mcp_client_send_test.rs` | root | 374 |
| `tests/mcp_intercept_test.rs` | root | 252 |
| `tests/mcp_scheduled_task_timer_test.rs` | root | 196 |
| `tests/mcp_startup_config_test.rs` | root | 138 |
| `tests/mcp_stdio_CLAUDE.md` | root | 58 |
| `tests/mcp_stdio_eof_test.rs` | root | 125 |
| `tests/mcp_stdio_test.rs` | root | 703 |
| `tests/mcp_stop_cleanup_test.rs` | root | 266 |
| `tests/min_stability_test.rs` | root | 180 |
| `tests/minimal_mock_test.rs` | root | 58 |
| `tests/mock_event_ids_test.rs` | root | 155 |
| `tests/mock_server_test.rs` | root | 66 |
| `tests/model_selection_endpoint_test.rs` | root | 103 |
| `tests/narrowing_cast_drift_test.rs` | root | 655 |
| `tests/no_protocol_is_hidden_from_the_model_test.rs` | root | 129 |
| `tests/non_interactive_run_limits_test.rs` | root | 342 |
| `tests/ollama_lock_is_a_noop_test.rs` | root | 138 |
| `tests/ollama_model_test.rs` | root | 932 |
| `tests/orphan_reaper_test.rs` | root | 417 |
| `tests/panic_is_logged_test.rs` | root | 140 |
| `tests/parameter_type_agreement_test.rs` | root | 159 |
| `tests/pcap_oracle_test.rs` | root | 387 |
| `tests/peer_handle_coverage_ratchet_test.rs` | root | 493 |
| `tests/pipe_test.rs` | root | 366 |
| `tests/placeholder_examples_test.rs` | root | 86 |
| `tests/privilege_requirement_test.rs` | root | 247 |
| `tests/privileged_port_availability_test.rs` | root | 132 |
| `tests/privileged_port_probe_test.rs` | root | 100 |
| `tests/prompt.rs` | root | 4 |
| `tests/prompt/mod.rs` | root | 1043 |
| `tests/prompt/snapshots/.gitignore` | root | 2 |
| `tests/prompt/snapshots/feedback_prompt_client.snap.md` | root | 523 |
| `tests/prompt/snapshots/feedback_prompt_server.snap.md` | root | 542 |
| `tests/prompt/snapshots/json_parse_retry_prompt.snap.md` | root | 33 |
| `tests/prompt/snapshots/network_event_prompt_proxy.snap.md` | root | 462 |
| `tests/prompt/snapshots/protocol_http_documentation.snap.md` | root | 6 |
| `tests/prompt/snapshots/protocol_ssh_documentation.snap.md` | root | 6 |
| `tests/prompt/snapshots/retry_mechanism_prompt.snap.md` | root | 1034 |
| `tests/prompt/snapshots/unknown_action_retry_prompt.snap.md` | root | 22 |
| `tests/prompt/snapshots/user_input_prompt.snap.md` | root | 989 |
| `tests/prompt/snapshots/user_input_prompt_after_docs.snap.md` | root | 1055 |
| `tests/prompt/snapshots/user_input_prompt_proxy_server.snap.md` | root | 576 |
| `tests/prompt/snapshots/user_input_prompt_without_scripting.snap.md` | root | 560 |
| `tests/prompt/snapshots/user_input_prompt_without_web_search.snap.md` | root | 976 |
| `tests/prompt/update_snapshots.sh` | root | 78 |
| `tests/prompt_growth_test.rs` | root | 250 |
| `tests/prompt_memory_verbatim_test.rs` | root | 52 |
| `tests/prompt_snapshots.rs` | root | 6 |
| `tests/prompt_snapshots/http_easy_test.rs` | root | 107 |
| `tests/prompt_snapshots/mod.rs` | root | 7 |
| `tests/prompt_snapshots/snapshots/http_easy_multiple_headers.snap.md` | root | 45 |
| `tests/prompt_snapshots/snapshots/http_easy_post_with_body.snap.md` | root | 45 |
| `tests/prompt_snapshots/snapshots/http_easy_simple_get.snap.md` | root | 38 |
| `tests/prompt_snapshots/snapshots/http_easy_with_query_string.snap.md` | root | 40 |
| `tests/prompt_snapshots/snapshots/http_easy_with_user_instruction.snap.md` | root | 40 |
| `tests/protocol_dependencies_test.rs` | root | 303 |
| `tests/protocol_docs_test.rs` | root | 30 |
| `tests/protocol_name_resolution_test.rs` | root | 71 |
| `tests/protocol_server_registry_test.rs` | root | 50 |
| `tests/protocol_startup_examples_test.rs` | root | 107 |
| `tests/protocol_startup_smoke_test.rs` | root | 799 |
| `tests/proxy_cert_cache_test.rs` | root | 93 |
| `tests/real_client_evidence_is_run_test.rs` | root | 356 |
| `tests/real_server_helper_test.rs` | root | 220 |
| `tests/recent_connections_test.rs` | root | 176 |
| `tests/recursive_decoder_depth_test.rs` | root | 1020 |
| `tests/reference_parser_test.rs` | root | 136 |
| `tests/request_only_declaration_test.rs` | root | 116 |
| `tests/rustls_provider_gate_test.rs` | root | 104 |
| `tests/scheduled_task_actions_test.rs` | root | 213 |
| `tests/scripting_detection_is_bounded_test.rs` | root | 124 |
| `tests/scripting_environment_test.rs` | root | 34 |
| `tests/scripting_executor_test.rs` | root | 588 |
| `tests/scripting_highlight_test.rs` | root | 25 |
| `tests/scripting_manager_test.rs` | root | 128 |
| `tests/scripting_resident_test.rs` | root | 494 |
| `tests/secret_redaction_test.rs` | root | 81 |
| `tests/send_first_is_refused_not_ignored_test.rs` | root | 313 |
| `tests/server.rs` | root | 11 |
| `tests/server/amqp/CLAUDE.md` | server_review | 122 |
| `tests/server/amqp/codec_test.rs` | server_review | 196 |
| `tests/server/amqp/connection_bounds_test.rs` | server_review | 205 |
| `tests/server/amqp/e2e_test.rs` | server_review | 366 |
| `tests/server/amqp/mod.rs` | server_review | 12 |
| `tests/server/amqp/peer_inject_test.rs` | server_review | 215 |
| `tests/server/amqp/wire_text_test.rs` | server_review | 194 |
| `tests/server/arp/CLAUDE.md` | server_review | 461 |
| `tests/server/arp/e2e_test.rs` | server_review | 369 |
| `tests/server/arp/frame_codec_test.rs` | server_review | 228 |
| `tests/server/arp/mod.rs` | server_review | 4 |
| `tests/server/beanstalkd/CLAUDE.md` | server_review | 56 |
| `tests/server/beanstalkd/answer_with_test.rs` | server_review | 58 |
| `tests/server/beanstalkd/common.rs` | server_review | 273 |
| `tests/server/beanstalkd/connection_bounds_test.rs` | server_review | 325 |
| `tests/server/beanstalkd/e2e_test.rs` | server_review | 200 |
| `tests/server/beanstalkd/llm_failure_test.rs` | server_review | 182 |
| `tests/server/beanstalkd/mod.rs` | server_review | 16 |
| `tests/server/beanstalkd/peer_inject_test.rs` | server_review | 115 |
| `tests/server/beanstalkd/real_client_test.rs` | server_review | 260 |
| `tests/server/beanstalkd/wire_test.rs` | server_review | 254 |
| `tests/server/bgp/CLAUDE.md` | server_review | 128 |
| `tests/server/bgp/connection_bounds_test.rs` | server_review | 189 |
| `tests/server/bgp/e2e_test.rs` | server_review | 663 |
| `tests/server/bgp/llm_failure_test.rs` | server_review | 158 |
| `tests/server/bgp/mod.rs` | server_review | 19 |
| `tests/server/bgp/peer_inject_test.rs` | server_review | 242 |
| `tests/server/bgp/static_default_test.rs` | server_review | 143 |
| `tests/server/bgp/test.rs` | server_review | 765 |
| `tests/server/bitcoin/CLAUDE.md` | server_review | 57 |
| `tests/server/bitcoin/connection_bounds_test.rs` | server_review | 197 |
| `tests/server/bitcoin/e2e_test.rs` | server_review | 644 |
| `tests/server/bitcoin/mod.rs` | server_review | 6 |
| `tests/server/bitcoin/peer_inject_test.rs` | server_review | 189 |
| `tests/server/bluetooth_ble/CLAUDE.md` | server_review | 362 |
| `tests/server/bluetooth_ble/e2e_test.rs` | server_review | 535 |
| `tests/server/bluetooth_ble/llm_failure_test.rs` | server_review | 219 |
| `tests/server/bluetooth_ble/mod.rs` | server_review | 8 |
| `tests/server/bluetooth_ble/read_default_value_test.rs` | server_review | 416 |
| `tests/server/bluetooth_ble/shared_peripheral_routing_test.rs` | server_review | 162 |
| `tests/server/bluetooth_ble_battery/CLAUDE.md` | server_review | 43 |
| `tests/server/bluetooth_ble_battery/characteristic_encoding_test.rs` | server_review | 33 |
| `tests/server/bluetooth_ble_battery/decision_tag_test.rs` | server_review | 132 |
| `tests/server/bluetooth_ble_battery/e2e_test.rs` | server_review | 118 |
| `tests/server/bluetooth_ble_battery/gatt_examples_test.rs` | server_review | 300 |
| `tests/server/bluetooth_ble_battery/mod.rs` | server_review | 8 |
| `tests/server/bluetooth_ble_beacon/CLAUDE.md` | server_review | 80 |
| `tests/server/bluetooth_ble_beacon/e2e_test.rs` | server_review | 183 |
| `tests/server/bluetooth_ble_beacon/llm_failure_test.rs` | server_review | 258 |
| `tests/server/bluetooth_ble_beacon/mod.rs` | server_review | 6 |
| `tests/server/bluetooth_ble_beacon/payload_test.rs` | server_review | 579 |
| `tests/server/bluetooth_ble_cycling/CLAUDE.md` | server_review | 20 |
| `tests/server/bluetooth_ble_cycling/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_cycling/gatt_examples_test.rs` | server_review | 319 |
| `tests/server/bluetooth_ble_cycling/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_data_stream/CLAUDE.md` | server_review | 20 |
| `tests/server/bluetooth_ble_data_stream/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_data_stream/gatt_examples_test.rs` | server_review | 225 |
| `tests/server/bluetooth_ble_data_stream/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_environmental/CLAUDE.md` | server_review | 19 |
| `tests/server/bluetooth_ble_environmental/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_environmental/gatt_examples_test.rs` | server_review | 343 |
| `tests/server/bluetooth_ble_environmental/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_file_transfer/CLAUDE.md` | server_review | 19 |
| `tests/server/bluetooth_ble_file_transfer/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_file_transfer/gatt_examples_test.rs` | server_review | 225 |
| `tests/server/bluetooth_ble_file_transfer/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_gamepad/CLAUDE.md` | server_review | 52 |
| `tests/server/bluetooth_ble_gamepad/e2e_test.rs` | server_review | 49 |
| `tests/server/bluetooth_ble_gamepad/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_gamepad/report_descriptor_test.rs` | server_review | 121 |
| `tests/server/bluetooth_ble_heart_rate/CLAUDE.md` | server_review | 26 |
| `tests/server/bluetooth_ble_heart_rate/characteristic_encoding_test.rs` | server_review | 49 |
| `tests/server/bluetooth_ble_heart_rate/decision_tag_test.rs` | server_review | 67 |
| `tests/server/bluetooth_ble_heart_rate/e2e_test.rs` | server_review | 112 |
| `tests/server/bluetooth_ble_heart_rate/gatt_examples_test.rs` | server_review | 327 |
| `tests/server/bluetooth_ble_heart_rate/mod.rs` | server_review | 8 |
| `tests/server/bluetooth_ble_keyboard/CLAUDE.md` | server_review | 60 |
| `tests/server/bluetooth_ble_keyboard/decision_tag_test.rs` | server_review | 68 |
| `tests/server/bluetooth_ble_keyboard/e2e_test.rs` | server_review | 49 |
| `tests/server/bluetooth_ble_keyboard/hid_descriptor.rs` | server_review | 319 |
| `tests/server/bluetooth_ble_keyboard/mod.rs` | server_review | 11 |
| `tests/server/bluetooth_ble_keyboard/report_descriptor_test.rs` | server_review | 184 |
| `tests/server/bluetooth_ble_mouse/CLAUDE.md` | server_review | 54 |
| `tests/server/bluetooth_ble_mouse/decision_tag_test.rs` | server_review | 67 |
| `tests/server/bluetooth_ble_mouse/e2e_test.rs` | server_review | 49 |
| `tests/server/bluetooth_ble_mouse/mod.rs` | server_review | 7 |
| `tests/server/bluetooth_ble_mouse/report_descriptor_test.rs` | server_review | 185 |
| `tests/server/bluetooth_ble_presenter/CLAUDE.md` | server_review | 51 |
| `tests/server/bluetooth_ble_presenter/e2e_test.rs` | server_review | 47 |
| `tests/server/bluetooth_ble_presenter/gatt_examples_test.rs` | server_review | 355 |
| `tests/server/bluetooth_ble_presenter/mod.rs` | server_review | 8 |
| `tests/server/bluetooth_ble_presenter/report_descriptor_test.rs` | server_review | 333 |
| `tests/server/bluetooth_ble_proximity/CLAUDE.md` | server_review | 48 |
| `tests/server/bluetooth_ble_proximity/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_proximity/gatt_layout_test.rs` | server_review | 210 |
| `tests/server/bluetooth_ble_proximity/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_remote/CLAUDE.md` | server_review | 69 |
| `tests/server/bluetooth_ble_remote/decision_tag_test.rs` | server_review | 68 |
| `tests/server/bluetooth_ble_remote/e2e_test.rs` | server_review | 59 |
| `tests/server/bluetooth_ble_remote/mod.rs` | server_review | 6 |
| `tests/server/bluetooth_ble_remote/report_descriptor_test.rs` | server_review | 254 |
| `tests/server/bluetooth_ble_running/CLAUDE.md` | server_review | 20 |
| `tests/server/bluetooth_ble_running/e2e_test.rs` | server_review | 48 |
| `tests/server/bluetooth_ble_running/gatt_examples_test.rs` | server_review | 320 |
| `tests/server/bluetooth_ble_running/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_thermometer/CLAUDE.md` | server_review | 20 |
| `tests/server/bluetooth_ble_thermometer/e2e_test.rs` | server_review | 50 |
| `tests/server/bluetooth_ble_thermometer/gatt_examples_test.rs` | server_review | 331 |
| `tests/server/bluetooth_ble_thermometer/mod.rs` | server_review | 4 |
| `tests/server/bluetooth_ble_weight_scale/CLAUDE.md` | server_review | 20 |
| `tests/server/bluetooth_ble_weight_scale/e2e_test.rs` | server_review | 49 |
| `tests/server/bluetooth_ble_weight_scale/gatt_examples_test.rs` | server_review | 337 |
| `tests/server/bluetooth_ble_weight_scale/mod.rs` | server_review | 4 |
| `tests/server/bolt/CLAUDE.md` | server_review | 53 |
| `tests/server/bolt/answer_with_test.rs` | server_review | 27 |
| `tests/server/bolt/common.rs` | server_review | 374 |
| `tests/server/bolt/connection_bounds_test.rs` | server_review | 305 |
| `tests/server/bolt/e2e_test.rs` | server_review | 179 |
| `tests/server/bolt/llm_failure_test.rs` | server_review | 186 |
| `tests/server/bolt/mod.rs` | server_review | 18 |
| `tests/server/bolt/packstream_test.rs` | server_review | 502 |
| `tests/server/bolt/peer_inject_test.rs` | server_review | 89 |
| `tests/server/bolt/real_client_test.rs` | server_review | 414 |
| `tests/server/bolt/state_machine_test.rs` | server_review | 545 |
| `tests/server/bootp/CLAUDE.md` | server_review | 250 |
| `tests/server/bootp/e2e_test.rs` | server_review | 426 |
| `tests/server/bootp/mod.rs` | server_review | 2 |
| `tests/server/can/CLAUDE.md` | server_review | 157 |
| `tests/server/can/e2e_test.rs` | server_review | 787 |
| `tests/server/can/frame_test.rs` | server_review | 660 |
| `tests/server/can/mod.rs` | server_review | 4 |
| `tests/server/cassandra/CLAUDE.md` | server_review | 286 |
| `tests/server/cassandra/e2e_test.rs` | server_review | 1003 |
| `tests/server/cassandra/llm_failure_test.rs` | server_review | 131 |
| `tests/server/cassandra/mod.rs` | server_review | 8 |
| `tests/server/cassandra/peer_inject_test.rs` | server_review | 228 |
| `tests/server/cassandra/protocol_error_test.rs` | server_review | 234 |
| `tests/server/cdp/CLAUDE.md` | server_review | 249 |
| `tests/server/cdp/codec_test.rs` | server_review | 823 |
| `tests/server/cdp/e2e_test.rs` | server_review | 358 |
| `tests/server/cdp/mod.rs` | server_review | 16 |
| `tests/server/coap/CLAUDE.md` | server_review | 236 |
| `tests/server/coap/answer_with_test.rs` | server_review | 38 |
| `tests/server/coap/bounds_test.rs` | server_review | 435 |
| `tests/server/coap/e2e_test.rs` | server_review | 542 |
| `tests/server/coap/llm_failure_test.rs` | server_review | 180 |
| `tests/server/coap/mod.rs` | server_review | 10 |
| `tests/server/coap/real_client_test.rs` | server_review | 234 |
| `tests/server/couchdb/CLAUDE.md` | server_review | 140 |
| `tests/server/couchdb/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/couchdb/e2e_test.rs` | server_review | 583 |
| `tests/server/couchdb/llm_failure_test.rs` | server_review | 91 |
| `tests/server/couchdb/mod.rs` | server_review | 11 |
| `tests/server/couchdb/refusal_test.rs` | server_review | 119 |
| `tests/server/datalink/CLAUDE.md` | server_review | 107 |
| `tests/server/datalink/e2e_test.rs` | server_review | 347 |
| `tests/server/datalink/mod.rs` | server_review | 5 |
| `tests/server/datalink/test.rs` | server_review | 148 |
| `tests/server/db2/CLAUDE.md` | server_review | 68 |
| `tests/server/db2/drda_test.rs` | server_review | 118 |
| `tests/server/db2/e2e_test.rs` | server_review | 171 |
| `tests/server/db2/mod.rs` | server_review | 4 |
| `tests/server/db2/peer_inject_test.rs` | server_review | 177 |
| `tests/server/dc/CLAUDE.md` | server_review | 295 |
| `tests/server/dc/connection_bounds_test.rs` | server_review | 264 |
| `tests/server/dc/llm_failure_test.rs` | server_review | 149 |
| `tests/server/dc/mod.rs` | server_review | 10 |
| `tests/server/dc/peer_inject_test.rs` | server_review | 179 |
| `tests/server/dc/test.rs` | server_review | 738 |
| `tests/server/dhcp/CLAUDE.md` | server_review | 71 |
| `tests/server/dhcp/mod.rs` | server_review | 2 |
| `tests/server/dhcp/test.rs` | server_review | 531 |
| `tests/server/dhcpv6/CLAUDE.md` | server_review | 115 |
| `tests/server/dhcpv6/e2e_test.rs` | server_review | 1058 |
| `tests/server/dhcpv6/mod.rs` | server_review | 1 |
| `tests/server/dict/CLAUDE.md` | server_review | 49 |
| `tests/server/dict/common.rs` | server_review | 199 |
| `tests/server/dict/connection_bounds_test.rs` | server_review | 254 |
| `tests/server/dict/e2e_test.rs` | server_review | 172 |
| `tests/server/dict/llm_failure_test.rs` | server_review | 145 |
| `tests/server/dict/mod.rs` | server_review | 14 |
| `tests/server/dict/peer_inject_test.rs` | server_review | 82 |
| `tests/server/dict/real_client_test.rs` | server_review | 284 |
| `tests/server/dict/wire_test.rs` | server_review | 176 |
| `tests/server/dns/CLAUDE.md` | server_review | 494 |
| `tests/server/dns/bounds_test.rs` | server_review | 355 |
| `tests/server/dns/dig_test.rs` | server_review | 351 |
| `tests/server/dns/kdig_test.rs` | server_review | 279 |
| `tests/server/dns/llm_failure_test.rs` | server_review | 245 |
| `tests/server/dns/mod.rs` | server_review | 10 |
| `tests/server/dns/test.rs` | server_review | 464 |
| `tests/server/docker/CLAUDE.md` | server_review | 42 |
| `tests/server/docker/api_test.rs` | server_review | 379 |
| `tests/server/docker/connection_bounds_test.rs` | server_review | 75 |
| `tests/server/docker/e2e_test.rs` | server_review | 223 |
| `tests/server/docker/llm_failure_test.rs` | server_review | 79 |
| `tests/server/docker/mod.rs` | server_review | 16 |
| `tests/server/docker/real_client_test.rs` | server_review | 401 |
| `tests/server/doh/CLAUDE.md` | server_review | 344 |
| `tests/server/doh/connection_bounds_test.rs` | server_review | 419 |
| `tests/server/doh/e2e_test.rs` | server_review | 397 |
| `tests/server/doh/llm_failure_test.rs` | server_review | 129 |
| `tests/server/doh/mod.rs` | server_review | 8 |
| `tests/server/doh/real_client_test.rs` | server_review | 204 |
| `tests/server/dot/CLAUDE.md` | server_review | 268 |
| `tests/server/dot/connection_bounds_test.rs` | server_review | 216 |
| `tests/server/dot/e2e_test.rs` | server_review | 291 |
| `tests/server/dot/llm_failure_test.rs` | server_review | 130 |
| `tests/server/dot/mod.rs` | server_review | 8 |
| `tests/server/dot/real_client_test.rs` | server_review | 198 |
| `tests/server/dynamo/CLAUDE.md` | server_review | 236 |
| `tests/server/dynamo/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/dynamo/e2e_aws_sdk_test.rs` | server_review | 822 |
| `tests/server/dynamo/e2e_test.rs` | server_review | 499 |
| `tests/server/dynamo/mod.rs` | server_review | 9 |
| `tests/server/dynamo/real_client_test.rs` | server_review | 235 |
| `tests/server/eapol/CLAUDE.md` | server_review | 158 |
| `tests/server/eapol/codec_test.rs` | server_review | 559 |
| `tests/server/eapol/e2e_test.rs` | server_review | 1100 |
| `tests/server/eapol/mod.rs` | server_review | 21 |
| `tests/server/elasticsearch/CLAUDE.md` | server_review | 280 |
| `tests/server/elasticsearch/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/elasticsearch/e2e_test.rs` | server_review | 685 |
| `tests/server/elasticsearch/llm_failure_test.rs` | server_review | 96 |
| `tests/server/elasticsearch/mod.rs` | server_review | 9 |
| `tests/server/elasticsearch/refusal_test.rs` | server_review | 172 |
| `tests/server/etcd/CLAUDE.md` | server_review | 112 |
| `tests/server/etcd/connection_tracking_test.rs` | server_review | 118 |
| `tests/server/etcd/e2e_test.rs` | server_review | 320 |
| `tests/server/etcd/llm_failure_test.rs` | server_review | 191 |
| `tests/server/etcd/mod.rs` | server_review | 12 |
| `tests/server/etcd/real_client_test.rs` | server_review | 256 |
| `tests/server/etcd/unanswered_request_test.rs` | server_review | 164 |
| `tests/server/finger/CLAUDE.md` | server_review | 139 |
| `tests/server/finger/connection_bounds_test.rs` | server_review | 169 |
| `tests/server/finger/e2e_test.rs` | server_review | 296 |
| `tests/server/finger/mod.rs` | server_review | 4 |
| `tests/server/ftp/CLAUDE.md` | server_review | 98 |
| `tests/server/ftp/connection_bounds_test.rs` | server_review | 412 |
| `tests/server/ftp/decision_tag_test.rs` | server_review | 208 |
| `tests/server/ftp/llm_failure_test.rs` | server_review | 83 |
| `tests/server/ftp/mod.rs` | server_review | 12 |
| `tests/server/ftp/one_reply_test.rs` | server_review | 97 |
| `tests/server/ftp/peer_injection_test.rs` | server_review | 165 |
| `tests/server/ftp/test.rs` | server_review | 480 |
| `tests/server/gearman/CLAUDE.md` | server_review | 53 |
| `tests/server/gearman/common.rs` | server_review | 298 |
| `tests/server/gearman/connection_bounds_test.rs` | server_review | 244 |
| `tests/server/gearman/e2e_test.rs` | server_review | 181 |
| `tests/server/gearman/llm_failure_test.rs` | server_review | 196 |
| `tests/server/gearman/mod.rs` | server_review | 14 |
| `tests/server/gearman/peer_inject_test.rs` | server_review | 82 |
| `tests/server/gearman/real_client_test.rs` | server_review | 265 |
| `tests/server/gearman/wire_test.rs` | server_review | 189 |
| `tests/server/gemini/CLAUDE.md` | server_review | 59 |
| `tests/server/gemini/answer_with_test.rs` | server_review | 71 |
| `tests/server/gemini/common.rs` | server_review | 359 |
| `tests/server/gemini/connection_bounds_test.rs` | server_review | 228 |
| `tests/server/gemini/e2e_test.rs` | server_review | 96 |
| `tests/server/gemini/llm_failure_test.rs` | server_review | 105 |
| `tests/server/gemini/mod.rs` | server_review | 16 |
| `tests/server/gemini/peer_inject_test.rs` | server_review | 84 |
| `tests/server/gemini/real_client_test.rs` | server_review | 222 |
| `tests/server/gemini/wire_test.rs` | server_review | 242 |
| `tests/server/git/CLAUDE.md` | server_review | 214 |
| `tests/server/git/connection_bounds_test.rs` | server_review | 179 |
| `tests/server/git/e2e_test.rs` | server_review | 742 |
| `tests/server/git/mod.rs` | server_review | 6 |
| `tests/server/gopher/CLAUDE.md` | server_review | 102 |
| `tests/server/gopher/connection_bounds_test.rs` | server_review | 162 |
| `tests/server/gopher/decision_tag_test.rs` | server_review | 147 |
| `tests/server/gopher/e2e_test.rs` | server_review | 465 |
| `tests/server/gopher/mod.rs` | server_review | 6 |
| `tests/server/grpc/CLAUDE.md` | server_review | 278 |
| `tests/server/grpc/connection_bounds_test.rs` | server_review | 201 |
| `tests/server/grpc/e2e_test.rs` | server_review | 695 |
| `tests/server/grpc/llm_failure_test.rs` | server_review | 361 |
| `tests/server/grpc/mod.rs` | server_review | 10 |
| `tests/server/grpc/real_client_test.rs` | server_review | 266 |
| `tests/server/gtp/CLAUDE.md` | server_review | 187 |
| `tests/server/gtp/codec_test.rs` | server_review | 491 |
| `tests/server/gtp/e2e_test.rs` | server_review | 1002 |
| `tests/server/gtp/mod.rs` | server_review | 7 |
| `tests/server/helpers.rs` | server_review | 5 |
| `tests/server/hls/CLAUDE.md` | server_review | 68 |
| `tests/server/hls/connection_bounds_test.rs` | server_review | 170 |
| `tests/server/hls/curl_test.rs` | server_review | 120 |
| `tests/server/hls/e2e_test.rs` | server_review | 384 |
| `tests/server/hls/inbound_limit_test.rs` | server_review | 138 |
| `tests/server/hls/mod.rs` | server_review | 8 |
| `tests/server/hsrp/CLAUDE.md` | server_review | 197 |
| `tests/server/hsrp/codec_test.rs` | server_review | 106 |
| `tests/server/hsrp/e2e_test.rs` | server_review | 488 |
| `tests/server/hsrp/mod.rs` | server_review | 12 |
| `tests/server/http/CLAUDE.md` | server_review | 383 |
| `tests/server/http/CLAUDE_SCHEDULED_TASKS.md` | server_review | 337 |
| `tests/server/http/connection_bounds_test.rs` | server_review | 48 |
| `tests/server/http/decision_tag_test.rs` | server_review | 168 |
| `tests/server/http/e2e_scheduled_tasks_test.rs` | server_review | 440 |
| `tests/server/http/failure_semantics_test.rs` | server_review | 220 |
| `tests/server/http/mod.rs` | server_review | 16 |
| `tests/server/http/real_client_test.rs` | server_review | 235 |
| `tests/server/http/test.rs` | server_review | 703 |
| `tests/server/http2/CLAUDE.md` | server_review | 336 |
| `tests/server/http2/connection_bounds_test.rs` | server_review | 362 |
| `tests/server/http2/e2e_test.rs` | server_review | 445 |
| `tests/server/http2/failure_semantics_test.rs` | server_review | 137 |
| `tests/server/http2/mod.rs` | server_review | 13 |
| `tests/server/http2/stream_bounds_test.rs` | server_review | 510 |
| `tests/server/icmp/CLAUDE.md` | server_review | 196 |
| `tests/server/icmp/e2e_test.rs` | server_review | 332 |
| `tests/server/icmp/mod.rs` | server_review | 4 |
| `tests/server/icmp/packet_codec_test.rs` | server_review | 661 |
| `tests/server/ident/CLAUDE.md` | server_review | 120 |
| `tests/server/ident/connection_bounds_test.rs` | server_review | 166 |
| `tests/server/ident/e2e_test.rs` | server_review | 282 |
| `tests/server/ident/mod.rs` | server_review | 4 |
| `tests/server/igmp/CLAUDE.md` | server_review | 319 |
| `tests/server/igmp/e2e_test.rs` | server_review | 498 |
| `tests/server/igmp/mod.rs` | server_review | 4 |
| `tests/server/igmp/packet_codec_test.rs` | server_review | 501 |
| `tests/server/imap/CLAUDE.md` | server_review | 236 |
| `tests/server/imap/answer_with_test.rs` | server_review | 326 |
| `tests/server/imap/connection_bounds_test.rs` | server_review | 215 |
| `tests/server/imap/e2e_client_test.rs` | server_review | 998 |
| `tests/server/imap/e2e_client_test_README.md` | server_review | 200 |
| `tests/server/imap/line_limit_test.rs` | server_review | 182 |
| `tests/server/imap/literal_framing_test.rs` | server_review | 163 |
| `tests/server/imap/llm_failure_test.rs` | server_review | 167 |
| `tests/server/imap/mod.rs` | server_review | 19 |
| `tests/server/imap/peer_inject_test.rs` | server_review | 169 |
| `tests/server/imap/real_client_test.rs` | server_review | 467 |
| `tests/server/imap/test.rs` | server_review | 1085 |
| `tests/server/ipp/CLAUDE.md` | server_review | 82 |
| `tests/server/ipp/attribute_range_test.rs` | server_review | 140 |
| `tests/server/ipp/body_limit_test.rs` | server_review | 416 |
| `tests/server/ipp/connection_bounds_test.rs` | server_review | 174 |
| `tests/server/ipp/mod.rs` | server_review | 14 |
| `tests/server/ipp/status_range_test.rs` | server_review | 59 |
| `tests/server/ipp/test.rs` | server_review | 602 |
| `tests/server/ipsec/CLAUDE.md` | server_review | 412 |
| `tests/server/ipsec/e2e_test.rs` | server_review | 571 |
| `tests/server/ipsec/mod.rs` | server_review | 2 |
| `tests/server/irc/CLAUDE.md` | server_review | 331 |
| `tests/server/irc/connection_bounds_test.rs` | server_review | 264 |
| `tests/server/irc/decision_tag_test.rs` | server_review | 170 |
| `tests/server/irc/e2e_test.rs` | server_review | 537 |
| `tests/server/irc/framing_test.rs` | server_review | 218 |
| `tests/server/irc/llm_failure_test.rs` | server_review | 112 |
| `tests/server/irc/mod.rs` | server_review | 12 |
| `tests/server/irc/peer_inject_test.rs` | server_review | 173 |
| `tests/server/isis/CLAUDE.md` | server_review | 277 |
| `tests/server/isis/e2e_test.rs` | server_review | 303 |
| `tests/server/isis/hello_field_offsets_test.rs` | server_review | 65 |
| `tests/server/isis/mod.rs` | server_review | 7 |
| `tests/server/jsonrpc/CLAUDE.md` | server_review | 252 |
| `tests/server/jsonrpc/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/jsonrpc/e2e_test.rs` | server_review | 448 |
| `tests/server/jsonrpc/llm_failure_test.rs` | server_review | 186 |
| `tests/server/jsonrpc/mod.rs` | server_review | 9 |
| `tests/server/kafka/CLAUDE.md` | server_review | 184 |
| `tests/server/kafka/connection_task_cleanup_test.rs` | server_review | 152 |
| `tests/server/kafka/e2e_test.rs` | server_review | 643 |
| `tests/server/kafka/mod.rs` | server_review | 10 |
| `tests/server/kafka/peer_inject_test.rs` | server_review | 227 |
| `tests/server/kafka/real_client_test.rs` | server_review | 326 |
| `tests/server/kubernetes/CLAUDE.md` | server_review | 108 |
| `tests/server/kubernetes/connection_bounds_test.rs` | server_review | 166 |
| `tests/server/kubernetes/e2e_test.rs` | server_review | 908 |
| `tests/server/kubernetes/guard_test.rs` | server_review | 267 |
| `tests/server/kubernetes/mod.rs` | server_review | 10 |
| `tests/server/ldap/CLAUDE.md` | server_review | 211 |
| `tests/server/ldap/connection_bounds_test.rs` | server_review | 329 |
| `tests/server/ldap/e2e_test.rs` | server_review | 660 |
| `tests/server/ldap/llm_failure_test.rs` | server_review | 101 |
| `tests/server/ldap/mod.rs` | server_review | 11 |
| `tests/server/ldap/real_client_test.rs` | server_review | 493 |
| `tests/server/ldap/result_code_range_test.rs` | server_review | 126 |
| `tests/server/lldp/CLAUDE.md` | server_review | 153 |
| `tests/server/lldp/codec_test.rs` | server_review | 856 |
| `tests/server/lldp/e2e_test.rs` | server_review | 649 |
| `tests/server/lldp/mod.rs` | server_review | 6 |
| `tests/server/llmnr/CLAUDE.md` | server_review | 142 |
| `tests/server/llmnr/connection_bounds_test.rs` | server_review | 185 |
| `tests/server/llmnr/e2e_test.rs` | server_review | 323 |
| `tests/server/llmnr/mod.rs` | server_review | 4 |
| `tests/server/m3ua/CLAUDE.md` | server_review | 139 |
| `tests/server/m3ua/codec_test.rs` | server_review | 552 |
| `tests/server/m3ua/e2e_test.rs` | server_review | 509 |
| `tests/server/m3ua/mod.rs` | server_review | 10 |
| `tests/server/m3ua/transport_test.rs` | server_review | 163 |
| `tests/server/maven/CLAUDE.md` | server_review | 258 |
| `tests/server/maven/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/maven/e2e_test.rs` | server_review | 895 |
| `tests/server/maven/llm_failure_test.rs` | server_review | 142 |
| `tests/server/maven/mod.rs` | server_review | 9 |
| `tests/server/mcp/CLAUDE.md` | server_review | 277 |
| `tests/server/mcp/e2e_test.rs` | server_review | 958 |
| `tests/server/mcp/error_code_range_test.rs` | server_review | 73 |
| `tests/server/mcp/inbound_limit_test.rs` | server_review | 156 |
| `tests/server/mcp/llm_failure_test.rs` | server_review | 91 |
| `tests/server/mcp/mod.rs` | server_review | 12 |
| `tests/server/mdns/CLAUDE.md` | server_review | 203 |
| `tests/server/mdns/llm_failure_test.rs` | server_review | 106 |
| `tests/server/mdns/mod.rs` | server_review | 4 |
| `tests/server/mdns/test.rs` | server_review | 351 |
| `tests/server/memcached/CLAUDE.md` | server_review | 117 |
| `tests/server/memcached/answer_with_test.rs` | server_review | 126 |
| `tests/server/memcached/connection_bounds_test.rs` | server_review | 160 |
| `tests/server/memcached/e2e_test.rs` | server_review | 615 |
| `tests/server/memcached/inbound_limit_test.rs` | server_review | 133 |
| `tests/server/memcached/llm_failure_test.rs` | server_review | 79 |
| `tests/server/memcached/mod.rs` | server_review | 18 |
| `tests/server/memcached/peer_inject_test.rs` | server_review | 146 |
| `tests/server/memcached/real_client_test.rs` | server_review | 214 |
| `tests/server/mercurial/CLAUDE.md` | server_review | 395 |
| `tests/server/mercurial/connection_bounds_test.rs` | server_review | 175 |
| `tests/server/mercurial/e2e_test.rs` | server_review | 490 |
| `tests/server/mercurial/mod.rs` | server_review | 8 |
| `tests/server/mercurial/real_client_test.rs` | server_review | 180 |
| `tests/server/mod.rs` | server_review | 351 |
| `tests/server/modbus/CLAUDE.md` | server_review | 209 |
| `tests/server/modbus/answer_with_test.rs` | server_review | 96 |
| `tests/server/modbus/bounds_test.rs` | server_review | 561 |
| `tests/server/modbus/connection_bounds_test.rs` | server_review | 182 |
| `tests/server/modbus/e2e_test.rs` | server_review | 716 |
| `tests/server/modbus/llm_failure_test.rs` | server_review | 301 |
| `tests/server/modbus/mod.rs` | server_review | 16 |
| `tests/server/modbus/pcap_oracle_test.rs` | server_review | 180 |
| `tests/server/modbus/peer_inject_test.rs` | server_review | 166 |
| `tests/server/modbus/real_client_test.rs` | server_review | 505 |
| `tests/server/mongodb/CLAUDE.md` | server_review | 483 |
| `tests/server/mongodb/bson_depth_test.rs` | server_review | 296 |
| `tests/server/mongodb/connection_bounds_test.rs` | server_review | 386 |
| `tests/server/mongodb/document_sequence_test.rs` | server_review | 426 |
| `tests/server/mongodb/e2e_test.rs` | server_review | 279 |
| `tests/server/mongodb/llm_failure_test.rs` | server_review | 123 |
| `tests/server/mongodb/mod.rs` | server_review | 21 |
| `tests/server/mongodb/peer_inject_test.rs` | server_review | 220 |
| `tests/server/mongodb/real_client_test.rs` | server_review | 195 |
| `tests/server/mongodb/required_fields_test.rs` | server_review | 95 |
| `tests/server/mqtt/CLAUDE.md` | server_review | 150 |
| `tests/server/mqtt/answer_with_test.rs` | server_review | 125 |
| `tests/server/mqtt/connection_bounds_test.rs` | server_review | 411 |
| `tests/server/mqtt/e2e_test.rs` | server_review | 292 |
| `tests/server/mqtt/llm_failure_test.rs` | server_review | 315 |
| `tests/server/mqtt/mod.rs` | server_review | 15 |
| `tests/server/mqtt/peer_inject_test.rs` | server_review | 173 |
| `tests/server/mqtt/real_client_test.rs` | server_review | 276 |
| `tests/server/mssql/CLAUDE.md` | server_review | 141 |
| `tests/server/mssql/hostile_input_test.rs` | server_review | 192 |
| `tests/server/mssql/llm_failure_test.rs` | server_review | 210 |
| `tests/server/mssql/mod.rs` | server_review | 12 |
| `tests/server/mssql/peer_inject_test.rs` | server_review | 222 |
| `tests/server/mssql/severity_range_test.rs` | server_review | 100 |
| `tests/server/mssql/test.rs` | server_review | 319 |
| `tests/server/mysql/CLAUDE.md` | server_review | 288 |
| `tests/server/mysql/connection_stats_test.rs` | server_review | 141 |
| `tests/server/mysql/llm_failure_test.rs` | server_review | 98 |
| `tests/server/mysql/mod.rs` | server_review | 14 |
| `tests/server/mysql/one_answer_per_query_test.rs` | server_review | 95 |
| `tests/server/mysql/packet_limit_test.rs` | server_review | 341 |
| `tests/server/mysql/prepared_statement_test.rs` | server_review | 267 |
| `tests/server/mysql/real_client_test.rs` | server_review | 336 |
| `tests/server/mysql/test.rs` | server_review | 306 |
| `tests/server/named_pipe/CLAUDE.md` | server_review | 67 |
| `tests/server/named_pipe/e2e_test.rs` | server_review | 200 |
| `tests/server/named_pipe/mod.rs` | server_review | 6 |
| `tests/server/nats/CLAUDE.md` | server_review | 130 |
| `tests/server/nats/connection_bounds_test.rs` | server_review | 244 |
| `tests/server/nats/e2e_test.rs` | server_review | 584 |
| `tests/server/nats/inbound_limit_test.rs` | server_review | 177 |
| `tests/server/nats/mod.rs` | server_review | 6 |
| `tests/server/ndp/CLAUDE.md` | server_review | 148 |
| `tests/server/ndp/codec_test.rs` | server_review | 1346 |
| `tests/server/ndp/e2e_test.rs` | server_review | 890 |
| `tests/server/ndp/mod.rs` | server_review | 6 |
| `tests/server/netbios_ns/CLAUDE.md` | server_review | 163 |
| `tests/server/netbios_ns/e2e_test.rs` | server_review | 942 |
| `tests/server/netbios_ns/mod.rs` | server_review | 2 |
| `tests/server/nfc/CLAUDE.md` | server_review | 106 |
| `tests/server/nfc/connection_bounds_test.rs` | server_review | 247 |
| `tests/server/nfc/e2e_test.rs` | server_review | 311 |
| `tests/server/nfc/mod.rs` | server_review | 5 |
| `tests/server/nfs/CLAUDE.md` | server_review | 114 |
| `tests/server/nfs/dos_guard_test.rs` | server_review | 240 |
| `tests/server/nfs/llm_failure_test.rs` | server_review | 159 |
| `tests/server/nfs/mod.rs` | server_review | 8 |
| `tests/server/nfs/test.rs` | server_review | 745 |
| `tests/server/nntp/CLAUDE.md` | server_review | 311 |
| `tests/server/nntp/answer_with_test.rs` | server_review | 125 |
| `tests/server/nntp/connection_bounds_test.rs` | server_review | 398 |
| `tests/server/nntp/e2e_test.rs` | server_review | 364 |
| `tests/server/nntp/line_ending_test.rs` | server_review | 40 |
| `tests/server/nntp/line_limit_test.rs` | server_review | 181 |
| `tests/server/nntp/llm_failure_test.rs` | server_review | 310 |
| `tests/server/nntp/mod.rs` | server_review | 14 |
| `tests/server/nntp/peer_inject_test.rs` | server_review | 181 |
| `tests/server/nostr/CLAUDE.md` | server_review | 67 |
| `tests/server/nostr/answer_with_test.rs` | server_review | 97 |
| `tests/server/nostr/common.rs` | server_review | 371 |
| `tests/server/nostr/connection_bounds_test.rs` | server_review | 339 |
| `tests/server/nostr/e2e_test.rs` | server_review | 150 |
| `tests/server/nostr/llm_failure_test.rs` | server_review | 161 |
| `tests/server/nostr/mod.rs` | server_review | 16 |
| `tests/server/nostr/peer_inject_test.rs` | server_review | 117 |
| `tests/server/nostr/real_client_test.rs` | server_review | 468 |
| `tests/server/nostr/wire_test.rs` | server_review | 393 |
| `tests/server/npm/CLAUDE.md` | server_review | 168 |
| `tests/server/npm/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/npm/decision_tag_test.rs` | server_review | 149 |
| `tests/server/npm/e2e_test.rs` | server_review | 726 |
| `tests/server/npm/mod.rs` | server_review | 14 |
| `tests/server/npm/status_range_test.rs` | server_review | 60 |
| `tests/server/nsq/CLAUDE.md` | server_review | 61 |
| `tests/server/nsq/answer_with_test.rs` | server_review | 88 |
| `tests/server/nsq/common.rs` | server_review | 285 |
| `tests/server/nsq/connection_bounds_test.rs` | server_review | 398 |
| `tests/server/nsq/e2e_test.rs` | server_review | 205 |
| `tests/server/nsq/llm_failure_test.rs` | server_review | 217 |
| `tests/server/nsq/mod.rs` | server_review | 16 |
| `tests/server/nsq/peer_inject_test.rs` | server_review | 93 |
| `tests/server/nsq/real_client_test.rs` | server_review | 246 |
| `tests/server/nsq/wire_test.rs` | server_review | 373 |
| `tests/server/ntp/CLAUDE.md` | server_review | 166 |
| `tests/server/ntp/decision_tag_test.rs` | server_review | 125 |
| `tests/server/ntp/llm_failure_test.rs` | server_review | 163 |
| `tests/server/ntp/mod.rs` | server_review | 8 |
| `tests/server/ntp/static_default_test.rs` | server_review | 110 |
| `tests/server/ntp/test.rs` | server_review | 483 |
| `tests/server/oauth2/CLAUDE.md` | server_review | 246 |
| `tests/server/oauth2/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/oauth2/e2e_test.rs` | server_review | 571 |
| `tests/server/oauth2/hardening_test.rs` | server_review | 149 |
| `tests/server/oauth2/llm_failure_test.rs` | server_review | 278 |
| `tests/server/oauth2/mod.rs` | server_review | 9 |
| `tests/server/oci_registry/CLAUDE.md` | server_review | 175 |
| `tests/server/oci_registry/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/oci_registry/digest_test.rs` | server_review | 327 |
| `tests/server/oci_registry/e2e_test.rs` | server_review | 782 |
| `tests/server/oci_registry/mod.rs` | server_review | 15 |
| `tests/server/ollama/CLAUDE.md` | server_review | 227 |
| `tests/server/ollama/connection_bounds_test.rs` | server_review | 258 |
| `tests/server/ollama/e2e_test.rs` | server_review | 394 |
| `tests/server/ollama/embeddings_test.rs` | server_review | 125 |
| `tests/server/ollama/mod.rs` | server_review | 8 |
| `tests/server/ollama/real_client_test.rs` | server_review | 276 |
| `tests/server/ollama/refusal_status_test.rs` | server_review | 103 |
| `tests/server/openai/CLAUDE.md` | server_review | 200 |
| `tests/server/openai/connection_bounds_test.rs` | server_review | 261 |
| `tests/server/openai/e2e_test.rs` | server_review | 654 |
| `tests/server/openai/mod.rs` | server_review | 11 |
| `tests/server/openai/request_limits_test.rs` | server_review | 184 |
| `tests/server/openai/status_range_test.rs` | server_review | 65 |
| `tests/server/openapi/CLAUDE.md` | server_review | 213 |
| `tests/server/openapi/body_limit_test.rs` | server_review | 116 |
| `tests/server/openapi/connection_bounds_test.rs` | server_review | 48 |
| `tests/server/openapi/e2e_route_matching_test.rs` | server_review | 295 |
| `tests/server/openapi/e2e_test.rs` | server_review | 567 |
| `tests/server/openapi/fail_closed_test.rs` | server_review | 98 |
| `tests/server/openapi/mod.rs` | server_review | 19 |
| `tests/server/openapi/status_range_test.rs` | server_review | 74 |
| `tests/server/openapi/test_spec.yaml` | server_review | 172 |
| `tests/server/openid/CLAUDE.md` | server_review | 192 |
| `tests/server/openid/configuration_test.rs` | server_review | 140 |
| `tests/server/openid/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/openid/e2e_test.rs` | server_review | 539 |
| `tests/server/openid/mod.rs` | server_review | 7 |
| `tests/server/openvpn/CLAUDE.md` | server_review | 147 |
| `tests/server/openvpn/codec_test.rs` | server_review | 629 |
| `tests/server/openvpn/e2e_test.rs` | server_review | 767 |
| `tests/server/openvpn/mod.rs` | server_review | 7 |
| `tests/server/openvpn/wire.rs` | server_review | 219 |
| `tests/server/ospf/CLAUDE.md` | server_review | 123 |
| `tests/server/ospf/e2e_test.rs` | server_review | 905 |
| `tests/server/ospf/mod.rs` | server_review | 4 |
| `tests/server/otlp/CLAUDE.md` | server_review | 60 |
| `tests/server/otlp/answer_with_test.rs` | server_review | 39 |
| `tests/server/otlp/codec_test.rs` | server_review | 340 |
| `tests/server/otlp/common.rs` | server_review | 289 |
| `tests/server/otlp/connection_bounds_test.rs` | server_review | 114 |
| `tests/server/otlp/e2e_test.rs` | server_review | 170 |
| `tests/server/otlp/llm_failure_test.rs` | server_review | 126 |
| `tests/server/otlp/mod.rs` | server_review | 14 |
| `tests/server/otlp/real_client_test.rs` | server_review | 315 |
| `tests/server/pop3/CLAUDE.md` | server_review | 149 |
| `tests/server/pop3/answer_with_test.rs` | server_review | 188 |
| `tests/server/pop3/connection_bounds_test.rs` | server_review | 395 |
| `tests/server/pop3/decision_tag_test.rs` | server_review | 219 |
| `tests/server/pop3/line_limit_test.rs` | server_review | 182 |
| `tests/server/pop3/llm_failure_test.rs` | server_review | 158 |
| `tests/server/pop3/mod.rs` | server_review | 14 |
| `tests/server/pop3/peer_inject_test.rs` | server_review | 161 |
| `tests/server/pop3/test.rs` | server_review | 448 |
| `tests/server/postgresql/CLAUDE.md` | server_review | 147 |
| `tests/server/postgresql/decoder_panic_test.rs` | server_review | 277 |
| `tests/server/postgresql/extended_query_test.rs` | server_review | 217 |
| `tests/server/postgresql/llm_failure_test.rs` | server_review | 93 |
| `tests/server/postgresql/mod.rs` | server_review | 12 |
| `tests/server/postgresql/one_answer_per_query_test.rs` | server_review | 99 |
| `tests/server/postgresql/real_client_test.rs` | server_review | 301 |
| `tests/server/postgresql/test.rs` | server_review | 430 |
| `tests/server/prometheus/CLAUDE.md` | server_review | 43 |
| `tests/server/prometheus/connection_bounds_test.rs` | server_review | 110 |
| `tests/server/prometheus/e2e_test.rs` | server_review | 250 |
| `tests/server/prometheus/exposition_test.rs` | server_review | 258 |
| `tests/server/prometheus/llm_failure_test.rs` | server_review | 83 |
| `tests/server/prometheus/mod.rs` | server_review | 16 |
| `tests/server/prometheus/real_client_test.rs` | server_review | 456 |
| `tests/server/proxy/CLAUDE.md` | server_review | 296 |
| `tests/server/proxy/connection_bounds_test.rs` | server_review | 172 |
| `tests/server/proxy/e2e_test.rs` | server_review | 589 |
| `tests/server/proxy/llm_failure_test.rs` | server_review | 135 |
| `tests/server/proxy/mod.rs` | server_review | 16 |
| `tests/server/proxy/status_range_test.rs` | server_review | 82 |
| `tests/server/proxy/test.rs` | server_review | 749 |
| `tests/server/pty/CLAUDE.md` | server_review | 58 |
| `tests/server/pty/e2e_test.rs` | server_review | 126 |
| `tests/server/pty/mod.rs` | server_review | 7 |
| `tests/server/pypi/CLAUDE.md` | server_review | 158 |
| `tests/server/pypi/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/pypi/e2e_test.rs` | server_review | 442 |
| `tests/server/pypi/e2e_test_mocked.rs` | server_review | 288 |
| `tests/server/pypi/mod.rs` | server_review | 11 |
| `tests/server/quic/CLAUDE.md` | server_review | 196 |
| `tests/server/quic/e2e_test.rs` | server_review | 692 |
| `tests/server/quic/llm_failure_test.rs` | server_review | 182 |
| `tests/server/quic/mod.rs` | server_review | 7 |
| `tests/server/radius/CLAUDE.md` | server_review | 145 |
| `tests/server/radius/e2e_test.rs` | server_review | 665 |
| `tests/server/radius/mod.rs` | server_review | 5 |
| `tests/server/radius/real_client_test.rs` | server_review | 324 |
| `tests/server/rawip/CLAUDE.md` | server_review | 138 |
| `tests/server/rawip/e2e_test.rs` | server_review | 895 |
| `tests/server/rawip/mod.rs` | server_review | 4 |
| `tests/server/rdp/CLAUDE.md` | server_review | 44 |
| `tests/server/rdp/connection_bounds_test.rs` | server_review | 275 |
| `tests/server/rdp/mod.rs` | server_review | 8 |
| `tests/server/rdp/peer_inject_test.rs` | server_review | 265 |
| `tests/server/rdp/test.rs` | server_review | 238 |
| `tests/server/redis/CLAUDE.md` | server_review | 188 |
| `tests/server/redis/connection_bounds_test.rs` | server_review | 247 |
| `tests/server/redis/e2e_test.rs` | server_review | 470 |
| `tests/server/redis/llm_failure_test.rs` | server_review | 87 |
| `tests/server/redis/mod.rs` | server_review | 14 |
| `tests/server/redis/peer_inject_test.rs` | server_review | 186 |
| `tests/server/redis/real_client_test.rs` | server_review | 241 |
| `tests/server/redis/resp_depth_test.rs` | server_review | 286 |
| `tests/server/redis/resp_framing_test.rs` | server_review | 240 |
| `tests/server/reverse_shell/CLAUDE.md` | server_review | 53 |
| `tests/server/reverse_shell/connection_bounds_test.rs` | server_review | 269 |
| `tests/server/reverse_shell/mod.rs` | server_review | 9 |
| `tests/server/reverse_shell/peer_inject_test.rs` | server_review | 186 |
| `tests/server/reverse_shell/test.rs` | server_review | 280 |
| `tests/server/rip/CLAUDE.md` | server_review | 282 |
| `tests/server/rip/action_validation_test.rs` | server_review | 147 |
| `tests/server/rip/e2e_test.rs` | server_review | 465 |
| `tests/server/rip/mod.rs` | server_review | 10 |
| `tests/server/rip/static_default_test.rs` | server_review | 80 |
| `tests/server/rss/CLAUDE.md` | server_review | 170 |
| `tests/server/rss/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/rss/e2e_test.rs` | server_review | 455 |
| `tests/server/rss/injection_test.rs` | server_review | 266 |
| `tests/server/rss/mod.rs` | server_review | 11 |
| `tests/server/rtp/CLAUDE.md` | server_review | 78 |
| `tests/server/rtp/budget_test.rs` | server_review | 194 |
| `tests/server/rtp/e2e_test.rs` | server_review | 111 |
| `tests/server/rtp/mod.rs` | server_review | 6 |
| `tests/server/rtp/script_fallback_budget_test.rs` | server_review | 287 |
| `tests/server/rtsp/CLAUDE.md` | server_review | 55 |
| `tests/server/rtsp/connection_bounds_test.rs` | server_review | 207 |
| `tests/server/rtsp/e2e_test.rs` | server_review | 184 |
| `tests/server/rtsp/ffprobe_test.rs` | server_review | 138 |
| `tests/server/rtsp/mod.rs` | server_review | 10 |
| `tests/server/rtsp/parser_test.rs` | server_review | 142 |
| `tests/server/rtsp/peer_inject_test.rs` | server_review | 177 |
| `tests/server/s3/CLAUDE.md` | server_review | 305 |
| `tests/server/s3/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/s3/e2e_test.rs` | server_review | 436 |
| `tests/server/s3/mod.rs` | server_review | 10 |
| `tests/server/s3/real_client_test.rs` | server_review | 220 |
| `tests/server/saml_idp/CLAUDE.md` | server_review | 72 |
| `tests/server/saml_idp/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/saml_idp/e2e_test.rs` | server_review | 429 |
| `tests/server/saml_idp/hardening_test.rs` | server_review | 128 |
| `tests/server/saml_idp/mod.rs` | server_review | 8 |
| `tests/server/saml_sp/CLAUDE.md` | server_review | 81 |
| `tests/server/saml_sp/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/saml_sp/e2e_test.rs` | server_review | 458 |
| `tests/server/saml_sp/hardening_test.rs` | server_review | 129 |
| `tests/server/saml_sp/mod.rs` | server_review | 8 |
| `tests/server/sip/CLAUDE.md` | server_review | 434 |
| `tests/server/sip/answer_with_test.rs` | server_review | 37 |
| `tests/server/sip/e2e_test.rs` | server_review | 422 |
| `tests/server/sip/fail_closed_test.rs` | server_review | 270 |
| `tests/server/sip/llm_failure_test.rs` | server_review | 127 |
| `tests/server/sip/mod.rs` | server_review | 12 |
| `tests/server/sip/real_client_test.rs` | server_review | 298 |
| `tests/server/sip/rtp_interop_test.rs` | server_review | 105 |
| `tests/server/smb/CLAUDE.md` | server_review | 79 |
| `tests/server/smb/bounds_test.rs` | server_review | 978 |
| `tests/server/smb/e2e_llm_test.rs` | server_review | 564 |
| `tests/server/smb/e2e_test.rs` | server_review | 1437 |
| `tests/server/smb/failure_modes_test.rs` | server_review | 299 |
| `tests/server/smb/header_layout_test.rs` | server_review | 534 |
| `tests/server/smb/inbound_limit_test.rs` | server_review | 207 |
| `tests/server/smb/llm_failure_test.rs` | server_review | 398 |
| `tests/server/smb/mod.rs` | server_review | 29 |
| `tests/server/smb/peer_inject_test.rs` | server_review | 219 |
| `tests/server/smb/real_client_test.rs` | server_review | 782 |
| `tests/server/smb/wire_util.rs` | server_review | 543 |
| `tests/server/smtp/CLAUDE.md` | server_review | 118 |
| `tests/server/smtp/answer_with_test.rs` | server_review | 158 |
| `tests/server/smtp/connection_bounds_test.rs` | server_review | 186 |
| `tests/server/smtp/llm_failure_test.rs` | server_review | 156 |
| `tests/server/smtp/mod.rs` | server_review | 10 |
| `tests/server/smtp/peer_inject_test.rs` | server_review | 161 |
| `tests/server/smtp/test.rs` | server_review | 473 |
| `tests/server/snmp/CLAUDE.md` | server_review | 382 |
| `tests/server/snmp/answer_with_test.rs` | server_review | 63 |
| `tests/server/snmp/ber_depth_test.rs` | server_review | 120 |
| `tests/server/snmp/llm_failure_test.rs` | server_review | 172 |
| `tests/server/snmp/mod.rs` | server_review | 8 |
| `tests/server/snmp/test.rs` | server_review | 590 |
| `tests/server/snowflake/CLAUDE.md` | server_review | 65 |
| `tests/server/snowflake/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/snowflake/e2e_test.rs` | server_review | 232 |
| `tests/server/snowflake/llm_failure_test.rs` | server_review | 130 |
| `tests/server/snowflake/mod.rs` | server_review | 8 |
| `tests/server/socket_file/CLAUDE.md` | server_review | 185 |
| `tests/server/socket_file/connection_bounds_test.rs` | server_review | 301 |
| `tests/server/socket_file/mod.rs` | server_review | 7 |
| `tests/server/socket_file/test.rs` | server_review | 331 |
| `tests/server/socks5/CLAUDE.md` | server_review | 343 |
| `tests/server/socks5/connection_bounds_test.rs` | server_review | 424 |
| `tests/server/socks5/e2e_test.rs` | server_review | 9 |
| `tests/server/socks5/mod.rs` | server_review | 8 |
| `tests/server/socks5/test.rs` | server_review | 776 |
| `tests/server/spark/CLAUDE.md` | server_review | 51 |
| `tests/server/spark/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/spark/e2e_test.rs` | server_review | 153 |
| `tests/server/spark/llm_failure_test.rs` | server_review | 99 |
| `tests/server/spark/mod.rs` | server_review | 8 |
| `tests/server/sqs/CLAUDE.md` | server_review | 439 |
| `tests/server/sqs/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/sqs/e2e_test.rs` | server_review | 502 |
| `tests/server/sqs/mod.rs` | server_review | 10 |
| `tests/server/sqs/real_client_test.rs` | server_review | 250 |
| `tests/server/ssdp/CLAUDE.md` | server_review | 226 |
| `tests/server/ssdp/e2e_test.rs` | server_review | 833 |
| `tests/server/ssdp/mod.rs` | server_review | 2 |
| `tests/server/ssh/CLAUDE.md` | server_review | 411 |
| `tests/server/ssh/connection_bounds_test.rs` | server_review | 169 |
| `tests/server/ssh/llm_failure_test.rs` | server_review | 311 |
| `tests/server/ssh/mod.rs` | server_review | 8 |
| `tests/server/ssh/real_client_test.rs` | server_review | 412 |
| `tests/server/ssh/test.rs` | server_review | 965 |
| `tests/server/ssh_agent/CLAUDE.md` | server_review | 253 |
| `tests/server/ssh_agent/connection_bounds_test.rs` | server_review | 304 |
| `tests/server/ssh_agent/e2e_test.rs` | server_review | 642 |
| `tests/server/ssh_agent/executor_test.rs` | server_review | 272 |
| `tests/server/ssh_agent/mod.rs` | server_review | 14 |
| `tests/server/ssh_agent/test.rs` | server_review | 293 |
| `tests/server/stdio/CLAUDE.md` | server_review | 80 |
| `tests/server/stdio/e2e_test.rs` | server_review | 378 |
| `tests/server/stdio/mod.rs` | server_review | 6 |
| `tests/server/stomp/CLAUDE.md` | server_review | 128 |
| `tests/server/stomp/codec_test.rs` | server_review | 366 |
| `tests/server/stomp/connection_bounds_test.rs` | server_review | 267 |
| `tests/server/stomp/e2e_test.rs` | server_review | 289 |
| `tests/server/stomp/mod.rs` | server_review | 8 |
| `tests/server/stomp/raw_socket_test.rs` | server_review | 379 |
| `tests/server/stp/CLAUDE.md` | server_review | 237 |
| `tests/server/stp/codec_test.rs` | server_review | 808 |
| `tests/server/stp/e2e_test.rs` | server_review | 628 |
| `tests/server/stp/mod.rs` | server_review | 16 |
| `tests/server/stun/CLAUDE.md` | server_review | 338 |
| `tests/server/stun/e2e_test.rs` | server_review | 823 |
| `tests/server/stun/llm_failure_test.rs` | server_review | 179 |
| `tests/server/stun/mod.rs` | server_review | 10 |
| `tests/server/stun/real_client_test.rs` | server_review | 253 |
| `tests/server/stun/reflection_test.rs` | server_review | 156 |
| `tests/server/stun/static_default_test.rs` | server_review | 146 |
| `tests/server/svn/CLAUDE.md` | server_review | 155 |
| `tests/server/svn/e2e_test.rs` | server_review | 425 |
| `tests/server/svn/framing_test.rs` | server_review | 249 |
| `tests/server/svn/llm_failure_test.rs` | server_review | 127 |
| `tests/server/svn/mod.rs` | server_review | 13 |
| `tests/server/svn/peer_inject_test.rs` | server_review | 181 |
| `tests/server/svn/real_client_test.rs` | server_review | 357 |
| `tests/server/syslog/CLAUDE.md` | server_review | 260 |
| `tests/server/syslog/e2e_test.rs` | server_review | 110 |
| `tests/server/syslog/mod.rs` | server_review | 4 |
| `tests/server/tcp/CLAUDE.md` | server_review | 215 |
| `tests/server/tcp/connection_bounds_test.rs` | server_review | 285 |
| `tests/server/tcp/mod.rs` | server_review | 6 |
| `tests/server/tcp/test.rs` | server_review | 505 |
| `tests/server/telnet/CLAUDE.md` | server_review | 369 |
| `tests/server/telnet/connection_bounds_test.rs` | server_review | 398 |
| `tests/server/telnet/decision_tag_test.rs` | server_review | 172 |
| `tests/server/telnet/line_framing_test.rs` | server_review | 178 |
| `tests/server/telnet/llm_failure_test.rs` | server_review | 132 |
| `tests/server/telnet/mod.rs` | server_review | 10 |
| `tests/server/telnet/test.rs` | server_review | 423 |
| `tests/server/tftp/CLAUDE.md` | server_review | 174 |
| `tests/server/tftp/decision_tag_test.rs` | server_review | 214 |
| `tests/server/tftp/e2e_test.rs` | server_review | 529 |
| `tests/server/tftp/llm_failure_test.rs` | server_review | 310 |
| `tests/server/tftp/mod.rs` | server_review | 8 |
| `tests/server/tls/CLAUDE.md` | server_review | 318 |
| `tests/server/tls/connection_bounds_test.rs` | server_review | 366 |
| `tests/server/tls/e2e_test.rs` | server_review | 368 |
| `tests/server/tls/llm_failure_test.rs` | server_review | 136 |
| `tests/server/tls/mod.rs` | server_review | 12 |
| `tests/server/tls/peer_inject_test.rs` | server_review | 225 |
| `tests/server/tls/queue_limit_test.rs` | server_review | 276 |
| `tests/server/tor_integration/consensus_builder.rs` | server_review | 135 |
| `tests/server/tor_integration/e2e_test.rs` | server_review | 290 |
| `tests/server/tor_integration/helpers.rs` | server_review | 330 |
| `tests/server/tor_integration/mod.rs` | server_review | 15 |
| `tests/server/tor_integration/tor_client.rs` | server_review | 253 |
| `tests/server/tor_relay/CLAUDE.md` | server_review | 97 |
| `tests/server/tor_relay/e2e_test.rs` | server_review | 209 |
| `tests/server/tor_relay/llm_failure_test.rs` | server_review | 194 |
| `tests/server/tor_relay/mod.rs` | server_review | 9 |
| `tests/server/tor_relay/peer.rs` | server_review | 431 |
| `tests/server/tor_relay/peer_inject_test.rs` | server_review | 312 |
| `tests/server/torrent_dht/CLAUDE.md` | server_review | 62 |
| `tests/server/torrent_dht/bencode_depth_guard_test.rs` | server_review | 241 |
| `tests/server/torrent_dht/e2e_test.rs` | server_review | 322 |
| `tests/server/torrent_dht/llm_failure_test.rs` | server_review | 157 |
| `tests/server/torrent_dht/mod.rs` | server_review | 10 |
| `tests/server/torrent_integration/e2e_test.rs` | server_review | 448 |
| `tests/server/torrent_integration/helpers.rs` | server_review | 141 |
| `tests/server/torrent_integration/mod.rs` | server_review | 20 |
| `tests/server/torrent_integration/torrent_builder.rs` | server_review | 216 |
| `tests/server/torrent_peer/CLAUDE.md` | server_review | 80 |
| `tests/server/torrent_peer/connection_bounds_test.rs` | server_review | 260 |
| `tests/server/torrent_peer/e2e_test.rs` | server_review | 355 |
| `tests/server/torrent_peer/llm_failure_test.rs` | server_review | 124 |
| `tests/server/torrent_peer/mod.rs` | server_review | 13 |
| `tests/server/torrent_peer/peer_inject_test.rs` | server_review | 184 |
| `tests/server/torrent_tracker/CLAUDE.md` | server_review | 105 |
| `tests/server/torrent_tracker/connection_bounds_test.rs` | server_review | 177 |
| `tests/server/torrent_tracker/e2e_test.rs` | server_review | 390 |
| `tests/server/torrent_tracker/llm_failure_test.rs` | server_review | 135 |
| `tests/server/torrent_tracker/mod.rs` | server_review | 14 |
| `tests/server/torrent_tracker/peer_inject_test.rs` | server_review | 264 |
| `tests/server/torrent_tracker/real_client_test.rs` | server_review | 241 |
| `tests/server/tuntap/CLAUDE.md` | server_review | 136 |
| `tests/server/tuntap/e2e_test.rs` | server_review | 1045 |
| `tests/server/tuntap/mod.rs` | server_review | 12 |
| `tests/server/tuntap/packet_test.rs` | server_review | 938 |
| `tests/server/turn/CLAUDE.md` | server_review | 98 |
| `tests/server/turn/e2e_test.rs` | server_review | 784 |
| `tests/server/turn/llm_failure_test.rs` | server_review | 162 |
| `tests/server/turn/mod.rs` | server_review | 14 |
| `tests/server/turn/peer_scope_test.rs` | server_review | 326 |
| `tests/server/turn/permission_limit_test.rs` | server_review | 302 |
| `tests/server/turn/static_default_test.rs` | server_review | 89 |
| `tests/server/udp/CLAUDE.md` | server_review | 189 |
| `tests/server/udp/decision_tag_test.rs` | server_review | 139 |
| `tests/server/udp/llm_failure_test.rs` | server_review | 101 |
| `tests/server/udp/mod.rs` | server_review | 6 |
| `tests/server/udp/test.rs` | server_review | 189 |
| `tests/server/usb_fido2/CLAUDE.md` | server_review | 125 |
| `tests/server/usb_fido2/ctaphid_client.rs` | server_review | 441 |
| `tests/server/usb_fido2/e2e_test.rs` | server_review | 1092 |
| `tests/server/usb_fido2/llm_failure_test.rs` | server_review | 160 |
| `tests/server/usb_fido2/mod.rs` | server_review | 8 |
| `tests/server/usb_keyboard/CLAUDE.md` | server_review | 93 |
| `tests/server/usb_keyboard/attach_on_import_test.rs` | server_review | 136 |
| `tests/server/usb_keyboard/connection_bounds_test.rs` | server_review | 41 |
| `tests/server/usb_keyboard/connection_cap_test.rs` | server_review | 185 |
| `tests/server/usb_keyboard/e2e_test.rs` | server_review | 411 |
| `tests/server/usb_keyboard/llm_failure_test.rs` | server_review | 120 |
| `tests/server/usb_keyboard/mod.rs` | server_review | 14 |
| `tests/server/usb_mouse/CLAUDE.md` | server_review | 82 |
| `tests/server/usb_mouse/connection_bounds_test.rs` | server_review | 33 |
| `tests/server/usb_mouse/e2e_test.rs` | server_review | 379 |
| `tests/server/usb_mouse/llm_failure_test.rs` | server_review | 108 |
| `tests/server/usb_mouse/mod.rs` | server_review | 8 |
| `tests/server/usb_msc/CLAUDE.md` | server_review | 175 |
| `tests/server/usb_msc/connection_bounds_test.rs` | server_review | 35 |
| `tests/server/usb_msc/e2e_test.rs` | server_review | 616 |
| `tests/server/usb_msc/fat16.rs` | server_review | 222 |
| `tests/server/usb_msc/guard_test.rs` | server_review | 191 |
| `tests/server/usb_msc/llm_failure_test.rs` | server_review | 127 |
| `tests/server/usb_msc/mod.rs` | server_review | 14 |
| `tests/server/usb_serial/CLAUDE.md` | server_review | 87 |
| `tests/server/usb_serial/connection_bounds_test.rs` | server_review | 33 |
| `tests/server/usb_serial/e2e_test.rs` | server_review | 449 |
| `tests/server/usb_serial/line_coding_test.rs` | server_review | 86 |
| `tests/server/usb_serial/llm_failure_test.rs` | server_review | 181 |
| `tests/server/usb_serial/mod.rs` | server_review | 11 |
| `tests/server/usb_smartcard/CLAUDE.md` | server_review | 107 |
| `tests/server/usb_smartcard/connection_bounds_test.rs` | server_review | 33 |
| `tests/server/usb_smartcard/e2e_test.rs` | server_review | 538 |
| `tests/server/usb_smartcard/llm_failure_test.rs` | server_review | 216 |
| `tests/server/usb_smartcard/mod.rs` | server_review | 8 |
| `tests/server/vault/CLAUDE.md` | server_review | 40 |
| `tests/server/vault/api_test.rs` | server_review | 170 |
| `tests/server/vault/connection_bounds_test.rs` | server_review | 79 |
| `tests/server/vault/e2e_test.rs` | server_review | 179 |
| `tests/server/vault/llm_failure_test.rs` | server_review | 73 |
| `tests/server/vault/mod.rs` | server_review | 16 |
| `tests/server/vault/real_client_test.rs` | server_review | 334 |
| `tests/server/vnc/CLAUDE.md` | server_review | 121 |
| `tests/server/vnc/connection_bounds_test.rs` | server_review | 290 |
| `tests/server/vnc/inbound_limit_test.rs` | server_review | 128 |
| `tests/server/vnc/mod.rs` | server_review | 10 |
| `tests/server/vnc/peer_inject_test.rs` | server_review | 218 |
| `tests/server/vnc/test.rs` | server_review | 683 |
| `tests/server/vrrp/CLAUDE.md` | server_review | 295 |
| `tests/server/vrrp/codec_test.rs` | server_review | 786 |
| `tests/server/vrrp/e2e_test.rs` | server_review | 772 |
| `tests/server/vrrp/mod.rs` | server_review | 17 |
| `tests/server/webdav/CLAUDE.md` | server_review | 171 |
| `tests/server/webdav/connection_bounds_test.rs` | server_review | 166 |
| `tests/server/webdav/decision_tag_test.rs` | server_review | 193 |
| `tests/server/webdav/mod.rs` | server_review | 8 |
| `tests/server/webdav/real_client_test.rs` | server_review | 587 |
| `tests/server/webdav/test.rs` | server_review | 388 |
| `tests/server/webrtc/CLAUDE.md` | server_review | 146 |
| `tests/server/webrtc/connection_bounds_test.rs` | server_review | 440 |
| `tests/server/webrtc/e2e_test.rs` | server_review | 629 |
| `tests/server/webrtc/inbound_limit_test.rs` | server_review | 108 |
| `tests/server/webrtc/mod.rs` | server_review | 8 |
| `tests/server/webrtc_signaling/CLAUDE.md` | server_review | 302 |
| `tests/server/webrtc_signaling/connection_bounds_test.rs` | server_review | 441 |
| `tests/server/webrtc_signaling/e2e_test.rs` | server_review | 215 |
| `tests/server/webrtc_signaling/inbound_limit_test.rs` | server_review | 112 |
| `tests/server/webrtc_signaling/llm_failure_test.rs` | server_review | 251 |
| `tests/server/webrtc_signaling/mod.rs` | server_review | 12 |
| `tests/server/webrtc_signaling/relay_abuse_test.rs` | server_review | 235 |
| `tests/server/websocket/CLAUDE.md` | server_review | 114 |
| `tests/server/websocket/answer_with_test.rs` | server_review | 153 |
| `tests/server/websocket/connection_bounds_test.rs` | server_review | 420 |
| `tests/server/websocket/e2e_test.rs` | server_review | 940 |
| `tests/server/websocket/mod.rs` | server_review | 5 |
| `tests/server/whois/CLAUDE.md` | server_review | 156 |
| `tests/server/whois/connection_bounds_test.rs` | server_review | 376 |
| `tests/server/whois/e2e_test.rs` | server_review | 418 |
| `tests/server/whois/line_framing_test.rs` | server_review | 285 |
| `tests/server/whois/mod.rs` | server_review | 10 |
| `tests/server/whois/peer_inject_test.rs` | server_review | 173 |
| `tests/server/whois/record_fields_test.rs` | server_review | 125 |
| `tests/server/wireguard/CLAUDE.md` | server_review | 126 |
| `tests/server/wireguard/e2e_test.rs` | server_review | 599 |
| `tests/server/wireguard/mod.rs` | server_review | 2 |
| `tests/server/wol/CLAUDE.md` | server_review | 136 |
| `tests/server/wol/decode_test.rs` | server_review | 243 |
| `tests/server/wol/e2e_test.rs` | server_review | 375 |
| `tests/server/wol/mod.rs` | server_review | 6 |
| `tests/server/wol/real_client_test.rs` | server_review | 160 |
| `tests/server/xmlrpc/CLAUDE.md` | server_review | 207 |
| `tests/server/xmlrpc/connection_bounds_test.rs` | server_review | 49 |
| `tests/server/xmlrpc/llm_failure_test.rs` | server_review | 111 |
| `tests/server/xmlrpc/mod.rs` | server_review | 7 |
| `tests/server/xmlrpc/test.rs` | server_review | 664 |
| `tests/server/xmpp/CLAUDE.md` | server_review | 69 |
| `tests/server/xmpp/connection_bounds_test.rs` | server_review | 216 |
| `tests/server/xmpp/llm_failure_test.rs` | server_review | 167 |
| `tests/server/xmpp/mod.rs` | server_review | 13 |
| `tests/server/xmpp/peer_inject_test.rs` | server_review | 201 |
| `tests/server/xmpp/test.rs` | server_review | 348 |
| `tests/server/yarn/CLAUDE.md` | server_review | 36 |
| `tests/server/yarn/connection_bounds_test.rs` | server_review | 56 |
| `tests/server/yarn/e2e_test.rs` | server_review | 204 |
| `tests/server/yarn/llm_failure_test.rs` | server_review | 83 |
| `tests/server/yarn/mod.rs` | server_review | 8 |
| `tests/server/zabbix/CLAUDE.md` | server_review | 54 |
| `tests/server/zabbix/answer_with_test.rs` | server_review | 37 |
| `tests/server/zabbix/common.rs` | server_review | 248 |
| `tests/server/zabbix/connection_bounds_test.rs` | server_review | 274 |
| `tests/server/zabbix/e2e_test.rs` | server_review | 128 |
| `tests/server/zabbix/llm_failure_test.rs` | server_review | 137 |
| `tests/server/zabbix/mod.rs` | server_review | 16 |
| `tests/server/zabbix/peer_inject_test.rs` | server_review | 94 |
| `tests/server/zabbix/real_client_test.rs` | server_review | 208 |
| `tests/server/zabbix/wire_test.rs` | server_review | 132 |
| `tests/server/zookeeper/CLAUDE.md` | server_review | 75 |
| `tests/server/zookeeper/e2e_test.rs` | server_review | 418 |
| `tests/server/zookeeper/error_code_range_test.rs` | server_review | 101 |
| `tests/server/zookeeper/mod.rs` | server_review | 9 |
| `tests/server/zookeeper/peer_inject_test.rs` | server_review | 220 |
| `tests/server_handle_registry_test.rs` | root | 184 |
| `tests/server_startup_survives_llm_outage_test.rs` | root | 170 |
| `tests/server_stop_cleans_scheduled_tasks_test.rs` | root | 121 |
| `tests/server_stop_releases_port_test.rs` | root | 129 |
| `tests/server_task_registry_test.rs` | root | 138 |
| `tests/silent_peer_probe_test.rs` | root | 572 |
| `tests/site_protocol_list_test.rs` | root | 186 |
| `tests/snapshot_util.rs` | root | 167 |
| `tests/snapshots/network_event_prompt_proxy.actual.txt` | root | 203 |
| `tests/snapshots/user_input_prompt.actual.txt` | root | 206 |
| `tests/spawned_netget_is_tied_test.rs` | root | 136 |
| `tests/sqlite_test.rs` | root | 697 |
| `tests/startup_dependency_gate_test.rs` | root | 166 |
| `tests/startup_examples_actually_start_test.rs` | root | 392 |
| `tests/startup_examples_validation_test.rs` | root | 412 |
| `tests/startup_param_defaults_test.rs` | root | 197 |
| `tests/startup_param_drift_test.rs` | root | 284 |
| `tests/startup_params_result_test.rs` | root | 163 |
| `tests/static_handler_action_catalog_test.rs` | root | 238 |
| `tests/static_handler_interpolation_test.rs` | root | 559 |
| `tests/stop_server_stops_connections_test.rs` | root | 398 |
| `tests/system_library_probe_test.rs` | root | 79 |
| `tests/system_stats_test.rs` | root | 28 |
| `tests/tcp_accumulate_loop_test.rs` | root | 188 |
| `tests/tcp_server_bounds_ratchet_test.rs` | root | 616 |
| `tests/terminal_snapshot.rs` | root | 8 |
| `tests/terminal_snapshot/mod.rs` | root | 860 |
| `tests/terminal_snapshot/snapshots/.gitignore` | root | 2 |
| `tests/terminal_snapshot/snapshots/ctrl_k_delete.snap.md` | root | 24 |
| `tests/terminal_snapshot/snapshots/cursor_navigation.snap.md` | root | 24 |
| `tests/terminal_snapshot/snapshots/initial_tui.snap.md` | root | 24 |
| `tests/terminal_snapshot/snapshots/input_line.snap.md` | root | 24 |
| `tests/terminal_snapshot/snapshots/typed_simple_input.snap.md` | root | 24 |
| `tests/terminal_snapshot/snapshots/usage_command_enabled.snap.md` | root | 24 |
| `tests/test_suite_hygiene_test.rs` | root | 261 |
| `tests/tool_call_integration_test.rs` | root | 341 |
| `tests/tool_classification_test.rs` | root | 137 |
| `tests/toolcall/read_file_integration_test.rs` | root | 5 |
| `tests/toolcall/read_file_test.rs` | root | 69 |
| `tests/toolcall/web_search_integration_test.rs` | root | 353 |
| `tests/toolcall/web_search_test.rs` | root | 59 |
| `tests/truncate_test.rs` | root | 183 |
| `tests/usb_accept_and_attach_ratchet_test.rs` | root | 137 |
| `tests/usb_fido2_approval_test.rs` | root | 135 |
| `tests/utf8_truncation_panic_test.rs` | root | 212 |
| `tests/utils_sanitize_test.rs` | root | 89 |
| `tests/utils_save_load_test.rs` | root | 109 |
| `tests/validators/http_validator.rs` | root | 177 |
| `tests/validators/mod.rs` | root | 23 |
| `tests/validators/ssh_validator.rs` | root | 102 |
| `tests/validators/tcp_validator.rs` | root | 148 |
| `tests/vendor_default_fallback_test.rs` | root | 528 |
| `tests/vendored_hyper_patch_test.rs` | root | 171 |
| `tests/well_known_port_declaration_test.rs` | root | 451 |
| `tests/wire_failure_test.rs` | root | 234 |
| `vendor/hyper/Cargo.toml` | root | 263 |
| `vendor/hyper/LICENSE` | root | 19 |
| `vendor/hyper/README.md` | root | 118 |
| `vendor/hyper/src/body/incoming.rs` | root | 628 |
| `vendor/hyper/src/body/length.rs` | root | 129 |
| `vendor/hyper/src/body/mod.rs` | root | 50 |
| `vendor/hyper/src/cfg.rs` | root | 44 |
| `vendor/hyper/src/client/conn/http1.rs` | root | 611 |
| `vendor/hyper/src/client/conn/http2.rs` | root | 718 |
| `vendor/hyper/src/client/conn/mod.rs` | root | 22 |
| `vendor/hyper/src/client/dispatch.rs` | root | 523 |
| `vendor/hyper/src/client/mod.rs` | root | 22 |
| `vendor/hyper/src/client/tests.rs` | root | 261 |
| `vendor/hyper/src/common/buf.rs` | root | 150 |
| `vendor/hyper/src/common/date.rs` | root | 157 |
| `vendor/hyper/src/common/either.rs` | root | 46 |
| `vendor/hyper/src/common/future.rs` | root | 30 |
| `vendor/hyper/src/common/io/compat.rs` | root | 150 |
| `vendor/hyper/src/common/io/mod.rs` | root | 7 |
| `vendor/hyper/src/common/io/rewind.rs` | root | 162 |
| `vendor/hyper/src/common/mod.rs` | root | 21 |
| `vendor/hyper/src/common/task.rs` | root | 45 |
| `vendor/hyper/src/common/time.rs` | root | 79 |
| `vendor/hyper/src/common/watch.rs` | root | 73 |
| `vendor/hyper/src/error.rs` | root | 679 |
| `vendor/hyper/src/ext/h1_reason_phrase.rs` | root | 221 |
| `vendor/hyper/src/ext/informational.rs` | root | 86 |
| `vendor/hyper/src/ext/mod.rs` | root | 295 |
| `vendor/hyper/src/ffi/body.rs` | root | 302 |
| `vendor/hyper/src/ffi/client.rs` | root | 274 |
| `vendor/hyper/src/ffi/error.rs` | root | 96 |
| `vendor/hyper/src/ffi/http_types.rs` | root | 703 |
| `vendor/hyper/src/ffi/io.rs` | root | 198 |
| `vendor/hyper/src/ffi/macros.rs` | root | 53 |
| `vendor/hyper/src/ffi/mod.rs` | root | 99 |
| `vendor/hyper/src/ffi/task.rs` | root | 549 |
| `vendor/hyper/src/headers.rs` | root | 159 |
| `vendor/hyper/src/lib.rs` | root | 139 |
| `vendor/hyper/src/mock.rs` | root | 235 |
| `vendor/hyper/src/proto/h1/conn.rs` | root | 1530 |
| `vendor/hyper/src/proto/h1/decode.rs` | root | 1236 |
| `vendor/hyper/src/proto/h1/dispatch.rs` | root | 808 |
| `vendor/hyper/src/proto/h1/encode.rs` | root | 660 |
| `vendor/hyper/src/proto/h1/io.rs` | root | 967 |
| `vendor/hyper/src/proto/h1/mod.rs` | root | 113 |
| `vendor/hyper/src/proto/h1/role.rs` | root | 3098 |
| `vendor/hyper/src/proto/h2/client.rs` | root | 746 |
| `vendor/hyper/src/proto/h2/mod.rs` | root | 446 |
| `vendor/hyper/src/proto/h2/ping.rs` | root | 510 |
| `vendor/hyper/src/proto/h2/server.rs` | root | 545 |
| `vendor/hyper/src/proto/mod.rs` | root | 73 |
| `vendor/hyper/src/rt/bounds.rs` | root | 109 |
| `vendor/hyper/src/rt/io.rs` | root | 405 |
| `vendor/hyper/src/rt/mod.rs` | root | 48 |
| `vendor/hyper/src/rt/timer.rs` | root | 127 |
| `vendor/hyper/src/server/conn/http1.rs` | root | 551 |
| `vendor/hyper/src/server/conn/http2.rs` | root | 312 |
| `vendor/hyper/src/server/conn/mod.rs` | root | 20 |
| `vendor/hyper/src/server/mod.rs` | root | 9 |
| `vendor/hyper/src/service/http.rs` | root | 65 |
| `vendor/hyper/src/service/mod.rs` | root | 30 |
| `vendor/hyper/src/service/service.rs` | root | 112 |
| `vendor/hyper/src/service/util.rs` | root | 82 |
| `vendor/hyper/src/trace.rs` | root | 128 |
| `vendor/hyper/src/upgrade.rs` | root | 407 |
| `web/README.md` | surfaces_review | 427 |
| `web/build.sh` | surfaces_review | 72 |
| `web/test/page_composer.py` | surfaces_review | 1279 |
| `web/test/smoke.mjs` | surfaces_review | 816 |

<a id="artifacts"></a>
## Evidence artifact index

| Artifact | Purpose |
|---|---|
| [verification-results.json](../../audit/2026-10-01/verification-results.json) | Final results, concrete command arrays, feature/environment constraints and preserved corrected failure history |
| [native-test-results.json](../../audit/2026-10-01/native-test-results.json) | Per-target counts for the 24 native regression targets |
| [changed-files.json](../../audit/2026-10-01/changed-files.json) | All 119 changed source/test/workflow/documentation files, sizes and final SHA-256 digests |
| [tracked-file-inventory.json](../../audit/2026-10-01/tracked-file-inventory.json) | Complete 3,342-file checkpoint inventory with sizes, owners and hashes |
| [static-scan.json](../../audit/2026-10-01/static-scan.json) | Per-source-file heuristic signal locations; findings require interpretation |
| [script-syntax-results.json](../../audit/2026-10-01/script-syntax-results.json) | 40 independent syntax check outcomes |
| [core-review.md](../../audit/2026-10-01/core-review.md) | Standalone shared core/build/CI section |
| [server-review.md](../../audit/2026-10-01/server-review.md) | Standalone server section and per-directory coverage ledger |
| [client-review.md](../../audit/2026-10-01/client-review.md) | Standalone client/easy/pipe section and file inventory |
| [runtime-review.md](../../audit/2026-10-01/runtime-review.md) | Standalone CLI/state/protocol section |
| [surfaces-review.md](../../audit/2026-10-01/surfaces-review.md) | Standalone TUI/display/browser/npm section |
| [automation-review.md](../../audit/2026-10-01/automation-review.md) | Standalone scripting/MCP section |
| [test-infrastructure-review.md](../../audit/2026-10-01/test-infrastructure-review.md) | Standalone tests/examples/prompts/schema/vendor section |

The seven detailed reports are embedded in full above so this Markdown file remains the primary consolidated deliverable. Temporary raw logs are available under `tmp/audit-2026-10-01/` in the current workspace; generated build directories and user runtime logs are not included in the report inventory.


---

# Remaining audit implementation — 2026-10-02

This report records the follow-up implementation of the remaining audit backlog after the
2026-10-01 review. It covers the twelve remaining recursive-decoder exceptions, the two
stale wrapper exceptions, concrete wrapper and peer-task ownership fixes, and the CI changes
that exercise them. It is an implementation and compatibility record, not a declaration
that every protocol has independent interoperability coverage.

The work was integrated in `/Users/matus/dev/netget/.audit-integration-20261002`. The existing
review snapshot was preserved before these changes. Parallel protocol-expansion worktrees
were outside this task. No GPU, real model, external model endpoint, physical USB device,
or other hardware was used for the checks described here.

## Verification status at report preparation

The coordinating agent confirmed these completed results:

| Check | Confirmed result | Scope |
|---|---|---|
| `audit_server_decoder_bounds_test` | 10 passed | Four IPP, three DHT, three FIDO2 tests; in-memory fixtures |
| `grpc_value_bounds_test` | 7 passed | Both public peer conversion paths; in-memory schema/value fixtures |
| `recursive_decoder_depth_test` | 3 passed | Empty unbounded set, known bounded identities, scanner fixtures |
| `spawned_netget_is_tied_test` | 3 passed | Death-tie and process-spawn recognition plus repository ratchet |
| `task_registration_cancellation_test` | 6 passed | Client/server/peer cancellation and successful ownership transfer |
| `wrapper_lifecycle_test` | 5 passed | E2E wrapper fixtures and included wrapper unit tests |
| Changed server/ratchet Rust files | Formatting and focused diff checks passed | Formatting/static validation only |

The coordinating agent confirmed **34 passing executions** across the six targets above.
The four PTY fixtures and broader 324-test native regression run also passed after this
checkpoint. Final fixture corrections, re-lint, Windows, and other integration outcomes
remain in the separate final verification record. This report deliberately does not
invent a final aggregate, convert unexecuted platform fixtures into passes, or reuse older
review totals as evidence for this implementation.

**Final machine-readable verification is separate.** The final verification artifacts are
the authority for exact commands, feature sets, exit statuses, logs, platform availability,
and final totals. A CI definition shows that a check is scheduled; it does not prove that
the remote runner has executed it.

## Changed-path inventory

Paths below are relative to the isolated integration worktree. Shared targets appear once.

| Area | Exact changed paths |
|---|---|
| IPP | `src/server/ipp/actions.rs`; `src/server/ipp/CLAUDE.md` |
| DHT | `src/server/torrent_dht/mod.rs`; `src/server/torrent_dht/CLAUDE.md` |
| FIDO2 | `src/server/usb/fido2/mod.rs`; `src/server/usb/fido2/CLAUDE.md` |
| IPP/DHT/FIDO2 regression target | `tests/audit_server_decoder_bounds_test.rs` |
| Shared gRPC conversion | `src/server/grpc/value_codec.rs`; `src/server/grpc/mod.rs`; `src/client/grpc/mod.rs` |
| gRPC documentation and tests | `src/server/grpc/CLAUDE.md`; `src/client/grpc/CLAUDE.md`; `tests/grpc_value_bounds_test.rs` |
| Recursion ratchet | `tests/recursive_decoder_depth_test.rs` |
| E2E wrapper ownership | `tests/e2e/netget_wrapper.rs`; `tests/helpers/wrapper_lifecycle.rs`; `tests/wrapper_lifecycle_test.rs` |
| PTY wrapper ownership | `tests/terminal_snapshot.rs`; `tests/terminal_snapshot/mod.rs`; `tests/terminal_snapshot/child_lifecycle.rs` |
| Wrapper ratchet | `tests/spawned_netget_is_tied_test.rs` |
| Peer-task registration | `src/state/app_state.rs`; `tests/task_registration_cancellation_test.rs` |
| Windows fixture portability | `Cargo.toml`; `tests/process_group_windows_test.rs` |
| CI | `.github/workflows/ci.yml` |
| Build invalidation inputs | `build.rs` |
| This implementation record | `audit/2026-10-02/remaining-audit-implementation.md` |

The server review agent implemented IPP/DHT/FIDO2, their shared focused regression target,
their local documentation, and the recursion-ratchet update. The client review agent
implemented the shared gRPC codec and its integration/tests. The surfaces review agent
implemented wrapper and platform fixtures. The coordinating agent integrated the changes,
implemented the peer-task registration and build-input corrections, and owns final
verification and publication.

## 1. IPP attribute validation and JSON fallback fields

### Before

`validate_attributes` contained a recursive `check` over arrays. It validated integer ranges
and raw string lengths but relied on the caller's JSON parser to restrict nesting. A directly
constructed value did not have that incidental parser protection. Objects were skipped by
this check even though the response encoder serialized objects and nested arrays as JSON text.

That fallback introduced a second concrete problem: a value could pass validation and then
serialize to more than the IPP two-byte value-length field can express. The low-level encoder
clamped the bytes to `u16::MAX`, producing a self-consistent but truncated representation.
Escaping could make the serialized text exceed the limit even when individual raw strings
were shorter than the limit.

### Implemented behavior

- `MAX_IPP_ATTRIBUTE_DEPTH` is 32 array/object levels. The surrounding attribute map is not
  counted. A scalar consumes no container level.
- An explicit iterative walk covers both arrays and objects before any JSON fallback
  serialization. It rejects excess depth with an attribute-specific error.
- Existing integer-range checks are preserved for ordinary scalar attributes and arrays.
  Numbers inside an object continue to use JSON syntax; they are not incorrectly forced
  into IPP's signed 32-bit integer syntax.
- The validation follows the actual encoder shape: the outer array is an IPP set; each
  nested array or object is one JSON-text field.
- A bounded `std::io::Write` implementation counts serialized JSON bytes without allocating
  an oversized temporary string. It refuses a field that cannot be encoded in full.
- The borrowed `validate_attributes` entry point and public depth constant permit direct
  validation of programmatically constructed values.

### Regression evidence

The four IPP tests cover array-only and mixed object/array nesting at 32 levels and at 33;
20,000-level directly constructed trees; exact 65,535-byte JSON fallback fields; excess
serialized length including escaped characters; nested container fallback; ordinary sets;
and large/fractional numbers inside JSON objects.

The deep-tree fixture dismantles the input iteratively after validation. This isolates the
validator from the standard recursive destructor of `serde_json::Value`; the test does not
claim to change that dependency's destruction behavior.

### Compatibility

Ordinary representable attributes retain their encoding. Values deeper than the new local
limit, or fallback JSON that previously became truncated text, now return errors. This is an
intentional refusal of values that cannot be processed under the documented bounds. No
partial field or substituted null is returned. This work does not add recursive parsing of
incoming IPP attribute groups; the existing inbound header parser remains a separate path.

## 2. DHT conversion has a local bound

### Before

`parse_krpc_message` already ran the iterative shared bencode structure check before
deserialization. That preflight capped wire nesting at 32, but `bencode_to_json` itself was
an infallible recursive walker. Its safety depended on callers always reaching it through
the preflight, and the protocol-local static scan could not see the bound in `src/utils`.

### Implemented behavior

- `MAX_DHT_VALUE_DEPTH` explicitly references the existing shared 32-level bencode limit.
- `bencode_to_json` returns `Result<serde_json::Value>` and calls a bounded recursive helper.
- Each list or dictionary consumes one level; scalar values do not consume a level.
- The check occurs before descending into an excess-depth container.
- Recursive errors propagate to `parse_krpc_message` with `?`; the converter never returns
  a shortened tree or a fabricated value.
- The original wire preflight remains in place before `serde_bencode` deserialization.

### Regression evidence and compatibility

Three tests cover integers, printable text, binary/non-ASCII hex conversion, ordinary
dictionaries and lists, exact depth 32, depth 33, and 20,000-level in-memory trees. The deepest
accepted tree is traversed to its original scalar leaf to establish that success did not
mean truncation. Deep test values are dismantled iteratively.

Existing accepted KRPC wire messages retain their conversions: the original 32-level wire
preflight is still at least as restrictive as conversion of a nested argument. Printable
bytes still become text, binary/non-ASCII bytes still become hex, and dictionary key
conversion is preserved. Direct conversion now exposes an explicit failure result and is
safe independently of the wire-parser calling convention.

## 3. FIDO2 dispatch and parking are acyclic

### Before

`run_command` called `park` when CTAP2 or U2F required user presence. If no approval channel
was attached, or its receiver was closed, `park` called `run_command` again with
`UserPresence::Denied`.

The cycle terminated because the current handlers never asked for approval after denial.
That was a semantic invariant rather than an explicit structural bound: a future handler
change could accidentally make the cycle recurse again.

### Implemented behavior

`park` now calls `deny_presence_command`, a leaf helper that directly invokes the appropriate
CTAP2 or U2F handler once with `Denied`. It never enters dispatch or parking. The normal
encoded denial/error result is framed for the original channel and command.

If a handler incorrectly returns `NeedsApproval` after denial, the helper emits an error log
and returns the protocol's denial immediately: U2F `0x6985` or CTAP2 `0x27`. It does not
retry, recurse, or create a credential. Unsupported command kinds receive CTAPHID
`InvalidCmd`.

### Regression evidence

Three tests drive the actual public `UsbInterfaceHandler` with in-memory interface and HID
frames. They do not bind USB/IP, enumerate devices, or obtain a physical device handle.

- Absent and closed approval channels are tested for both U2F and CTAP2 over repeated
  registrations. Each response has the expected denial bytes, leaves no pending response,
  and stores no credentials.
- An attached approval channel preserves `KEEPALIVE(UPNEEDED)`, denied registration,
  approved registration, and channel-busy behavior when another command arrives while
  approval is pending. Approved registration exercises CPU cryptography.
- PING accepts the exact 7,609-byte CTAPHID maximum. A 7,610-byte declaration receives the
  expected length error. Malformed U2F/CTAP2 payloads retain their protocol errors, and a
  subsequent valid PING still succeeds.

### Compatibility

Normal approval, denial, and framing semantics are preserved. The new defensive branch
only matters if a handler violates the denied-presence invariant. These tests establish
in-memory handler behavior, not interoperability with libfido2, browsers, physical security
keys, or OS USB/IP clients.

## 4. Shared gRPC value conversion

### Before

The client and server each maintained their own recursive JSON/protobuf conversion helpers.
Their nesting protection depended on serde/prost parser defaults. Directly constructed
values did not receive the same protection. Some invalid shapes were silently transformed:
unknown fields were logged and discarded, non-object messages could become empty messages,
and conflicting fields or keys could overwrite earlier values.

### Implemented behavior

Both peers now expose conversion entry points backed by
`src/server/grpc/value_codec.rs`. One shared budget follows every recursive path and sibling:

| Bound | Value | Meaning |
|---|---:|---|
| Depth | 32 | Root depth zero; each message field, map value, or list element adds one |
| Nodes | 100,000 | Aggregate logical nodes across the whole conversion |
| Retained content | 8 MiB | Accounting includes values, strings/base64, node overhead, and key overhead |
| Node accounting | 64 bytes | Per logical node, charged before retaining its representation |
| Map-key accounting | 32 bytes plus text | Charged in addition to the key's content |

These are conversion budgets, not a replacement for the existing 4 MiB inbound gRPC wire-body
cap. Checks occur before large copies, base64 output, or decoded-byte allocation. Exceeding
a bound produces the typed `ValueLimitExceeded` error; complete values or errors are returned.

Validation also rejects unknown fields, non-object messages, multiple members of one `oneof`,
map keys that normalize to the same protobuf key, float overflow, float underflow to zero,
non-finite reflected floats, invalid bytes/base64, and invalid scalar shapes. Field updates
use fallible reflection APIs. A request conversion resource error maps to gRPC status
`RESOURCE_EXHAUSTED` (8); invalid representational/schema input maps to `INVALID_ARGUMENT`
(3), preserving the distinction from internal failures.

### Regression evidence

Seven tests use in-memory protobuf descriptors without invoking `protoc`. They exercise both
public peer conversion paths, nested protobuf encode/decode round trips, message/list/map
depth boundaries, directly constructed deep reflected values, exact node and content limits,
aggregate sibling budgets, base64 expansion, malformed values, duplicate normalized keys,
`oneof` conflicts, non-finite values, and request error classification.

### Compatibility

Valid field-name JSON and protobuf messages inside the limits retain their round-trip
meaning. Callers that relied on unknown fields being ignored, non-object values producing
empty messages, conflicting keys/oneofs choosing a winner, or unrepresentable floating-point
values silently changing now receive errors. Large/deep conversions beyond the explicit
budgets are intentionally refused. This is stricter validation, not protocol expansion.

## 5. All twelve recursive-decoder exceptions are closed

The previous remaining exception identities map to these implemented changes:

| Former exception | Resolution |
|---|---|
| `client:grpc:mod.rs:json_to_dynamic_message` | Shared explicitly bounded codec |
| `client:grpc:mod.rs:json_to_field_value` | Shared explicitly bounded codec |
| `client:grpc:mod.rs:json_to_proto_value` | Shared explicitly bounded codec |
| `client:grpc:mod.rs:proto_value_to_json` | Shared explicitly bounded codec |
| `server:grpc:mod.rs:json_to_dynamic_message` | Shared explicitly bounded codec |
| `server:grpc:mod.rs:json_to_field_value` | Shared explicitly bounded codec |
| `server:grpc:mod.rs:json_to_proto_value` | Shared explicitly bounded codec |
| `server:grpc:mod.rs:proto_value_to_json` | Shared explicitly bounded codec |
| `server:ipp:actions.rs:check` | Iterative attribute walk and explicit container limit |
| `server:torrent_dht:mod.rs:bencode_to_json` | Fallible helper with its own depth parameter and bound |
| `server:usb/fido2:mod.rs:park` | Calls direct leaf denial, not dispatch |
| `server:usb/fido2:mod.rs:run_command` | Dispatch/parking cycle removed |

`tests/recursive_decoder_depth_test.rs` no longer contains an unbounded baseline. It requires
the discovered unbounded set to be empty. Its previous minimum-count assertion was removed:
sharing duplicate codecs and replacing recursion with iteration legitimately reduce counts.

Sensitivity is maintained through specific known bounded AMQP, VNC, XML-RPC, DHT and gRPC
identities, checks that removed IPP/FIDO2 cycle identities stay absent, historical unbounded
fixtures, bound-removal fixtures, and new FIDO2-cycle/iterative-IPP fixtures. The gRPC
`value_to_json` helper is a recognized `Value`-shaped recursive entry. The JSON-side `Json`
alias is outside the scanner's current type-shape vocabulary; its explicit budgets are
exercised by the runtime codec target. The source scanner remains a heuristic for call
cycles and visible bounds, not a proof of every parser's safety.

## 6. Wrapper ownership and the two stale exceptions

### Correction to the earlier exception descriptions

The old wrapper baseline listed `tests/e2e/netget_wrapper.rs` and
`tests/terminal_snapshot/mod.rs` as lacking an OS-level tie. Inspection showed that both
already called `arm_death_tie`; those descriptions were stale. This pass does not claim to
have introduced a previously absent death tie to those wrappers.

There were still concrete ownership defects to repair. Optional tie creation could fail
without refusing startup; cancellation could drop the sole child owner during shutdown;
and successful reaping was not consistently coordinated with disarming a numeric-PID tie.

### E2E wrapper changes

- Spawn enables `kill_on_drop(true)` and creates a private process group.
- `protect_child` requires successful death-tie arming. Failure terminates the owned process
  group, awaits reaping within a bound, and returns an error.
- `stop` retains the child inside the wrapper across every await. Cancelling that future
  does not detach the child's only owner while leaving the wrapper alive.
- Graceful shutdown has a one-second bound. Forced termination signals the owned group and
  waits up to two seconds for the child.
- `is_running` disarms the tie when `try_wait` has reaped the child, reducing the interval in
  which an armed numeric PID could refer to a reused PID.
- Drop handles an already-reaped child, otherwise terminates the owned group and reaps using
  the available runtime. The tie remains a backstop if reaping cannot be confirmed.

### PTY wrapper changes

The `NetGetChild` constructor requires a death tie before returning the wrapper. Failed
arming leaves an owned guard that kills and reaps during error cleanup. Drop recognizes
already-reaped children before signalling, retains bounded teardown, and leaves the tie
armed if termination/reaping cannot be confirmed. Unix PTY-specific test code is explicitly
gated to Unix platforms.

### Fixture and ratchet coverage

`tests/helpers/wrapper_lifecycle.rs` creates exactly owned inert shell/sleep fixtures and an
unrelated sentinel. Parent-death tests kill only their fixture owner; the sentinel must
survive. The inert child does not rely on stdin EOF for termination. The PTY child ignores
SIGHUP before announcing readiness, preventing terminal hangup from making a missing
death-tie implementation appear to pass.

A final fixture review removed a failure-only raw PID kill after a timeout: the orphan could
have exited and its numeric PID could have been reused. Inert children now check a unique
outer-owned temporary-file lease; outer cleanup revokes it on failure, and a bounded loop
also expires independently. The lease stays present throughout the parent-death assertion,
so it cannot hide a missing death tie. Both fixture paths reuse their wrapper's child-guard
module, resolving the duplicate-module strict lint without suppressing it.

The E2E fixtures cover abrupt parent death, graceful and forced stop, cancellation of stop,
and failed tie arming. PTY fixtures cover abrupt parent death, bounded normal teardown,
already-reaped children, and failed arming. Normal cleanup requires reaping; abrupt-parent
fixtures recognize an already-dead orphan zombie as terminated if the host init has not yet
reaped it. That distinction is explicit rather than a claim that the dead parent reaped it.

The wrapper ratchet now recognizes both `::tie_child` and `::arm_death_tie`. It does not
mistake `kill_on_drop` or `untie_child` for a tie. It distinguishes process `Command` spawning
from a protocol object's unrelated `spawn` method. The two stale exceptions were removed,
leaving an empty exception list. Source fixtures pin those recognition rules.

## 7. Peer-task registration retains ownership before first poll

`AppState::register_peer_task` previously accepted an already-running `JoinHandle` inside an
`async fn`. Dropping the returned future before its first poll could drop that handle without
aborting the running worker. A cancellation while awaiting the state lock had the same
ownership concern. This was the peer-specific counterpart of the already addressed
client/server task-registration pattern.

The method now constructs `PendingTaskRegistration` synchronously and returns an async block
that owns the guard. Dropping an unpolled or unfinished registration aborts the child. After
the server and peer are confirmed present under the state lock, ownership transfers into
the registered task collection. Missing owners return without disarming the guard.

Existing `.await` call sites retain their usage. Successful registration keeps the worker
alive until the peer is removed. Two added tests distinguish unpolled cancellation from
successful ownership transfer, and the successful-removal fixture also verifies that removing
one peer preserves its server. The target retains its existing client/server registration
coverage. The coordinating agent confirmed all six tests in the target passed; exact commands
and logs belong to the separate verification record.

## 8. CI integration and platform boundaries

The Linux `resource-lifecycles` job shares one explicit `AUDIT_CPU_FEATURES` set across
its native commands, including the original CPU features plus gRPC, IPP, DHT, FIDO2 and
terminal snapshots. The six new/extended targets run with the existing native regressions;
a separate command selects only `terminal_snapshot child_lifecycle`. Both use the same
feature set, avoiding separate full-library compilations. Build concurrency is two.

The new target selection is:

```sh
--test grpc_value_bounds_test --test audit_server_decoder_bounds_test \
--test wrapper_lifecycle_test --test task_registration_cancellation_test \
--test recursive_decoder_depth_test --test spawned_netget_is_tied_test
```

The PTY command is:

```sh
cargo test --locked --no-default-features --features "$AUDIT_CPU_FEATURES" \
  --test terminal_snapshot child_lifecycle -- --test-threads=32
```

The filtered PTY invocation runs the inert lifecycle fixtures; it does not claim to run all
interactive terminal snapshots. The job already sets `NETGET_USE_OLLAMA=0`.

The native Windows resource job adds `process_group_windows_test`. Its fixture uses copies
of the test executable and Windows process handles, without shells, interpreters, network,
or models. It tests Job Object closure killing a child and descendant while an independent
job survives, and abrupt owner termination closing the owner's job without Rust destructors.
A readiness pipe prevents fixture descendants from being created before job assignment.

`pty-process` and `nix` move into Unix-only dev-dependencies; portable terminal parsing
remains in the shared dev-dependencies. This avoids requiring Unix process/PTY APIs when
building the Windows targets. Windows behavior is not inferred from a Unix pass: native
Windows execution remains a distinct result reported by its runner.

Other boundaries remain explicit:

- USB FIDO2 compilation uses the existing native dependency stack; the fixtures never access
  a USB device. They do not establish hardware interoperability or browser WebAuthn behavior.
- The gRPC fixtures use in-memory descriptors and reflection, not `protoc`, grpcurl, a live
  network peer, or a model. Existing interoperability coverage remains separate.
- Unix wrapper parent-death protection uses the existing death-tie mechanism and its documented
  assumptions. Simultaneously killing that independent reaper is outside the mechanism.
- Platform-gated tests excluded on the current host are not counted as runtime passes.
- No general fuzzing, benchmarking campaign, all-protocol runner, or protocol-maturity
  promotion is implied by these focused results.

## 9. Build-script invalidation follows its actual inputs

Previously `build.rs` emitted no explicit change inputs. Cargo therefore used its default
package-directory change detection, causing unrelated test or report edits to rerun the
build script and invalidate the library build.

The script now always emits `cargo:rerun-if-changed=build.rs`. When `etcd` is enabled, it also
tracks the `proto/etcd` directory and the `PROTOC` and `PROTOC_INCLUDE` environment variables,
which are the local schema/compiler inputs used by that conditional protobuf generation.
Non-etcd builds do not add irrelevant protobuf-toolchain watches.

This narrows unnecessary rebuilds without changing the generated code or runtime protocol
behavior. The report does not attach an invented speedup measurement to the change; final
build/lint results and their elapsed times are recorded separately.

## Final integration handoff

All twelve remaining recursion exceptions have implemented code changes and focused tests;
the recursion ratchet now permits no unbounded exceptions. The two wrapper exception
descriptions were corrected and removed, with concrete lifecycle fixes and fixtures added.
The peer-registration ownership hole is fixed through synchronous guard construction.

This report can be appended to the existing consolidated review as the follow-up
implementation record. Final machine-readable verification and publication details should
be appended by the coordinating agent after the remaining checks finish, without replacing
or rewriting the earlier review's historical test evidence.


## Final October 2 verification and change inventory

| Check | Result | Evidence |
|---|---|---|
| `remaining-native-final` | Passed; 233.33 seconds | [remaining-native-final](../../audit/2026-10-02/logs/remaining-native-final.log) |
| `wrapper-lifecycle-final` | Passed; 9.66 seconds | [wrapper-lifecycle-final](../../audit/2026-10-02/logs/wrapper-lifecycle-final.log) |
| `pty-lifecycle-final` | Passed; 3.0 seconds | [pty-lifecycle-final](../../audit/2026-10-02/logs/pty-lifecycle-final.log) |
| `integrated-native` | Passed; 81.65 seconds | [integrated-native](../../audit/2026-10-02/logs/integrated-native.log) |
| `integrated-clippy-final` | Passed; 38.35 seconds | [integrated-clippy-final](../../audit/2026-10-02/logs/integrated-clippy-final.log) |
| `node-regressions` | Passed; 0.73 seconds | [node-regressions](../../audit/2026-10-02/logs/node-regressions.log) |
| `formatting` | Passed; 35.05 seconds | [formatting](../../audit/2026-10-02/logs/formatting.log) |
| `module-reachability` | Passed; 118.3 seconds | [module-reachability](../../audit/2026-10-02/logs/module-reachability.log) |
| `workflow-yaml` | Passed; 0.11 seconds | [workflow-yaml](../../audit/2026-10-02/logs/workflow-yaml.log) |
| `integrated-wasm-build` | Passed; 311.08 seconds | [integrated-wasm-build](../../audit/2026-10-02/logs/integrated-wasm-build.log) |
| `integrated-wasm-smoke` | Passed; 4.03 seconds | [integrated-wasm-smoke](../../audit/2026-10-02/logs/integrated-wasm-smoke.log) |

Windows fixture compilation passed; native Windows execution is not claimed. The source fingerprint file is conservative and includes protocol sources beyond this run’s feature set. Build outputs are ignored local artifacts, not committed binaries.

| Changed implementation/test/build path | Bytes | SHA-256 |
|---|---:|---|
| `.github/workflows/ci.yml` | 86177 | `0f0310ffa453db2f239f37f54b5bffaecbab413661a1af5ff9f200b3338bc3de` |
| `Cargo.toml` | 55677 | `3179858ec131b413fee7a1053668122b53ec5a1f994dab95f58b963fa4a72ae8` |
| `build.rs` | 810 | `1af642a03ffa1034c7a0c48c4de83bd38cdb59b07bf9158b47d8d813007f2e58` |
| `src/client/grpc/CLAUDE.md` | 17343 | `809e27497e0f28f92a4fae16d6404328b87eafd79ad2aa27253db318b05f14ca` |
| `src/client/grpc/mod.rs` | 39991 | `6633de529b7d90f1ddfc24a20915e6165f7c2455d863f622cdfc5fbbaf994896` |
| `src/server/grpc/CLAUDE.md` | 17684 | `f677cfa17eec57ec8b3b1cd9f9690e2d1867baf31691702c4539462a6236e8fa` |
| `src/server/grpc/mod.rs` | 53133 | `70963f567a7fe459a2fd5b90ceba08c561d67b79b970b6c86eb072ee982d4878` |
| `src/server/grpc/value_codec.rs` | 14271 | `4a138266caace7c6050d0f35b23c4fba888d63830a8228b77c08d31c319c639b` |
| `src/server/ipp/CLAUDE.md` | 20111 | `350173f45540aa6eaac2fec082cf1b0934ee79108b769e04b3e320cae033f5c4` |
| `src/server/ipp/actions.rs` | 41282 | `789dafba4be7da1550b999d1eaa8639896dbd323df022f6929df585f88fea125` |
| `src/server/torrent_dht/CLAUDE.md` | 14357 | `ae6365129a060f325735661563d0f765bce4b60982257150ad35402950d58f00` |
| `src/server/torrent_dht/mod.rs` | 26730 | `ca1413ed80ab318063cc436fb59b094a24cba9f3bb33f0077442bd3aecac4ae2` |
| `src/server/usb/fido2/CLAUDE.md` | 19218 | `5d51837d2ef449e883986030b29a1ee886edba85adbed8157f82f0cabc67ea39` |
| `src/server/usb/fido2/mod.rs` | 48046 | `06ec8bb5f66381569739b52926ce7f78eadb39834ef6ab30380dade06cbed76f` |
| `src/state/app_state.rs` | 130679 | `1d7552505e1b21222554a8e052d1e7b867432abf23c717d6ee37637e8ae9be99` |
| `tests/audit_server_decoder_bounds_test.rs` | 15322 | `bcfd3cd81c7a5a823891d0ffecc483d9813203f025d9001739c6c6f81531320d` |
| `tests/e2e/netget_wrapper.rs` | 13443 | `09d9339f35638459be0899f177b6e4bcd5b775f4de6c2108946b5c60c05ad6c2` |
| `tests/grpc_value_bounds_test.rs` | 10818 | `6b71a7c1ff21cc3fd55a243abe5d2f1bad8821d95541ec428bec6624455a95fc` |
| `tests/helpers/wrapper_lifecycle.rs` | 5503 | `3eb69bf46ffd1baee40e90e55cf6254a34b0a4a26db3d0bac1a3cd8cda394556` |
| `tests/process_group_windows_test.rs` | 5677 | `f756fb4e111960d9e960e30fd810d4e23f5d7b99320c37189713e67e0d11d70f` |
| `tests/recursive_decoder_depth_test.rs` | 36678 | `22fee92d1a8bd4bae162ae5e57324b177cfaf49c8958f257941e09776817578c` |
| `tests/spawned_netget_is_tied_test.rs` | 5781 | `c56441a3f7ddb5faafa67ee0f37c005c7cf6e5fd894f0e0b8ce0d3c070808977` |
| `tests/task_registration_cancellation_test.rs` | 5260 | `380eae861e94075d11468dbbedf3ec1794c819bc73896c431258e897e0a830a0` |
| `tests/terminal_snapshot.rs` | 230 | `b67b4a31c622a18aff492a8dd34ca397fdd73e2e2292d9ef05e82c0199f84235` |
| `tests/terminal_snapshot/child_lifecycle.rs` | 3729 | `bc2507f01e52cea9a2ba8381bfc219238eae2a3891f4e88c5b86da54dce60300` |
| `tests/terminal_snapshot/mod.rs` | 37700 | `972326e5b6e9b4ab60cf59d3c9192490c416417e61ee06f3efc892120b57fe65` |
| `tests/wrapper_lifecycle_test.rs` | 2359 | `a54576167766861b79cb44f7463e07c97ec8d1d9995168990b8c69a774d976a4` |
