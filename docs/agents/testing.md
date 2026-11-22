# Testing

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Contents: test location policy · the mod.rs footgun · mocks · running tests and sweeps ·
terminal (pty) tests · whole-tree source ratchets. CI is in `ci.md`; the clean-baseline and
"load-flaky" lessons are under "Git" in `collaboration.md`.

Black-box and prompt-driven: the LLM (or a mock of it) interprets an instruction, and tests
validate the result with real protocol clients.

**Tests define expected behavior. When a test fails, fix the implementation, not the test.**
"The test passes but the implementation doesn't work" means you are not done. Only change a
test when its expectation is genuinely wrong.

## Test location policy (CRITICAL)

**All tests live in `tests/`. Never add `#[cfg(test)] mod tests` to `src/`.** Tests reach
internals via `use netget::` public APIs; make items public or refactor if needed.

**This policy was satisfied in September 2026 — zero violations**: no `#[cfg(test)] mod tests`
and no `mod tests` of any kind existed under `src/`. **It has one violation as of 21 November
2026**, named below the commands.

**The derivation command this section used to give is wrong, and produced five false
positives** — it matched *doc comments quoting the policy*, in `bluetooth_ble/mod.rs`,
`bluetooth_ble_beacon/mod.rs`, `etcd/mod.rs`, `grpc/mod.rs` and `oci_registry/actions.rs`.
Every one of those lines is prose explaining why the code does **not** have a test module.
This section then asserted the opposite of what the code did, in both directions over time,
which is a good argument for the anchored form:

```bash
# Real test modules only. The naive `grep -rln "#\[cfg(test)\]"` matches the comments too.
grep -rnE '^[[:space:]]*#\[cfg\(test\)\]' src/ --include='*.rs'
grep -rnE '^[[:space:]]*(pub )?mod tests' src/ --include='*.rs'
```

Both returned nothing in September 2026, and a hit from either is a real violation. Re-run
21 November 2026, the first returns one: `src/server/accept_bounded.rs` carries
`#[cfg(test)] mod response_drain_tests`, which still has to move into `tests/`. The second does
not see it, because it is anchored on the literal module name `tests`.

## The mod.rs footgun (CRITICAL)

`tests/server.rs` and `tests/client.rs` only compile submodules explicitly declared in
`tests/server/mod.rs` / `tests/client/mod.rs`. **A test directory that exists on disk but is
not declared is silently never compiled and never run — no error, no warning.**

This was the single largest hole in the suite — **15 of 116 server test dirs and 61 of 83
client test dirs were orphaned**, including complete, correctly-gated E2E suites for `arp`,
`whois`, `bitcoin`, `igmp`, `tls`, `sip`, and every USB protocol. All 76 are now declared, and
the `orphaned-tests` job in `.github/workflows/ci.yml` fails the build if it happens again.
Verify locally with:

```bash
comm -23 <(ls -d tests/server/*/ | sed 's|tests/server/||;s|/||' | sort) \
         <(grep -oE "pub mod [a-z0-9_]+" tests/server/mod.rs | awk '{print $3}' | sort)
```

Note `$3`, not `$2`: `grep -oE "pub mod <name>"` yields three fields and `$2` is the literal
word `mod`, so the version this file carried until now reported every directory as orphaned.

## Mocks

Default mode needs no Ollama. `tests/helpers/mock_ollama.rs` runs a real in-process axum
server implementing `/api/chat`, `/api/generate`, `/api/tags`. Configure with `.with_mock()`
and **always finish with `server.verify_mocks().await?`** — without it the test asserts
nothing about LLM interaction. An unmatched request returns HTTP 500 with a clear error, and
`verify_calls()` dumps full call history on mismatch.

**Call `wait_for_mocks(30)` before `verify_mocks()`.** A protocol exchange finishes with the
last LLM call it provokes, which is exactly what the expectations describe, so waiting on
them waits on the exchange. Suites used to sleep a fixed 1–2s and then verify, which is
enough alone and not when a hundred run together. It returns quietly on timeout —
`verify_mocks` remains the thing that asserts, and it names the rule that fell short.
`wait_for_any(&[needles], secs)` does the same job for output assertions.

**Rules are first-match-wins, and two rules on the same event with no way to tell them apart
is the most common mistake in this repo.** The first answers every occurrence and the second
reports zero calls; if the first answers with an action that produces the same event again,
it loops until something else stops it (99 calls, in one case). To express "then", use ONE
rule with `respond_with_actions_from_event` that branches on the event — a GET after a delete
returns count 0, a PUT response names the key it just wrote, an IMAP reply carries the tag.

**A response generator may carry state between calls, but only because it is now rendered
once per request.** `to_response_string` used to be called twice — once to build the routing
diagnostics and once for the reply — so a stateful closure advanced two steps per request and
answered the first request with the second answer. That cost real debugging time; it is fixed,
and worth not reintroducing.

**Check the event id and the action name against the protocol, not against the neighbouring
suite.** Whole suites were mocked against events their server never raises (`http_request` for
Elasticsearch, which raises `elasticsearch_request`), fields the event does not carry
(`uri` where it is `path`, and vice versa for HTTP/2), and actions the protocol cannot execute
(`send_http_response` to an OpenAPI server). None of these fail loudly: the rule simply never
matches, the request falls through to a real LLM call, the server answers an error, and the
failure surfaces two steps later on a different expectation.

UDP-style protocols (DNS, STUN, NTP, DHCP, BOOTP, TFTP…) **must** use
`.respond_with_actions_from_event()` to echo the client's random transaction/query ID back.
Static mocks with hardcoded IDs cause client timeouts. See `tests/server/dns/AGENTS.md`.

```rust
.on_event("dns_query")
.and_event_data_contains("domain", "example.com")
.respond_with_actions_from_event(|e| serde_json::json!([{
    "type": "send_dns_a_response",
    "query_id": e["query_id"].as_u64().unwrap_or(0),   // ← must be dynamic
    "domain": "example.com", "ip": "93.184.216.34"
}]))
.expect_calls(1)
```

Keep each suite under ~10 LLM calls: reuse servers, bundle scenarios, prefer script mode.
Bind to localhost only (127.0.0.1 / ::1); never contact external endpoints.

## Running tests

```bash
# Single protocol: select its suite by module path (every protocol is compiled in)
./cargo-isolated.sh test --test server -- server::tcp::e2e_test --test-threads=100

# Full sweep: the top-level targets in batches (each test binary links every protocol,
# ~870 MB; all ~230 at once is ~200 GB), then the protocol suites.
CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 scripts/test_batches.sh > /tmp/sweep.txt 2>&1
./cargo-isolated.sh test --test server --test client -- --test-threads=32 >> /tmp/sweep.txt 2>&1
```

**Never build every test target at once.** With every protocol in every build, each of the
~230 test binaries is ~870 MB unoptimised (debug info off), so a plain `cargo test` needs
~200 GB and filled this machine's disk in October 2026. `scripts/test_batches.sh` builds ten
at a time and deletes each batch's executables; CI's `test` job runs it, split five ways with
`SHARD=i/5` (`TARGETS` names an explicit list, as the `ratchets` job does, and anything after
`--` goes to every test binary).

**Checking the library alone peaks at ~12 GB of memory** (clippy, measured October 2026), which
is most of a 16 GB hosted runner. The heavy CI jobs add 16 GB of swap first; without it the
runner does not fail, it "loses communication with the server".

**`--test-threads=100` is right for one protocol and wrong for the whole tree**, and the
failure is not a test failure. `--all-features` builds ~29 test binaries that each link the
whole 137-protocol library; at 100 threads the run was **killed by the OS for memory pressure**
on a 96 GB machine (September 2026). "3GB+ RAM", which this section used to say, is off by an
order of magnitude. At 32 threads the same sweep is **172 targets, 3768 passed, 0 failed**.

**Redirect the sweep to a file and parse the file.** Two sweeps were mis-read in one day
because of how their output was handled, and both nearly got reported as clean:

- One died at `ld: write() failed, errno=28 (No space left on device)` while linking, **exited
  0**, and produced zero `test result` lines. Six concurrent `--all-features` target dirs is
  ~150 GiB; a seventh filled the disk.
- The other was piped through `tail -30`, which discarded almost every result line — it read as
  "29 targets, 154 passed" where the truth was 171 targets and 17 failures.

So: parse for a **non-zero target count** and a plausible total, never grep only for failures,
and never truncate the stream you are about to measure.

**Use `--test-threads=32` for a whole-tree or combined-feature suite; 100 is useful for
targeted stress runs.** If a test hangs, fix the hang rather than serializing the suite.

`./test-e2e.sh <protocol>` runs mocked; `./test-e2e.sh --use-ollama <protocol>` uses a real model.

## Terminal (PTY) tests

`tests/terminal_snapshot/` drives the real binary through a pty. Four traps cost a full debugging
pass each, and all four present as *product* bugs:

- **Write to the right end.** Bytes written to the pty **master** are delivered to the child as
  keystrokes; bytes written to the **slave** are what appears on the terminal. A test setting up
  "pre-existing screen content" on the master is typing it into the chat box.
- **`write_all` is unsafe once anything has set `O_NONBLOCK`.** A capture that drains until quiet
  has to; afterwards a write can return `EAGAIN` part-way and be abandoned, and `Pty`'s `Write`
  impl reports the short write as success. The symptom is a *truncated command*, which looks
  exactly like a UI dropping keystrokes. Retry against a deadline.
- **Never wait on a fixed sleep.** A 33-character command took ~1.3s to land in the old
  rolling TUI and longer under `--test-threads`. Wait for the condition (`PtyScreen::wait_until`
  keeps one vt100 parser for the whole test), then let the frame settle.
- **A capture that builds a fresh vt100 `Parser` from only the bytes read in that call is not
  idempotent.** Calling it twice renders the second from a blank screen. Polling needs one parser
  fed for the whole wait.

Also: `snapshot_util::assert_snapshot` **fails** on a missing or different snapshot and writes
what it captured to `<name>.actual.snap.md` beside it. Accepting is a deliberate step —
`UPDATE_SNAPSHOTS=1`, or `mv` the `.actual` file over the snapshot — so diff the two before you
do; a snapshot is only as good as the review of the screen it records.

## Whole-tree source ratchets

These tests scan **every** server and client protocol by reading source, so they hold on any
build — a registry-walking test only ever sees what that build compiled, which leaves out the
system-library and platform-gated protocols. Each carries a baseline that **may only shrink**,
and every numeric one has reached zero (re-derived 21 November 2026 — the figures here read 6
clients, 20 params and 18 examples for months after the work that removed them, so **read the
baseline out of the test file**, not out of this table):

| Test | Catches | Baseline |
|---|---|---|
| `client_event_wiring_test` | a client that asks the model and cannot act on the answer — including `if let Err(..)` with no success arm, `Ok(ClientLlmResult { .., .. })` dropping actions, `Ok(_) =>`, and count-and-log | **empty** (all three lists) |
| `event_emit_sites_test` | an `EventType` declared and never raised (the USB/BLE/imap defect) | **empty**, both trees |
| `startup_param_drift_test` | a startup parameter declared and read by nothing — an advertised knob that does nothing when turned | **empty** |
| `executable_examples_test` | an action whose own `example` its own `execute_action` refuses — the shape the model copies | **empty** |
| `event_action_declarations_test` | actions the model can never see, and advertised names the executor cannot run | — |
| `well_known_port_declaration_test` | a server with no declared well-known port and no stated reason; a `PrivilegedPort(n)` or transport disagreeing with it | `NO_WELL_KNOWN_PORT` — finished answers, not a queue |
| `startup_param_defaults_test` | a declared parameter `default` written as a literal instead of the constant the code uses (the type check is a registry walk) | **empty** |
| `hand_rolled_dual_logging_ratchet_test` | a `status_tx.send("[LEVEL] …")` beside a tracing macro instead of one `Log` call | **empty** under `src/server/` and `src/client/`; elsewhere in `src/`, one reasoned status-only site (`NOT_DUAL_LOGGING`) |

A third check worth understanding: `event_action_declarations_test` probes each advertised
name with a bare `{"type": name}`, which finds *unknown action* but can never find a wrong
**field**, because it never sends one. `executable_examples_test` sends the declared example
itself, and that is what caught `ospf` advertising `list_neighbors`/`list_lsdb` with no
executor arm, and `tor_relay_log` advertised under a comment claiming the executor "has always
handled it" when there was no arm at all.

**A source-reading ratchet must know both ways metadata is declared, and which direction it
fails in when it does not.** `ProtocolMetadataV2` is usually built through the builder
(`.state(…)`, `.connectionless()`, `.deliberately_silent()`, `.max_inbound_bytes(…)`), but it
can also be built by struct literal, where the same declarations read `state: …`,
`connectionless: true` and so on. One protocol does that today, `src/client/ospf/actions.rs`.

Ask which way a missed match fails:

- **`no_protocol_is_hidden_from_the_model_test` failed the dangerous way** and was fixed in
  September 2026. It looked only for `.state(…Incomplete)`, so a protocol hidden from the model
  in the literal form would have passed. Hidden is invisible by construction, so nothing else
  would have caught it either.
- **The other three fail the safe way.** `connectionless_audit_test`,
  `failure_mode_declaration_test` and `max_inbound_bytes_declaration_test` each require a
  declaration to be *present*, so an unrecognised form reads as "declares nothing" and is
  flagged. A false positive costs a reader five minutes; a miss costs months.

Two lessons from building them, both about false positives rather than misses. **Detect at the
right nesting depth**: an `Ok(_) => {}` catch-all on an inner `match protocol.execute_action(..)`
is correct and everywhere, and a substring version of that check flagged `ntp` and `tor` while
they executed the model's actions perfectly well. And **for a build-failing check, prefer the
conservative rule**: the strict version of the startup-param scan flagged 57 client parameters,
of which many were read through `get_protocol_field` or a helper — a false positive trains
people to edit the baseline instead of the code.

The blocking gate is deliberately not `--all-features`: that needs system libraries the runner
does not install (`libpcap`, `dbus`, `libusb`, `pcsclite`). It compiles every protocol that
needs none of them and **runs the suites of six** (`CI_PROTOCOL_TESTS` in
`.github/workflows/ci.yml`) — a green PR says nothing about any other protocol's suite. Run the
relevant tests yourself before claiming done.
