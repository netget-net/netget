# NetGet Improvement Backlog

Living backlog of known defects and hardening work, ordered by impact. Not a session
report — delete entries as they are fixed, add as they are found. Every entry cites a
file:line so it can be verified independently.

Findings marked **[verified]** were reproduced against a binary built from HEAD.
Findings marked **[static]** come from code reading only.

---

## START HERE — what to do next

Four sections: **START HERE** (here), **Fixed** (index of what landed and where the reasoning
lives), **Open** (genuinely outstanding), **Archive**.

Do not trust a count in this file over the tree; derive it. This document once listed 48 open
items when fifteen were already fixed and seventeen were findings rather than work.

### State

`DevelopmentState::Incomplete` is down from twelve to **zero**. The last one,
`bluetooth_ble_beacon`, was a platform limit rather than unfinished work, and was closed by
implementing the BlueZ path and making the macOS refusal explicit — see the maturity section of
`CLAUDE.md`. `Stable` is also **zero** now (`wireguard` demoted — see item 10).

A large protocol-and-features wave landed August 2026 on top of that: **21 new server protocols**
(named_pipe, pty, stdio, rtp, rtsp, hls + real SIP RTP, snowflake, db2, yarn, spark, reverse_shell,
rdp, modbus, coap, websocket, kubernetes, oci_registry, radius, memcached), plus stability gating
(`/stability` + `--min-stability`), resident scripts, the `pipe` event-forwarding tap, the
create/update management surface, and the static-default conversion of nine mechanical protocols.
`--all-features` is green throughout. It was built by ~10 concurrent agents and cost the fifth
shared-index incident (see the Git section of `CLAUDE.md`, now with the `GIT_INDEX_FILE` fix) —
history is misattributed in places but nothing was lost and the tree self-healed.

Measured at `5d18c9fb` in a throwaway worktree, not on a dirty tree:

| Check | Result |
|---|---|
| `cargo test`, CI feature set | **486 passed / 0 failed / 37 ignored** (run twice, identical) |
| `cargo check --all-features --tests` | clean |
| Registry audits at `--all-features` (6 binaries) | **53 passed / 0 failed** |
| `cargo fmt --check` | clean |
| clippy `-D correctness -D suspicious --all-targets` | clean |
| `protocol_startup_smoke_test` | see below |

**Every registered protocol has now been started through the real startup path**
(`tests/protocol_startup_smoke_test.rs`, wired into the advisory `registry-audit` CI job).
**121 servers registered, 92 listening** — 76 accepting a TCP connection, 16 holding a datagram
socket, 3 running without a socket by design. **26 refuse cleanly, 0 defects, 0 port leaks, 0
hangs, 0 panics.** The 26 refusals are all honest environment limits on this unprivileged macOS
host: 15 BLE profiles with no adapter, 3 raw-socket, 3 packet-capture, `wireguard` (root), and
four platform refusals. Clients: 91 registered, 44 refuse cleanly, 0 hung, 0 panicked.

That "0 defects" line is the one worth re-deriving rather than trusting — it means no protocol
reported `Running` while nothing was listening, which is a bug this repo has shipped four times
(arp, datalink, icmp, isis). The harness checks *listening*, not merely *bound*, because its
first version did not and would have passed a socket that never called `listen()`.

Three gates were added because the green result was worth less than it looked (see archived
items 5, 79, 80, 81):

* **`orphaned-tests` now checks files, not just directories.**
  `.github/scripts/check-module-reachability.sh` resolves the real module graph and fails on any
  tracked `.rs` under `src/`/`tests/` that no `mod` statement names, with an explicit
  `.github/unreachable-modules.txt` allowlist for the six known-dead modules. It also runs
  rustfmt over every tracked file, which is what closes the formatting hole — `cargo fmt` has no
  feature flags and does not evaluate `cfg`, so **undeclared** modules, not cfg-gated ones, were
  the only files it never saw.
* **The blocking clippy gate gained `--all-targets` and `terminal-snapshot`.** Without those it
  linted the lib only, exempting ~200 test files, and two `clippy::suspicious` violations were
  living there — one of them leaking a live `netget` process per run.
* **A `Drop` guard that panics** when a mock config carrying expectations is never verified.

A second-pass protocol audit (2026-08-11) confirmed the four classic defect classes are now
largely closed and **retired three items as stale — verified, not assumed**: item 39 (DNS Beta
tests fail — false, `server::dns` is 5/5), item 47 (ntp asserts nothing — now 27 asserts + a real
`rsntp` client), item 76 (nfs/ipp/vnc/webdav transport-only — all decode payloads now). Their
entries below are kept only as archive.

### Closed in the August 2026 backlog wave

A parallel wave cleared most of the discrete open items (all verified against the current tree):
`grpc` empty-`OK` fail-open → `INTERNAL` (`107c6c87`); MCP scheduled tasks now fire via a 1s
ticker in both `--mcp`/`--mcp-http` (`1fb979d8`); `bluetooth_ble` `block_on` removed and the
first-start poisoning fixed with a process-wide shared `Peripheral` (`6394895e`); WireGuard's
authorize flow made reachable via a `wireguard_add_peer` pre-authorization action (`a57f7145`);
the `stdio` pipe-filter unblocked and its stdout kept clean (`50513c4d`); 13 stale per-protocol
`CLAUDE.md` files refreshed (`a19c6592`); and the "too much LLM" family (`stun`/`ntp`/the
routing-discovery protocols) was already static-defaulted earlier. Some of these landed as CODE
fixes whose end-to-end validation still needs hardware — see item 2 below.

### Still open

Re-derived from source on 26 September 2026. Seven items in "Open — actionable" below were
already fixed and are now marked so in their headings (7, 9, 16, 32, 39, 42, 50).

1. **`bluetooth_ble_beacon` on real Linux hardware.** *(Implemented, unverified.)* The BlueZ
   path has never been compiled or run on Linux; first use is bring-up via the `#[ignore]`d test
   in `tests/server/bluetooth_ble_beacon/e2e_test.rs` and `btmon`.
2. **Real-hardware validation of the BLE and WireGuard fixes.** Neither has been driven end to
   end: BLE needs an adapter, WireGuard needs root and a backend. WireGuard is `Experimental`.
3. **`pgwire` malformed-query panic (item 77)** — upstream; kills one connection task only.
4. **`AppState` is one `RwLock` over everything (item 23)** — a throughput ceiling.
5. **The `easy` layer (item 35)** — still present (`src/easy/http`). Finish or delete.
6. **Startup does not consult the dependency system (item 20b)** — **fixed 26 Sep 2026**: all
   four `start_*` paths refuse a definitively-missing library or tool; see the item.
7. **`REQUIRE_DOCS_FOR_OPEN_ACTIONS` (item 29)** — a hardcoded `false` guarding a gate nobody
   enables; make it a runtime setting or delete it and its state.
8. **ARP and DataLink are absent from the Linux `dist` set (item 54).**
9. **Connect events fire only with `send_first` (item 78)** — **fixed 26 Sep 2026**
   (`527e07f3`) for `tcp`, `telnet` and `tls`; `socket_file`, `pty` and `stdio` still gate theirs
   on `send_first`. See the item.

10. **Logging long tail.** 111 of 153 server `mod.rs` files use the `Log` facade
    (`src/logging/emit.rs`); 42 still hand-roll dual logging. Derive with
    `grep -L 'Log::new\|crate::logging::Log' src/server/*/mod.rs`.

11. **RTP failed the startup smoke test once in CI, and passes otherwise (item 82).** See below.

### Patterns worth auditing for

**Collapsing "the handler declined to decide" into "the handler could not run."** This is the
general form of the OAuth2 disaster and it kept recurring: MQTT answered `CONNACK 0 = ACCEPTED`
when the LLM call failed, so an outage admitted every client and a model's denial was
indistinguishable from a dead backend; the proxy defaulted to `Pass` and forwarded unfiltered,
while its HTTPS twin always blocked; LDAP's search answered resultCode 0 with zero entries,
which is *success* meaning "nothing matched", so an outage read as a directory decision. In every
case the permissive default was right for "the model considered this and had nothing to add" and
catastrophic for "the model never ran". **Wherever a protocol has a default for "no answer",
check what a backend failure reaches.**

**A mechanism fully built and wired, with nothing flowing through it.** Found repeatedly:
`get_dependencies()` with every protocol inheriting an empty default; `PacketCapture` defined
with zero adopters; `EventType.actions` rendered with 22 events attaching nothing; `netgauze`,
`webrtc-turn` and `lapin` declared as the only dependency of the protocol they were supposed to
implement and never called. **Assert adoption, not mechanism** — a test that checks the
machinery works while nothing uses it is the thing that let all of these survive.

**A test that cannot fail.** An assertion-free body, a swallowed error, a capability check that
returns `Ok(())` when the capability is missing, an async call without `.await`, a mock rule that
matches nothing (`on_event("*")` was compared literally), a suite that starts a server and never
connects a client. These count as passing coverage, which is worse than none because it is
counted.

Two further shapes, both found repeatedly in this sweep and neither visible by reading the test
alone:

* **A suite written against a vocabulary the code never had.** `tests/server/proxy/test.rs` named
  events with a `_received` suffix that does not exist and actions like `proxy_forward_request`
  when the real one is `handle_request_pass`; the IRC client suite named `irc_data_received` for
  `irc_message_received`; the SSH suite mocked `sftp_readdir`/`sftp_stat` when the server emits
  one `sftp_operation` event with an `operation` field. No rule ever matched — and because the
  protocol did something reasonable anyway, the assertions still passed while the LLM path was
  entirely dead. `tests/mock_action_names.rs` now catches the action half.
* **A suite that asks for a feature in prompt prose but never passes the `startup_params` that
  enable it.** The couchdb basic-auth test asserted a 401 that came from its own *mock*, not from
  the server, because `AuthConfig::enabled` was false the whole time. Worth a sweep.

**Two mock rules with identical matchers.** Rules match in declaration order and the first one
answers, so the second never fires and one rule replies twice. It surfaces only at
`verify_mocks()`, long after the wrong bytes went out — and if `verify_mocks()` is missing, never.

**An `#[ignore]` citing a defect elsewhere.** It goes stale silently when that defect is fixed.
43 tests were parked on one such reason.

**Measurement under load.** The suite has a 120s server-startup timeout, `target/debug/netget` is
shared so a concurrent build silently breaks another run, and the first run after a source edit
relinks that binary. All three produce failures indistinguishable from real ones. Use a private
`CARGO_TARGET_DIR`, run twice, and never conclude from a single run — a mutation test nearly
recorded a false negative this way.

## Fixed

Items below are resolved; kept here with their commit so the reasoning stays findable.
Delete an entry once its context is no longer useful.

| Item | Commit | What landed |
|---|---|---|
| 7 — unknown action names silent | (earlier) | `validate_static_action_names` rejects a bogus action at startup |
| 9 — MCP scheduled-task leak | `82034d3d` | `remove_server()` owns teardown; MCP-surface coverage added so a rewrite cannot silently drop it |
| 29/50 — dead documentation gate | (earlier) | One gate remains, behind a documented compile-time `false`; the second is gone |
| 32 — validator accepted a superset | `272acbc0` | `advertised_user_input_actions()` narrows to what the prompt rendered, mirroring the network-event path |
| 39 — doc gate broke mocked tests | (earlier) | The retry no longer fires; 35 tests recovered from the `#[ignore]` it caused |
| 78 — connect events fired only with `send_first` | `527e07f3`, then narrowed | `telnet_connection_opened` is raised for every connection, answered by a zero-action rule on dashboard servers via `EventType::raised_on_every_connection()`. `tcp_connection_opened` and `tls_connection_opened` stay gated on `send_first`, and their event and parameter descriptions now say so: raising them everywhere cost a model call per connection and cut the real-model eval's `tcp` score from 15/15 to 10/15. |
| 47 — tests passing while broken | `1b7f26e5`, `180c01ac`, `f0c7e42c` | NTP now requires the client to succeed; three assertion-free tests no longer count as coverage; the FIDO2 test awaits the future it was only constructing |
| 76 — transport-level-only asserts | `1e989ba5` | nfs/ipp/vnc/webdav decode and assert real protocol output |
| — 43 stale blanket `#[ignore]`s | `025ff3f5`, `2e3c8fbc`, `8009299b` | svn/whois/USB/bitcoin/sip/tls running; arp/igmp ignored for the real privilege reason |
| — USB family non-functional | `2eed8ed9` | usbip 0.3.1 needs tokio 0.3; its server panics on every attach. Five protocols demoted to Incomplete |
| — DNS client tests flaky | `8f670500` | Ran against 8.8.8.8; now a local server. Three identical runs had given 1, 2 and 3 passes |
| — live-internet test ungated | `7dc810cc` | web_search gated behind `NETGET_USE_NETWORK` |
| — src/ test-policy violation | `9f1aade0` | 32 unit tests moved to `tests/`; `grep -rln '#\[cfg(test)\]' src/` is now empty |
| 20b — startup ignored dependencies | `353a03fd`, then 26 Sep 2026 | Non-privilege deps enforced at startup; gRPC declares its runtime `protoc` so the gate is not decorative. The first pass gated only `start_server_by_id`; all four `start_*` paths now go through `dependencies::startup_blocker`, which refuses only a dependency the probe established is absent |
| 8 — verified fixed | (earlier) | ARP/DataLink/ICMP now await readiness via a oneshot and propagate bind failure, so a capture failure reports Error not Running |
| 14 — verified fixed | (earlier) | `read_documentation` is in TOOL_ACTION_NAMES; is_tool() no longer misreports it |
| 15 — verified fixed | (earlier) | `ConversationHandler::trim_history` exists and is called; history no longer grows unbounded |
| 17 — verified fixed | (earlier) | git/mercurial no longer call generate_with_retry directly |
| 18 — verified fixed | (earlier) | server_startup gates on `PrivilegeRequirement::is_met_by()` alone; the ANDed capability is gone |
| 30 — verified fixed | (earlier) | `register_server_task` keeps a per-server `Vec` and prunes finished handles |
| 34 — verified fixed | (earlier) | `src/server/vpn_util/` deleted along with the dead `packet` module |
| 37 — verified fixed | (earlier) | `interpolate_actions` gives static handlers access to event data |
| 40 — verified fixed | (earlier) | svn no longer declares an unreachable PrivilegedPort; ospf declares RawSockets rather than Root |
| 41 — verified fixed | (earlier) | `ExecutionResult::failures` recordsper-action failure; executor logs at error! and continues |
| 49 — verified fixed | (earlier) | DNS client drains iteratively; stack depth is constant regardless of round-trips |
| 55 — verified fixed | (earlier) | `has_packet_capture_access` split from `has_raw_socket_access`, each probed separately |
| 60 — verified fixed | (earlier) | `PrivilegeRequirement::DeviceAccess(DeviceClass)` added and adopted |
| 63 — verified fixed | (earlier) | saml_idp and saml_sp both have e2e_test.rs, mod.rs and CLAUDE.md |
| 69 — verified fixed | (earlier) | connection registered synchronously before any task is spawned, in all four protocols |
| 65 — placeholder response examples | `3e5b5f7a` | `effective_response_example()` derives a real example from the event's first attached action; guard test pins the rendered property, so the 215 literals can be swept incrementally |
| 46 — no single-feature CI | `5bed7583` | `single-feature` job runs `cargo check --tests` over 14 protocol features one at a time — the only way to catch an under-declared feature |
| 20 — dependency system inert | `2a48ccfb` | `get_dependencies()` derives from `privilege_requirement` instead of 116 restatements. Also fixed `PromiscuousMode` reading the raw-socket flag instead of the capture flag |
| — ARP/DataLink/IS-IS misdeclared privilege | `f48e26da` | Declared `RawSockets`; they do layer-2 capture. A macOS ChmodBPF user was hard-refused three protocols they can run. `PacketCapture` had existed with zero adopters |
| — Kafka client was dead code | (this change) | Reimplemented on `kafka-protocol` in the client direction, sharing the broker's re-export and its `encode_field`/`decode_field`. `rdkafka`/librdkafka removed from `Cargo.toml` and from `all-protocols`; the module is gated on `feature = "kafka"` alone. Four `#[ignore]`d tests replaced by two mutation-checked E2E tests driving NetGet's own broker |
| — CLAUDE.md drift | `9949fb5d` | Maturity ratings, four fixed-but-still-documented bugs, and an orphan-check snippet whose `awk $2` reported every directory as orphaned |
| 56 — events with no action vocabulary (remainder) | `0619bab9` | Last 22 events; all 8 SSH-Agent events were affected, so that whole protocol reached the model with no vocabulary. Four events that genuinely have none now say so with `.with_no_actions()`. `KNOWN_MISDECLARED` is empty |
| 31 — async actions had no live state | `e5f58be9`, `da5cf2f0` | Type-erased server-handle registry, then the defaulted `Server::execute_action_with_state` and the executor call site |
| 10 — vestigial instance handles | `652d452d` | Deleted `ServerInstance.handle`/`ClientInstance.handle`; they were the only reason the structs could not derive `Clone`, which forced four hand-written field-by-field copies that silently dropped new fields |
| 5 — keyword land-grabs | `68d4e8c4` | TCP no longer claims `"ftp"`; TFTP no longer claims bare `"file"`/`"transfer"`. Two test assertions encoded the old behaviour and were wrong |
| 4b — the 4 `client::udp` failures | `292e5794` | Broken tests, not product bugs: a case-sensitive matcher against `"via UDP"`, a server mock answering `open_client`, and client configs with no mock calling `verify_mocks()` |
| 2 — TCP hex never decoded | `d70bb5b5` | Explicit `encoding` field on `send_tcp_data`/`send_to_connection`, defaulting to `utf8`; inbound events now carry `encoding` too, so echo is symmetric |
| 3 — UTF-8 truncation panics | `b9aa1058` | `src/utils/truncate.rs` with char-boundary helpers; 24 sites across 8 files; model-facing cuts now carry a truncation notice |
| 4 — feedback loop always failed | `b7c9a204` | Advertised and validated action lists are now the same filtered list |
| 6 — no CI | `45b8bde4` | PR/master workflow: blocking clippy correctness+suspicious, tests on a feature subset, and an orphaned-test-dir gate |
| 24 — scripts parked worker threads | `efd990e5`, `c3d92a16` | `tokio::process`-based async executor; both call sites switched |
| 25 — unbounded stdin deadlock | `efd990e5` | stdin write, stdout/stderr drain and `wait()` joined under one timeout; child reaped on timeout |
| 26 — script trust boundary undocumented | `65ed6bcf` | `src/scripting/CLAUDE.md` leads with the arbitrary-code-execution boundary |
| Scheduled tasks could never act | `2789cb40` | Same empty-action-list bug as item 4, in the scheduled-task path; found while fixing item 4 |
| Runtime prompt was 81% irrelevant | `73d334c8` | Dropped the handler-configuration tutorial from the per-event template: system prompt 11853 → 2219 chars, request 16377 → 8230 bytes |
| 11 — MCP docs described the wrong API | `40907b06` | New `src/mcp_stdio/docs.rs` renders MCP-shaped docs (event field names, action schemas, startup params, privilege); `open_server`/`open_client`/`base_stack` no longer appear, asserted by a test |
| 12 — no MCP client surface | `f1f25528` | `start_client`/`stop_client`/`list_clients`/`client_status`; client half of `list_protocols` now carries maturity and description |
| 13 — `send_first` ignored | `de5d9e19` | Folded into `startup_params` for the 8 protocols that declare it; warns rather than silently ignoring elsewhere. `interface`, `mac_address`, `initial_memory`, `feedback_instructions`, `scheduled_tasks` also un-hardcoded |
| 19 — ARP/ICMP absent from releases | `748fccca` | `arp` added to `dist-darwin`, `icmp` to `dist`; ICMP deliberately excluded from Windows, where `pnet` unconditionally links WinPcap |
| — registry couldn't say "compiled out" | `d58854ca` | `resolve()` on both registries distinguishes not-compiled from unknown, with a did-you-mean suggestion (adoption pending, item 36) |
| — unbounded `netget.log` | `c14c8b71`, `e3617126` | Size-based rotation (50 MiB × 5 generations ≈ 300 MiB ceiling), wired into `init_logging`; the repo's log had reached 481 MB in a day |
| — clients unreachable by lowercase name | `f1f25528` | `CLIENT_REGISTRY` is keyed by each protocol's own casing and lookup was exact-match, so `protocol: "tcp"` failed. Also, `client_startup.rs` dropped its status receiver, silently discarding every client status message |
| — VPN family misrepresented | `10f1e2b4`, `2bce6e64`, `f013c510` | OpenVPN demoted to `Incomplete` (identical keys for all peers, no TLS handshake) plus a TUN deadlock fix; WireGuard's advertised LLM control did not exist and now does; IPSec now actually calls the LLM |
| — DNS answers rejected by real resolvers | `6a384617` | Responses carried no question section, so glibc/systemd-resolved/`dig` discarded them. Verified after the fix: `dig @127.0.0.1 example.com A` returns NOERROR with the question echoed and the transaction id matched |
| — remote unauthenticated panic in DHCP/BOOTP | udpinfra pass, `b06165fc` | dhcproto never validates `hlen` and `Message::chaddr()` slices a `[u8; 16]` with it, so **one datagram declaring `hlen > 16` panicked the socket task** — server dead, status still `Running`. Guarded on the server, and on the client's receive path where the same unguarded call let a malicious DHCP server kill the client |
| — NTP never echoed origin timestamps | udpinfra pass | Beta was false: real clients rejected every reply. The code mutated `execution_result.raw_actions` *after* `call_llm` had already executed the actions and built the packet, so the injection never touched a byte. Fixed with a per-datagram protocol instance; verified with a raw client |
| — DHCP correlation race across clients | udpinfra pass | `xid`/`chaddr` lived in one `Arc<Mutex<Option<_>>>` shared by the whole server, written just before a multi-second LLM call, so two overlapping clients echoed each other's transaction id |
| — SNMP BER lengths wrapped at 256 | udpinfra pass | Every length used `0x81 + len as u8`, so any response ≥256 bytes (a long sysDescr, a multi-binding reply) produced a corrupt packet |
| — Syslog filters could never match | udpinfra pass | `facility`/`severity` were emitted with `{:?}` as `log_kern`/`sev_err` while every doc and example prompt says `kern`/`err`. Numeric codes added alongside, which is how the docs describe filtering |
| 5 — 76 orphaned test directories | `87e02967`, `84a4fb24`, `1e842bf0`, `9fd32787` | All 15 server and 61 client directories wired in; both orphan sets are now empty, so the CI gate added in `45b8bde4` passes |
| 45 — mock harness misrouted the docs step | `98c54d4e` | Context extraction classified the *startup* call as an `http_request` event, because the documentation retry embeds `### Event: <id>` headings. Now classified on the prompt template rather than wording. **`--test server` 5/24 → 18/24, `server::tcp` 0/10 → 10/10, `server::dns` 0/4 → 4/4, `--test examples` 13/34 → 34/34, `--test client` 5/9 → 12/13** |
| — tests phoning external endpoints | `da4c86f5` | The DoT and Git client tests connect to `dns.google:853`, `1.1.1.1:853` and `github.com`. Harmless while orphaned; wiring them in made the calls live, violating the localhost-only policy |
| 51 — remaining HTTP test failures | `2528629` | 7/10 → 10/10 in `tests/server/http/`; mocks keyed on `uri` where the event emits `path`, and a `write_file` action HTTP does not have, replaced with the real `append_to_log` |
| 1 — `StartupParams` panicked on model input | `a9f03fd6` | All 16 panic sites return `Result`; 163 call sites across 74 protocol modules converted. Params are now validated *before* `add_server`, so a rejected request leaves no orphan. Verified over MCP: an undeclared key went from **no JSON-RPC response at all** (caller hangs, server stuck in `Starting`) to a clean tool error naming the key and listing the allowed ones, with `list_servers` empty |
| 36 — registry `resolve()` unadopted | `a158da2f` | `start_server` now answers `Protocol 'ARP' exists but is not compiled into this build (rebuild with --features arp)` and `Unknown protocol: 'htpp'. Did you mean 'HTTP'?` |
| 18 (rest) — gate ANDed the wrong capability | `aa713be3` | Both sites (`:72`, `:417`) now test `PrivilegeRequirement::is_met_by()` alone; a failed `spawn()` also drops its registration instead of leaving a zombie `Error` row |
| — test targets broken under narrow features | `57a4c42f` | `server_stop_releases_port_test` (stale arity after `ec79eda5`) and `examples` (empty feature-gated vec, E0282) failed to *compile* with `--features telnet`, silently disabling every test in those targets |
| — proxy/tunneling family | `2cf3d4f2`, `ec4231ab`, `a3e101a9`, `a0d8a6cb`, `32a30f83` | Suite went **21 failures → 5**. Proxy's certificate cache returned a regenerated certificate paired with the *cached* key, so every repeat MITM connection to a host failed with `KeyMismatch`; `certificate_mode: "load_from_file"` read the operator's key, **ignored the certificate file entirely** and minted a different CA, so clients trusting the real one rejected everything while the config looked correct; absolute-form request targets were forwarded verbatim, which `curl --proxy` caught and our tests never did. SOCKS5 ended three paths with no reply at all. TLS had the `d70bb5b5` defect again — hex documented, never decoded. TURN demoted to `Incomplete`: it cannot relay a byte, as no relay socket is ever bound |
| 56 (part) — STUN's actions were invisible | `a0d8a6cb` | STUN's event never called `.with_actions(...)`, so every response was rejected as unknown; five E2E tests failed. Its shipped static example also used three nonexistent fields and a 6-byte transaction id |
| 43 — `Http2Server` dead code | `a9ae64c9` | 349 lines removed; `src/server/mod.rs` now exports the live `H2Server`. That dead path is why HTTP/2's `request_filter` was silently inert |
| 66 — `http_common` gated too narrowly | `ab04a5c2` | Gate widened to include `oauth2`, `openid`, `saml-idp`, `saml-sp`; all its deps are unconditional so it costs nothing. Four local `build_safe_response` copies are now deletable by those files' owners |
| 44 — connection stats never updated | `515b8b7a` | **My justification was wrong and the truth was worse.** The TUI never renders these counters. The real reader is `cleanup_old_connections`, which retains only connections with `last_activity` under 10s and runs in both the TUI loop and the MCP reaper — so with `last_activity` frozen at accept time, **every HTTP connection was evicted from the state map ~10-15s after opening, while still serving**. Measured: `t=0s {0,0}` → `t=15s {'connection': None}` before; `t=28s {0,422}` after. Connection-scoped scheduled tasks also fed those constant zeros straight into the model's prompt, so the idle-timeout use case CLAUDE.md advertises was reading nothing real |
| 29 + 39 + 50 — two documentation gates | `ab04a5c2` | `REQUIRE_DOCS_FOR_OPEN_ACTIONS` now gates both halves; the `DocumentationRequired` retry was unconditional. Measured A/B on the DNS suite: doc-gate round-trips **4 → 0**, total LLM requests **13 → 9**, same 4 tests passing. Note MCP `start_server` never went through this gate — it calls `start_server_from_action` directly |
| 52 — `scheduled_tasks` created silently | `ab04a5c2` | The `open_server` array path now logs like the standalone `schedule_task` action |
| 33 — dev builds defaulted to TRACE | `ab04a5c2`, `d6225b03` | Now DEBUG. TRACE is the only level carrying full payloads and full prompts, so it was both the 481 MB/day problem and a credential-disclosure one; `--log-level trace` is unchanged |
| 28 — `--api-key` world-readable | `c81ab797` | Warns once per process on stderr (never stdout — MCP carries JSON-RPC there); help and the missing-key error name the env vars first |
| 27 — no CLI client entry point | `767f47e2` | `--client <PROTOCOL> --connect <ADDR>` plus `--client-params`, `--client-handlers`, `--client-list`, routed through `start_client_from_action` |
| 70 — `--load` panicked; phantom "listening" | `f5092b35` | `--load` built a second tokio runtime inside `#[tokio::main]` and panicked on every use. Also, port 0 is never a real bound port, so unbound spawns now log `(no listening socket)` instead of `listening on 0.0.0.0:0` |
| — piped stdin was swallowed | `c8938396` | `get_actions_json()` and `get_prompt()` each called `read_to_string()`; the first drained the pipe and the second saw EOF, so `echo '…' \| netget` always failed with "Cannot start in interactive mode without a terminal" |
| 22 (part) — 46 stale root docs | `ab04a5c2` | Root went 64 markdown files → 18. The removed 46 were single-run artifacts (instance reports, mock batch logs, timestamped test analyses, compilation-fix logs), none touched since Nov 2025, several contradicting current code — which is the actual harm, since a reader cannot tell live from stale. Recoverable via `git show <commit>^:<file>` |
| 59 — BLE taught an unparseable UUID | `ab04a5c2`, `66d568f4` | `parse_ble_uuid` expands the 16- and 32-bit shorthands the protocol's own examples and docs use; `Uuid::parse_str("180D")` had always failed. 7 tests |
| — clippy `never_loop`, and the bug behind it | `cfc11d3e` | `s3` and `npm` looped over `protocol_results` with an unconditional `return`, so they examined exactly one result. The lint was pointing at a real defect: both returned a fallback (empty 200 / 500) for anything unrecognised, so a model emitting the documented `show_message` + response pair lost its real answer. Both now return `Option` and the caller scans |
| 7 + 41 — action failures were invisible | `5deee649`, `0069d90c` | Static handlers naming a nonexistent action are now rejected at `start_server` with the valid list; execution failures are recorded as `FAILED: <name>` in the access log with the error and original action, and logged at `error!`. Batch semantics are continue-and-report, not abort — aborting would suppress the valid actions after a bad one |
| 18 (part) — raw-socket gate never fired | `c9a65c80` | `has_raw_socket_capability()` used `pcap::Device::list()`, a `getifaddrs` wrapper that succeeds for any user, so it always returned true and the pre-flight never ran. Now probes a real `SOCK_RAW` socket plus `/dev/bpf*`. `is_running_as_root()` also fixed — it stat'd `/root` and compared `$USER`, so `sudo -E` and most containers fooled it |
| — raw-socket family started but did nothing | `1e977cbe`, `b58b5788`, `21b09483`, `4204bbbc` | ARP, DataLink and ICMP opened their privileged handle in a fire-and-forget `spawn_blocking` and returned `Ok` unconditionally, so an unprivileged start sat in `Running` capturing nothing forever. Now report readiness. Also fixed IGMP's `from_raw_fd`-before-check unsoundness, a checksum underflow, a 100%-CPU spin on recv error, and a `"lo"` default that does not exist on macOS |
| — HTTP family defects | `3c414406`, `f2d4cf3e`, `e9eec1cb`, `e32cf485` | 204 responses were served as empty 200; a model status of 999 or a CRLF header panicked the connection task; HTTP/2's `request_filter` was accepted and silently ignored because the hyper path is dead code; HTTP/3 documented as the QUIC transport it actually is |

### Independent verification after landing

Each of these was re-checked against a freshly built binary, driven over MCP stdio, separately
from the agent that made the change — because several of the bugs above were ones our own
tests had been passing straight through.

- **Script handler + TCP encoding together**: a Python handler returning
  `{"data":"48454c4c4f","encoding":"hex"}` puts `HELLO` on the wire, with no LLM call.
- **DNS against `dig`**: `dig @127.0.0.1 -p … example.com A` returns `status: NOERROR` with the
  question section echoed and the transaction id matched — the real-resolver check the Beta
  rating always implied.
- **NTP against a raw client**: 48-byte reply, version 4 echoed, mode 4, and the origin
  timestamp byte-identical to the client's transmit timestamp (`1d7a39180519de39`). Driven
  through a *static* handler, so the per-datagram fix holds on the zero-LLM path too.
- **DHCP remote panic**: a datagram declaring `hlen = 255` no longer kills the socket task —
  the server answered a well-formed request afterwards, echoing xid `deadbeef`, confirming both
  the panic guard and the per-datagram correlation fix.
- **The committed tree**: `cargo check --all-features` in a clean worktree at HEAD finishes in
  5m00s with **zero errors**. Worth re-running this way rather than in the working tree, which
  during heavy parallel work is routinely mid-edit and produces failures belonging to nobody.
- **TUI logging**: the rotating writer is exercised on the interactive path — netget started
  under a real PTY produced a well-formed `netget.log` through `RotatingFileWriter`. The
  interactive branch of `init_logging` is the only consumer, so a compile check alone would not
  have shown this.

---


---

## Open — actionable

Everything below is genuinely outstanding. Items verified fixed have moved to the Fixed
table, and historical findings to the Archive.

### 7. Unknown action names fail silently at runtime **[fixed — re-verified 26 Sep 2026]**

> Fixed: static handler action names are validated at parse time (`validate_static_action_names`, `src/events/handler.rs`). The text below is the original finding.
A static `event_handler` naming a nonexistent action is accepted at startup and does nothing
when the event fires: the peer gets no response, no error reaches the MCP caller, and
`list_access_logs` records the action name as though it executed.

Fix: validate handler action names against the protocol's action catalog at parse time in
`EventHandler::parse_event_handlers` (`src/events/handler.rs:1682`), and record execution
failures in the access log.

### 9. Scheduled tasks leak when servers stop via MCP **[fixed — re-verified 26 Sep 2026]**

> Fixed: teardown moved inside `AppState::remove_server`, pinned by `tests/mcp_stop_cleanup_test.rs`. The text below is the original finding.
`src/mcp_stdio/tools.rs:415,718` call `remove_server()` without `cleanup_server_tasks()`,
unlike the TUI paths (`src/cli/rolling_tui.rs:2421,2466`). Orphaned server- and
connection-scoped tasks keep firing every tick, each producing a failed LLM prompt. There is
also no reaper under `--mcp` (`cleanup_old_servers` is only wired into the TUI loop), so
LLM-initiated `CloseServer` leaves entries in `AppState` forever.

### 16. No circuit breaker on the LLM backend **[fixed — re-verified 26 Sep 2026]**

> Fixed: `src/llm/circuit_breaker.rs` fails fast after consecutive transport failures. The text below is the original finding.
`is_available()` exists (`src/llm/ollama_client.rs:1315`) but nothing calls it. With Ollama
down, every request independently waits the full 120s timeout, and with `max_concurrent: 1`
(`src/llm/rate_limiter.rs`) N connections serialize into N×120s.

Two corrections to the version of this item that stood here before. First, those N connections
did **not** queue: `RequestSource::Network` used `try_acquire_owned()` and bailed on contention,
so at the shipped default of `max_concurrent: 1` every request overlapping an in-flight LLM call
was *discarded* — two simultaneous `curl`s were enough, and the flag's own help text promised
"sequential processing". That is fixed: network requests now wait for a permit, bounded by
`--llm-queue-timeout` (default 120s, one backend request timeout) and `--llm-max-queued`
(default 128), and both bounds fail with a typed `RateLimitError` rather than silence.

Second, "on failure most protocols reset to Idle and write nothing" was right in general but
wrong about the two protocols it cited. HTTP always answered (500, now 503 + `Retry-After` when
the error is an overload) and TCP now half-closes the connection so the peer reads EOF instead
of blocking. The pattern survives in 70 of the 79 server `mod.rs` files with a recognisable
LLM-error branch — see the systemic-issues list in CLAUDE.md.

What remains of this item is the circuit breaker proper: nothing calls `is_available()`, so a
backend that is down is rediscovered by every request paying the full timeout.

### 20b. Startup still does not consult the dependency system **[fixed — 26 Sep 2026]**

> Fixed: `dependencies::startup_blocker` gates `start_server_from_action`, `start_server_by_id`,
> `start_client_from_action` and `start_client_by_id`. `353a03fd` had gated only
> `start_server_by_id`, which MCP, the model's `open_server` and `--load` never call. The probe
> is now tri-state (`DependencyStatus::{Available, Missing, Unknown}`): only `Missing` refuses,
> `Unknown` (e.g. no `PATH` to search) is logged and let through, and `is_available` — what the
> TUI list and the model's list read — is "not definitively missing", so an unsure probe hides
> nothing either. `Protocol::startup_dependencies(startup_params)` lets a dependency apply to
> some configurations only: gRPC drops `protoc` for a pre-compiled descriptor set, which it
> decodes without running it. A refusal registers nothing and names the dependency and its
> install hint. `tests/startup_dependency_gate_test.rs`; each branch was verified by removing
> it. The text below is the original finding.

Item 20 is fixed (see the Fixed table): `Protocol::get_dependencies()` now derives from
`metadata().privilege_requirement`, so all 116 protocols report correct data and
`get_excluded_protocols()` is live in the TUI footer and the event handler.

What remains is the *startup* half. Neither `start_server_by_id` nor `start_server_from_action`
calls `is_protocol_available()` before `spawn()`. `server_startup.rs` does gate on
`PrivilegeRequirement::is_met_by()`, so a privilege-derived dependency is in practice enforced
there — but a protocol that *overrides* `get_dependencies()` to add a `SystemLibrary` or
`ToolInPath` has no such gate, and would be excluded from the TUI list while a direct
`start_server` still attempts it and fails with whatever raw error the underlying library
produces. One call in the startup path closes that gap.

Note the two mechanisms differ in force on purpose: `privilege_requirement` refuses startup,
dependencies inform. Do not turn the informational one into a second hard gate without deciding
what happens to a protocol whose dependency probe is merely unsure — `DeviceAccess` derives no
dependency for exactly that reason.

### 23. Architectural ceilings **[static]**

- `AppState` is a single `RwLock` over servers, clients, connections, tasks, LLM config, and
  access logs (`src/state/app_state.rs:261`). No deadlock (no `.await` under the guard), but
  every per-connection stat update from every server serializes through one writer.
- All 27 `mpsc` channels are unbounded; there is no backpressure anywhere. A stalled consumer
  grows memory without bound.
- `state/machine.rs` defines a generic `StateMachine<S>` that nothing instantiates; every
  protocol hand-rolls Idle/Processing/Accumulating, so a fix in one does not propagate.

---


> The MCP `start_server` tool description actively steers callers toward `event_handlers` with
> script handlers over the LLM path. This code is therefore on the hot path, not a corner case.

### 29. `REQUIRE_DOCS_FOR_OPEN_ACTIONS` is dead configuration **[verified]**

`src/events/handler.rs:20` is a hardcoded `const … = false`, so the "model must read the docs
before it may open a server" gate never engages, while `is_server_docs_read()` /
`is_client_docs_read()` state is still tracked to feed it. Either make it a real runtime
setting or remove it and the state it depends on.

---


### 32. Validator accepts a superset of what the prompt advertises **[fixed — re-verified 26 Sep 2026]**

> Fixed: the user-input path narrows to `advertised_user_input_actions` before validating. The text below is the original finding.
Items 4 and the scheduled-task fix closed two cases where the advertised and validated action
lists diverged outright. A milder version remains: several call sites pass the *unfiltered*
list to the validator while the prompt builder applies `filter_actions_by_scripting_mode` to
what it renders, so e.g. `update_script` is accepted with scripting Off. Permissive rather
than broken, but it is the same drift. Clearest at `src/events/handler.rs:611-637` and
`src/llm/action_helper.rs:143-167`.

### 35. The `easy` layer is a parallel subsystem serving one protocol **[verified]**

`src/easy/` contains exactly one protocol (HTTP, 378 LOC) but carries its own trait, registry
(`src/protocol/easy_registry.rs`), startup path (`src/cli/easy_startup.rs`), prompt templates
(`prompts/easy_request/`), and snapshot tests. In `src/llm/action_helper.rs:361-394` it is
checked *before* `try_execute_event_handler` and returns early, so for an easy-managed server
the deterministic script/static path would be bypassed in favour of an LLM call. Not currently
reachable — `easy_startup.rs` accepts no `event_handlers` — but the ordering inverts the
project's stated preference and is a trap if easy servers ever gain handler support.

### 39. `open_server`'s documentation gate makes mocked tests fragile **[fixed — re-verified 26 Sep 2026]**

> Fixed: the documentation gate is behind `REQUIRE_DOCS_FOR_OPEN_ACTIONS`, which is `false`. The text below is the original finding.
`src/events/handler.rs:844` forces a `DocumentationRequired` retry on first use of
`open_server`. Mock configurations that don't answer that retry never start their server, which
is why all 4 `tests/server/dns/test.rs` tests and 7 in `tests/examples/` fail at HEAD while
DoT/DoH/mDNS survive. Either the gate should be off by default (compare
`REQUIRE_DOCS_FOR_OPEN_ACTIONS` at `:20`, which is a hardcoded `false` — see item 29) or the
mock helper should answer it centrally so every protocol's tests don't have to.

### 42. `http3` is the QUIC transport, not HTTP/3 **[fixed — re-verified 26 Sep 2026]**

> Fixed: the server protocol is `quic` (`src/server/quic/`); the real HTTP/3 client keeps `http3`. The text below is the original finding.
Correction to the original item: I wrote that `h3`/`h3-quinn` could be dropped because only the
client uses them. **They cannot.** `http3` is a single feature gate over both halves, and
`src/client/http3/mod.rs:175-176` is built on those crates. There is no `Cargo.toml` dependency
saving here, and anyone attempting the rename for that reason should stop — the dependency
survives it.

The reviewed recommendation is **rename the protocol to `quic`, and do not implement RFC 9114
here**, on these grounds: what runs today is coherent and tested (multiplexed bidirectional QUIC
streams under TLS 1.3 with the model owning every byte), and nothing else in NetGet offers a raw
QUIC stream — converting deletes that and buys a third request/response HTTP server duplicating
HTTP/2's surface. `h3` is also pre-1.0 with a server API that has moved repeatedly. And it would
be a rewrite of `handle_stream_with_actions` plus a new event/action pair, breaking every prompt
written against `http3_stream_opened`/`send_http3_data` — not a patch.

Landed already: `keywords()` leads with `quic`, so a model asking for a QUIC server resolves to
the protocol that is one. **Not landed, needs a decision** — the rename touches `Cargo.toml`,
both registries, `cli/server_startup.rs`, `src/server/mod.rs`, the directory itself and
`tests/server/http3/`, plus a call on whether the real HTTP/3 *client* keeps the `http3` name.
The full table is in `src/server/http3/CLAUDE.md`.

If HTTP/3 is wanted later, add it *beside* `quic`, modelled on `http2/h2_server.rs` — the `h3`
server API mirrors `h2`'s — and reusing `http_common`.

### 47. Several tests pass while the protocol is broken **[verified]**

`tests/server/ntp/test.rs:63-96` catches the rsntp client's failure, prints a note and asserts
nothing — so it passed for the entire life of the origin-timestamp bug, while every real NTP
client rejected the server's replies. `tests/server/dot/e2e_test.rs` has the same shape for
transaction ids (item 40).

This is the same lesson as item 38 stated twice: a mocked test that only checks our own
plumbing cannot substantiate a **Beta** rating, which this project defines as "works with real
clients". Suggested rule: no protocol may be rated Beta without at least one test that fails
when a real off-the-shelf client would reject the output — and that test must assert, not log.

### 48. Library panics reachable from the wire need auditing per dependency **[static]**

The dhcproto `chaddr()` panic was found in the DHCP server and then existed unfixed in the
DHCP client. The general shape — a parsing crate that trusts a length field the wire controls
— will recur. Worth a pass over the other binary-format decoders (`rasn-snmp`, `hickory-proto`,
`kafka-protocol`, `cassandra-protocol`, `bson`, `pgwire`, `opensrv-mysql`) asking specifically
which of their accessors panic on malformed input, since all of them run inside a socket task
where a panic silently kills the server while its status still reads `Running`.

### 50. Two overlapping documentation gates, one of them dead **[fixed — re-verified 26 Sep 2026]**

> Fixed: the retry gate is now behind the same `REQUIRE_DOCS_FOR_OPEN_ACTIONS` flag. The text below is the original finding.
`REQUIRE_DOCS_FOR_OPEN_ACTIONS` (`src/events/handler.rs:20`) is a hardcoded `false` and only
controls whether `open_server`/`open_client` appear in the action list. The gate that actually
forces a `DocumentationRequired` retry is unconditional, at `src/events/handler.rs:807` and
`:1223`. That retry costs a full extra model round-trip on the first `open_server` of every
process, and it gives the model nothing: the handler already fetches the documentation itself
and calls `mark_server_protocols_documented` before returning the error, so it could simply
fall through and start the server.

Gate both behind the existing flag. Note the flag is process-global — `is_server_docs_read()`
returns `!documented_server_protocols.is_empty()` (`src/state/app_state.rs:728`) — so it fires
once per process regardless of which protocol is being started.

### 54. ARP and DataLink still cannot ship on Linux **[verified]**

`748fccca` added `arp` to `dist-darwin` and `icmp` to `dist`, which fixed macOS. But `arp` and
`datalink` remain absent from `dist` itself, so the Linux release binaries still cannot start
them at all — the same "Unknown protocol" dead end, just on a different platform. They need
libpcap at link time, which is the original reason for the exclusion; the options are bundling
it, dynamically loading it, or documenting the gap in the release notes rather than leaving
users to discover it.

### 77. pgwire panics the PostgreSQL connection on a malformed simple query **[verified]**

`pgwire` 0.35's `decode_packet` (`codec.rs:62-83`) bounds the declared message length only
from *above*, then hands `decode_fn` the entire remaining buffer rather than a slice limited
to `msg_len`. `get_cstring` (`codec.rs:26`) scans for a NUL, exits with `i == buf.remaining()`
when there isn't one, and calls `split_to(i + 1)` — which panics.

**Reproduced against a running NetGet PostgreSQL server**, and the repro corrects the
audit's framing in one respect worth keeping straight:

- The audit described it as unauthenticated and reachable with six bytes. Sending
  `51 00 00 00 05 78` on a fresh connection does **nothing** — no panic, no reply.
- It needs the startup handshake first. After a valid startup message, the same six bytes
  panic inside `bytes-1.10.1/src/bytes_mut.rs:396`.

Since NetGet's PostgreSQL server performs no authentication — the model answers everything —
"unauthenticated" is fair *for NetGet*, but the precise repro is handshake-then-six-bytes, and
anyone writing this up upstream needs that distinction.

Severity, measured rather than assumed: the panic kills **that connection's task only**. The
server stayed up and accepted a further connection. So this is not in the class of item 71's
server-killers; it is a malformed message producing a panic instead of a clean protocol error.
Still worth fixing, because a panicking connection is a silent one.

The fix belongs upstream — `pgwire` owns the socket loop, so NetGet cannot bound the frame
without wrapping the stream. Report it there. `opensrv-mysql`'s `params.rs` cluster (five
malformed `COM_STMT_EXECUTE` shapes, including an explicit `panic!("bad column type")` on a
client-chosen byte) and `kafka-protocol`'s unbounded element counts are the same shape and are
documented in the panic audit.

### 78. `tcp_connection_opened` is advertised unconditionally and fires only for `send_first` servers **[verified, fixed: telnet raises it always, tcp/tls document the gate]**

**Resolution.** Both options below were taken, per protocol. `telnet` raises its connect event on
every connection: a telnet server is expected to speak first, the model answers with no actions
when there is nothing to say, and a dashboard-created server answers it with a zero-action static
rule (`EventType::raised_on_every_connection()`, read by `src/tui/modal/form.rs`). `tcp` and `tls`
were converted the same way in `527e07f3` and then narrowed back to `send_first` only, with their
event and parameter descriptions saying that `send_first` is how a server greets. The measurement
decided it: generic TCP is client-speaks-first, so raising the event everywhere cost one model
call per connection, and in the seeded real-model eval llama3.1:8b answered the empty connect
event with an unrequested greeting, taking `tcp` from 15/15 to 10/15. `send_first` means the peer
is owed a greeting: reads are held until the connect event is answered, a silent answer is
`decision=model_silent`, and a failed one closes. **Still gated, unchanged:** `socket_file`, `pty`
and `stdio`.

`src/server/tcp/actions.rs:490` describes the event as *"New TCP connection established (send
initial greeting/banner if needed)"* and ships a `response_example` that sends a `220 Welcome`
banner. `src/server/tcp/mod.rs:125,261-277` raises it only when the server was started with
`startup_params: {"send_first": true}` — the default is `false`.

So a model that reads the event catalogue, sees `tcp_connection_opened`, and configures a
handler for it (LLM, script or static) gets nothing at all: the event never fires, the handler
never runs, and no diagnostic says why. This is the "declared and never emitted" class the root
`CLAUDE.md` records for the USB family, in a `Beta`-adjacent protocol.

Found by making `tests/examples/tcp_examples_test.rs` able to fail — three of its four tests
swallowed every failure mode, so the shipped `response_example` had never actually been
exercised. The tests now pass `send_first` explicitly and assert the wire bytes; the product
side is still open:

* say so in the event description, and in the `send_first` parameter description, so the model
  can tell that one requires the other; or
* raise the event on every connection and let the handler decide whether to write anything,
  which is what its description already promises.

Note this is *not* archived item 13 (`send_first` ignored as a top-level `open_server` field) —
the `startup_params` path does work. It is the documentation and the conditional emission.

### 76. Test suites that assert only at the transport level **[verified]**

`tests/server/{nfs,ipp,vnc,webdav}/test.rs` are declared and running, and assert only that a
connection was accepted — none decodes a protocol payload. That is why NFS's empty action list
and IPP's encoding bug both passed through green. Same shape as the NTP test in item 47 and the
tracker/DHT tests: the suite proves the process started, not that the protocol works.

Worth a rule alongside item 47: a protocol test must assert on decoded protocol output, not on
transport success.

---

### 82. RTP read as "not listening", then its port as leaked, in one registry-audit run **[verified once, not reproduced]**

In `registry-audit` run 36267858809 (26 September 2026, `--all-features`, Ubuntu 22.04),
`tests/protocol_startup_smoke_test.rs` reported `RTP ... LIED` with `PORT LEAK after stop
(127.0.0.1:52926)`. Both halves together say RTP's socket was **not** on its recorded address
while the server read `Running`, and that something else held that address after the stop. The
next run of the same job passed (`LISTENING-udp`), and `--features rtp,tcp` passes locally every
time.

What is known: the smoke test passes an explicit port 0, so the default-port resolver is not
involved; `spawn_with_llm_actions` records the address its own `UdpSocket` returned; the accept
loop only logs a `recv_from` error and continues. The binary's second test, the client
connect-refusal smoke, runs concurrently in the same process and binds ephemeral UDP sockets,
which would explain the address being taken after RTP's socket went away, but not why the socket
went away first. **Do not label this flaky.** The smoke test now prints the last 40 status
messages of any server it calls a liar or finds leaking, so the next occurrence carries RTP's own
account of its socket; read that before theorising further.

## Archive — fixed items and recorded findings

Kept because the reasoning is worth finding again, not because anything is pending here.
Each fixed item has a row in the Fixed table above.

### 79. The orphaned-test gate checked directories, so 30 test functions never compiled **[verified, fixed]**

Archived item 5 fixed 76 orphaned test *directories* and added a CI job to hold the line. The job
compares `ls -d tests/server/*/` against `pub mod` lines, which cannot see a **file** inside a
declared directory, a test tree outside `tests/server`/`tests/client`, or anything under `src/`.
Twenty tracked `.rs` files were unreachable from every cargo target root; ten held tests.

* `tests/server/{proxy,ssh_agent,datalink}/mod.rs` declared only `mod e2e_test;`. `proxy/test.rs`
  alone is 704 lines and 8 tests — the only proxy tests that stand up real HTTP/HTTPS targets and
  route traffic through the proxy, for the protocol family archived as "21 failures → 5".
* `tests/server/bluetooth_ble_{keyboard,mouse}/mod.rs` said *"Tests would go here"* with an
  `e2e_test.rs` beside them.
* `tests/e2e/` and `tests/validators/` were reachable from no root at all.

Eight of the newly-live tests failed on first execution, all in `proxy/test.rs`, which had been
written against an API that does not exist: events `proxy_http_request_received` /
`proxy_https_connect_received` (real: `proxy_http_request` / `proxy_https_connect`) and actions
`proxy_forward_request` / `proxy_block_request` / `proxy_allow_connect` / `proxy_block_connect`
(real: `handle_request_pass` / `handle_request_block` / `handle_request_modify` /
`handle_https_connection_{allow,block}`, with different parameter names). No rule ever matched;
the proxy forwarded anyway, so the assertions would have passed while the LLM path was dead.

Two product defects fell out once the tests could run:

* `apply_request_modifications` (`src/server/proxy/mod.rs`) keyed its header map on the raw field
  name. HTTP field names are case-insensitive (RFC 9110 §5.1) and hyper lowercases them on the
  wire while a model writes `User-Agent`, so `remove_headers` removed nothing and `headers:
  {"Host": …}` would have **appended** a second Host header. `tls_mitm.rs` already lowercased;
  the plain-HTTP path did not.
* `start_test_https_server` wrote `${TMPDIR}/test_https_cert_${PID}.pem` "to avoid conflicts when
  running tests concurrently" — concurrent Rust tests share one process, so both HTTPS tests
  wrote the same paths with different key pairs. Intermittent handshake failures. Now in memory.

Fixed by declaring everything, adding `tests/e2e.rs` as a root, and replacing the
directory-only CI job with `.github/scripts/check-module-reachability.sh`.

### 80. Two clippy::suspicious violations lived where the blocking gate could not see them **[verified, fixed]**

The `lint` job ran `cargo clippy` **without `--all-targets`**, so it linted the lib and exempted
every test file. At `--all-features --all-targets` the same `-D clippy::correctness -D
clippy::suspicious` invocation exits 101 on two:

* `tests/terminal_snapshot/mod.rs` — `clippy::zombie_processes`. Seventeen tests spawned the
  netget binary into a PTY, bound it to `let _child` and returned. `Child::drop` neither kills
  nor waits, so **every run leaked a live `netget` process**, and this project's standing rule is
  that netget processes are never killed — so nothing collected them afterwards either. Fixed
  with an owning `NetGetChild` guard that kills and reaps the pid it spawned.
* `tests/helpers/event_trigger.rs` — `clippy::empty_line_after_doc_comments`.

The blocking gate now runs `--all-targets` with `terminal-snapshot` enabled (verified to catch
both when reverted), and an advisory `clippy-wide` job covers ~95 further features. Blocking
`--all-features` is not achievable on the runner: protoc, libpcap, dbus, libusb, pcsclite.

Note the fmt half of this was a *different* mechanism. `cargo fmt` has no feature flags and does
not evaluate `cfg` — cfg-gated modules **are** visited. All six unformatted files at the time
were among the twenty undeclared ones in item 79, so fixing the declarations closed the fmt gap
by itself; the rustfmt sweep in the reachability script keeps the remaining allowlisted files
honest.

### 81. Mock helpers with an API that lied, a guard that only printed, and tests that could not fail **[verified, fixed]**

Three separate ways the mock harness let a suite assert nothing:

* **`.on_custom(pred)` never called `pred`.** `MockRule::matches` consulted only the serialized
  matcher, and `on_custom` set `match_any = true` there as a placeholder — so every custom rule
  was an `on_any` rule. Seven call sites in the grpc/http2/quic suites wrote
  `|ctx| !ctx.instruction.contains("Event ID:")` believing it filtered; they were saved only by
  being declared last, and one carried the comment *"catch-all for user input, MUST come LAST"*.
  `MockLlmConfig::clone` compounded it by dropping the matcher on the way to the mock server.
  The matcher is now an `Arc`, survives the clone, and is consulted whenever
  `has_custom_predicate` is set. All twelve tests in those three suites still pass.
* **24 test files configured mocks and never called `verify_mocks()`.** The `Drop` backstop
  `eprintln!`ed a warning that at `--test-threads=100` nobody has ever read. It now **panics**
  when the config carries any `expect_calls`/`expect_at_least`/`expect_at_most` and the thread is
  not already panicking (panicking twice would abort and destroy the real message); a config with
  no expectations still only warns. 113 `verify_mocks()` calls were added across 22 files, and
  the guard immediately found a 24th case the sweep missed —
  `tests/client/tcp/e2e_test.rs` verified its server and not its client.
* **`tests/examples/tcp_examples_test.rs` had three tests that could not fail.** Each read arm
  printed `⚠ … may be expected in mock mode` and continued, and one skipped mock verification
  unless data had arrived. They now read the `response_example` **from the registry** rather than
  keeping a copy — the copy had already drifted, missing the `"encoding": "hex"` field the
  protocol gained — and assert the exact wire bytes. That is what surfaced item 78.

### 56. Sixteen protocols never show the model their own actions **[verified]**

`call_llm` builds the model's action list from `event.event_type.actions`
(`src/llm/action_helper.rs:455`) — **not** from `get_sync_actions()`. Only its sibling
`call_llm_with_actions` consults the protocol (`:130`). So a protocol that uses `call_llm` and
never calls `.with_actions(...)` on its `EventType`s offers the model nothing it can act on,
however many actions it declares. Anything protocol-specific the model returns is rejected as
an unknown action, retried twice, and fails.

Measured empirically. An npm server was pointed at a capturing endpoint and sent a real HTTP
request; the tool list in the prompt was exactly:

```
set_memory, append_memory, show_message, append_to_log
```

Zero npm actions, against five declared. The model cannot answer an npm request at all.

Affected — using `call_llm`, no `.with_actions(...)` anywhere, declaring sync actions:
`bluetooth_ble`, `dc` (10 actions), `ipsec`, `isis`, `nntp` (8), `npm` (5), `ollama`,
`openai` (**Beta**), `openvpn`, `rip`, `rss`, `sip` (6), `smb` (10), `stun`, `tftp`,
`wireguard`.

MongoDB had exactly this and was fixed in `b769f29a` — its six actions were all being rejected
as unknown, which is also why its E2E suite was failing silently against a broken protocol.

Two fixes are needed, and the second matters more:
1. Add `.with_actions(...)` to the affected event types.
2. Remove the trap. Two functions that differ only in whether the protocol's own actions reach
   the model is a footgun that has now caught at least 17 protocols. Either have `call_llm`
   consult the protocol too, or make `EventType` require its actions at construction so the
   omission cannot compile.

Reproduce the sweep with:
```bash
for f in src/server/*/actions.rs; do d=$(dirname $f); p=$(basename $d)
  ev=$(grep -c "EventType::new(" $f); wa=$(grep -c "\.with_actions(" $f)
  sy=$(sed -n '/fn get_sync_actions/,/^    }/p' $f | grep -cE "_action\(\)")
  pl=$(grep -rl "call_llm(" $d | wc -l); wi=$(grep -rl "call_llm_with_actions(" $d | wc -l)
  [ "$ev" -gt 0 ] && [ "$wa" -eq 0 ] && [ "$sy" -gt 0 ] && [ "$pl" -gt 0 ] && [ "$wi" -eq 0 ] && echo "$p ($sy invisible)"
done
```

### 1. `StartupParams` panics on malformed input; MCP callers hang forever **[verified]**

`src/protocol/spawn_context.rs:42` and every `get_*` accessor (`:63-311`) call `panic!` on an
undeclared key, a missing required key, or a wrong-typed value. The JSON originates from the
LLM (`open_server`) or an MCP client (`start_server`), so this is remotely triggerable.

Reproduced: an MCP `tools/call` with `startup_params: {"undeclared_xyz": 1}` panics the
per-request task, so **no JSON-RPC response is ever sent** — the caller blocks until its own
timeout. The `ServerInstance` was already registered (`src/cli/server_startup.rs:383`) before
params are built (`:457`), so it is left permanently in `ServerStatus::Starting`.

Fix: convert `StartupParams::new` and all accessors to return `Result`; surface the error
through `start_server_from_action`'s existing `Err` path so status becomes `Error` and MCP
returns a tool error. Validate before `add_server`.

### 2. `send_tcp_data` never decodes hex, contradicting its own documentation **[verified]**

`src/server/tcp/actions.rs:242,276` do `data.as_bytes()`. The field is documented as
"text string or hex-encoded for binary data" at `:355,359`, the docs served to the LLM show
`{"data": "48656c6c6f"}` as a `tcp_data_received` response example, and
`src/server/tcp/CLAUDE.md` states `"48656c6c6f"` sends `"Hello"`.

Reproduced: a static handler returning `data: "48656c6c6f"` put `34 38 36 35 36 63 36 63 36 66`
on the wire — the literal ASCII, not `48 65 6c 6c 6f`. Inbound data *is* hex-encoded when
non-printable (`src/server/tcp/mod.rs:154,301,430,487`), so the round-trip is asymmetric: the
model is shown hex, told to answer in hex, and its hex is sent verbatim. Any binary protocol
built on raw TCP is silently corrupt.

Fix: pick one contract and make code and docs agree. Recommended: an explicit
`encoding: "utf8" | "hex"` field defaulting to `utf8`, since heuristic sniffing cannot
distinguish the string `"48656c6c6f"` from the bytes it encodes. Audit the other protocols
that hex-encode inbound but never decode outbound: `socket_file`, `tls`, `cassandra`,
`http3`, `kafka`, `snmp`, `tor_relay`.

### 3. UTF-8 boundary panics on LLM-controlled strings **[static]**

The pattern `if s.len() > N { &s[..N] }` checks *byte* length and panics when the cut lands
inside a multi-byte character. Occurrences include `src/llm/conversation.rs:604,1213,1220,1361,1409,1419,1446,1504`,
`src/llm/action_helper.rs:153,464`, `src/llm/event_handler_executor.rs:204`,
`src/llm/actions/summary.rs` (9 sites), `src/llm/ollama_client.rs:764,1084`,
`src/mcp_stdio/tools.rs:783`, `src/cli/rolling_tui.rs:814`.

These run on the action-summary/logging path for essentially every LLM response, and the
strings are model output and event descriptions — any emoji, curly quote, or non-English text
near the offset crashes the handling task. `action_helper.rs:153` uses a 27-byte window.

Fix: one shared `truncate_chars(s, n)` helper using `char_indices()`, applied everywhere.

### 4. Feedback loop cannot succeed **[static]**

`src/llm/action_helper.rs:684-701` builds a prompt telling the model which actions are
available, then `:752` defines `let feedback_actions: Vec<ActionDefinition> = Vec::new();`
and passes that empty vector to both `with_native_tools` (`:761`) and
`generate_with_tools_and_retry` (`:781`). `valid_action_names` is derived from it
(`src/llm/conversation.rs:504-511`), so every action the model returns is rejected as unknown,
retried twice, then `bail!`s. The whole `feedback_instructions` feature can only no-op or fail.

Fix: pass the same action list used to build the prompt.

---


### 5. 76 test directories are never compiled **[verified]**

`tests/server.rs` / `tests/client.rs` only compile modules declared in the respective
`mod.rs`. Directories present on disk but undeclared are silently skipped — no error.

Measured: **15 of 116** server dirs orphaned (`arp bitcoin igmp nfc openid sip svn tls
usb_fido2 usb_keyboard usb_mouse usb_msc usb_serial usb_smartcard whois`) and **61 of 83**
client dirs. These are real, feature-gated suites, not stubs.

Fix: add the missing `pub mod` lines (31 client dirs are ready as-is; 30 need a `mod.rs`
first), then add a CI check that the two sets match.

### 6. No CI runs tests **[verified]**

`.github/workflows/release.yml` is the only workflow; it triggers on `v*` tags and manual
dispatch and runs `cargo build` for the `dist*` sets. `cargo test` appears nowhere. The
1,038-test suite is developer-run only, with no PR gate and no lint job.

Fix: a PR workflow running `cargo clippy` plus a representative feature subset
(`tcp,http,dns,udp,redis`) with `--test-threads=100`, and the orphan check from item 5.

### 8. Raw-socket protocols report `Running` when capture fails **[static]**

`arp`, `datalink`, `icmp`, `isis` start their capture loop in a fire-and-forget
`spawn_blocking`; a failure to open the pcap/raw handle never propagates, so the server shows
`Running` while doing nothing. Same class of problem as an accept-loop panic, which also
leaves status at `Running` with no supervision or restart.

Fix: have `spawn()` await a readiness signal before returning `Ok`, and set
`ServerStatus::Error` when the capture handle fails.

### 10. Client lifecycle is unfinished **[static]**

`ClientInstance.handle` (`src/state/client.rs:120`) is never populated — no
`register_client_task()` exists, and every client protocol discards its read-loop
`JoinHandle`. `remove_client()` therefore cannot stop a client's network activity. Per-connection
server tasks are likewise untracked, so `stop_server` does not cancel in-flight connections
(the listening socket *is* released correctly via `register_server_task`).

---


### 11. `get_protocol_docs` documents the wrong API to MCP callers **[verified]**

The MCP tool reuses the TUI LLM's `read_documentation` output
(`src/llm/actions/tools.rs:2260-2272`), which opens with guidance on choosing between
`open_server` and `open_client` and describes `base_stack` — none of which an MCP caller can
use. It explicitly recommends `open_client`, for which no MCP tool exists.

Fix: render MCP-shaped docs — `start_server` arguments, the protocol's event ids with field
names, its action names with parameter schemas, its startup parameters, and its privilege
requirement. This is the single highest-leverage change for making the MCP surface usable by
a calling model without trial and error.

### 12. No client control surface over MCP **[verified]**

`list_protocols` advertises ~75 client protocols and the docs tell the caller to use them,
but no MCP tool starts, lists, queries, or stops a client. The client list also carries no
maturity or description, unlike the server list.

### 13. `send_first` is silently ignored everywhere **[verified]**

`start_server_from_action` takes it as `_send_first` (`src/cli/server_startup.rs:217`) and
never uses it. TCP's banner feature is unreachable through the action API, and MCP hardcodes
`false` anyway (`src/mcp_stdio/tools.rs:368`). Either wire it through to
`ProtocolConnectionInfo`/spawn or delete the parameter and the documentation for it.

### 14. Prompt tells the model something false about re-invocation **[static]**

`ActionDefinition::is_tool()` (`src/llm/actions/mod.rs:252-262`) omits `read_documentation`,
`list_tasks`, `execute_sql`, `list_databases`. `build_actions_section_public`
(`src/llm/prompt.rs:139`) partitions on it, so `read_documentation` — the primary discovery
tool — is rendered under a heading stating "you will not be invoked again", while
`ToolAction::is_tool_action()` (`src/llm/actions/tools.rs:184-204`) does re-invoke it.

Fix: single source of truth for tool classification.

### 15. Unbounded prompt growth **[static]**

`ConversationHandler.messages` (`src/llm/conversation.rs:53`) is never trimmed across up to
5 tool iterations × 5 retries, and failed attempts plus their correction messages persist for
the rest of the conversation. `ConversationState`'s 8000-char window is a separate structure
applied only to cross-call history, never to what is actually sent. Server `memory` is an
unbounded `String` injected into every prompt (`src/llm/actions/executor.rs:174-194`). The
full base-stack catalog is re-sent on every call once any server is running
(`src/llm/prompt.rs:706-712`).

### 17. `git` and `mercurial` bypass the LLM infrastructure **[static]**

Both call `llm_client.generate_with_retry` directly (`src/server/git/mod.rs:335-362`) instead
of `call_llm`. They therefore skip the rate limiter, the unknown/malformed-action repair
loops, native tool schemas, and `try_execute_event_handler` — meaning script and static
handlers are silently ignored for these two protocols and every request hits the LLM.

---


### 18. Privilege gate ANDs in the wrong capability **[verified]**

`src/cli/server_startup.rs:348` gates on `!system_caps.can_bind_privileged_ports` even when
the requirement is `RawSockets` or `Root`. A process with `CAP_NET_BIND_SERVICE` but not
`CAP_NET_RAW` skips the check and fails later with an opaque `EPERM`. Use
`PrivilegeRequirement::is_met_by()` alone — it already handles each variant.

Also: only ~23 of 116 protocols declare a requirement. `smtp`, `ldap`, `imap`, `pop3`, `ipp`,
`syslog` (privileged default ports) and `igmp` declare none. And the actionable remediation
text ("run as root", "use a port ≥1024") lives only in `start_server_by_id:82-100`, which MCP
never calls — the MCP path returns the bare description (`:348-355`).

### 19. ARP and ICMP are absent from every shipped binary **[verified]**

`dist` excludes `datalink`, `arp`, `isis` (libpcap) and `icmp`. `dist-darwin` adds back
`datalink` and `isis` — because macOS ships libpcap — but **not `arp`**, which needs the same
library, nor `icmp`, which needs no system library at all (`pnet` + `socket2` only). Both
look like oversights. Users of the released binary get `Unknown protocol: arp`, with no
indication the protocol exists but was compiled out.

Fix: add `arp` to `dist-darwin` and `icmp` to `dist`; make the registry distinguish "no such
protocol" from "compiled out of this build" in its error.

### 21. Five protocols expose zero actions — and the grep that found them was misleading **[verified]**

Corrected: an earlier version of this item listed nine, including `doh` and `dot`. Those two
are fine. They **delegate** — `get_sync_actions()` forwards `DnsProtocol`'s set verbatim, so
the model sees the full DNS vocabulary on every query. A grep for `vec![]` cannot tell
delegation from hollowness; measure both:

```
grep -A3 "fn get_sync_actions" src/server/<p>/actions.rs | grep -c 'vec!\[\]'   # hollow
grep -c "DnsProtocol\|BluetoothBle::" src/server/<p>/actions.rs                  # delegating
```

The genuinely hollow ones are `bluetooth_ble_proximity`, `_presenter`, `_gamepad`,
`_environmental` and `_file_transfer`: literally `vec![]` for both actions and events, zero
delegation, so the LLM gets nothing it can act on — while they are registered `Experimental`
and therefore offered. `bluetooth_ble_proximity` compounds it by shipping
`get_startup_examples()` referencing an event (`ble_proximity_detected`) and an action
(`wait_for_more`) it does not define, so the example is unusable copy-paste.

`amqp` and `mqtt` were the same shape (`// Placeholder` in source) and are being addressed
separately.

The rule worth keeping: a protocol the model can select but cannot control is worse than one
that is not offered — it will be chosen, accept connections, and never respond. Either
delegate like `doh`/`dot`, implement, or mark `Incomplete` so `is_available_to_llm()` hides it.


### 22. Documentation drift **[verified]**

- **Correction to an earlier claim in this file**: it previously said 27 server protocols had
  no E2E test. That was wrong — it counted only files named `e2e_test.rs`. Every directory
  under `tests/server/` has at least one test file; 25 protocols simply name theirs `test.rs`,
  including `tcp`, `http`, `dns`, `ssh`, `snmp`, `ntp`, `dhcp`, `udp`, `mysql`, `postgresql`,
  `smtp`, `imap` and `nfs`, and those are correctly declared in both their own `mod.rs` and
  `tests/server/mod.rs`. The coverage problem is not absence of tests; it is item 5 (15 server
  and 61 client directories orphaned from the parent `mod.rs`) plus tests that are wired and
  failing — all 4 of `tests/server/dns/test.rs` fail at HEAD, independent of any change made
  in this pass. Verify with `ls tests/server/*/` rather than grepping for `e2e_test.rs`.
- `openvpn` declares `DevelopmentState::Stable` and describes itself as "production-ready",
  but its key material is HKDF-derived from hardcoded constants
  (`src/server/openvpn/mod.rs:441-461`) — every peer gets identical keys — and its control
  channel handlers are no-op stubs. Data-plane encryption is real; the handshake is not.
  It should not be `Stable`.
- `ipsec` documents LLM-driven accept/reject decisions but never calls `call_llm`.
- `isis` fabricates a MAC on non-Linux (`src/server/isis/mod.rs:638-663`); the OSPF and IGMP
  E2E tests run over plain UDP and never exercise the raw-socket path they claim to test.
- 8 files in `src/` contain ~23 unit tests, violating the project's own "no tests in `src/`"
  policy.
- ~50 of 63 root markdown files are one-off session reports last touched in 2025; two files
  the old CLAUDE.md referenced (`TEST_INFRASTRUCTURE_FIXES.md`, `TEST_STATUS_REPORT.md`)
  do not exist.

### 24. Script execution parks a tokio worker thread for up to 30s **[verified]**

`src/scripting/executor.rs::execute_script` is synchronous and is called directly from
`async fn execute_script_handler` (`src/llm/event_handler_executor.rs:194`) with no
`spawn_blocking`. `wait_with_timeout` (`:310-341`) polls with
`std::thread::sleep(100ms)` until the child exits or 30s elapses.

`src/bin/netget.rs` uses bare `#[tokio::main]`, so worker_threads equals the CPU count. Each
in-flight script parks one worker for its full duration; on an 8-core machine, 8 concurrent
script-handled requests stall every protocol server, the TUI, and the MCP stdio loop.

Fix: async execution via `tokio::process::Command` + `tokio::time::timeout`.

### 25. Unbounded blocking write to child stdin has no timeout **[static]**

`execute_with_command` (`src/scripting/executor.rs:271-276`) does `write_all` of the entire
event JSON to the child's stdin *before* reading stdout and *before* entering the timeout
loop. If the payload exceeds the pipe buffer (~64KB) while the child is blocked writing
stdout, both deadlock — and since the timeout only starts afterwards, that hang is unbounded.
Event payloads can be large (HTTP bodies, accumulated TCP buffers). Also, `child.kill()` at
`:332` is never awaited, so timed-out scripts can linger as zombies.

### 26. Script execution is unsandboxed and undocumented **[verified]**

`python3 -c <code>`, `node -e <code>`, and `go run` are spawned with the code passed straight
through (`src/scripting/executor.rs:108-135,205`). There is no sandbox, no allowlist, and no
privilege reduction — scripts run with the full privileges of the netget process.

That may be the right choice for a local tool, but it is currently undocumented, and it means
**the MCP `start_server` tool is an arbitrary-code-execution surface**: any MCP client, or any
model driving one, can execute arbitrary code as the user via a script handler. Document the
trust boundary explicitly; decide separately whether a sandbox is wanted.

---


### 27. A client can only be started by an LLM call **[verified]**

There is no MCP tool for clients, no CLI flag, and no deterministic entry point —
`open_client` exists solely as an LLM action (`src/events/handler.rs`,
`src/cli/non_interactive.rs:380`). Starting a client always costs a model round-trip and
cannot be scripted or tested deterministically.

Combined with items 10 (no `JoinHandle`, so clients cannot be stopped) and 5 (61 of 83 client
test directories never compiled), the client half needs a deliberate completion pass: an MCP
`start_client`/`stop_client`/`list_clients` surface, task-handle tracking, and its test suite
turned on.

### 28. `--api-key` on the command line is world-readable **[static]**

`src/cli/args.rs` accepts `--api-key <KEY>`, which places the secret in the process table for
every local user to read via `ps`. The env-var path (`NETGET_API_KEY` / `OPENAI_API_KEY`) is
already supported and should be the documented default; consider warning when the flag form
is used.

### 30. `register_server_task()` stores only one handle per server **[static]**

`src/state/app_state.rs:487-493` overwrites any previously registered `JoinHandle`, so a
protocol with two long-lived loops (OpenVPN's UDP listener plus its TUN reader) silently leaks
the first — and `stop_server` then only aborts the second. OpenVPN worked around it by joining
both loops under one task with `select!`. Either document the single-handle contract at the
call site or change the field to a `Vec<JoinHandle<()>>`.

### 31. Protocol async actions are structurally unreachable **[static]**

`src/llm/actions/executor.rs:100` dispatches async actions through `Server::execute_action()`,
which is invoked on a *stateless* protocol struct with no handle to the running server
instance. Any async action needing live state (`list_peers`, `get_server_info`, …) can only
return `NoAction`. Several protocols advertised such actions to the model; the VPN family's
dead advertisements were removed, but the general fix needs a server-instance registry reachable
from `src/llm/actions/protocol_trait.rs`.

### 33. Development builds default to TRACE, which writes full payloads to disk **[verified]**

`src/cli/args.rs` defaults dev builds to `trace`; per CLAUDE.md, TRACE logs full payloads.
That is what produced a 481 MB `netget.log` in a day. Rotation now bounds total size
(`e3617126`), but `debug` would be a better default, with `--log-level trace` still available
when payload-level detail is genuinely wanted.

### 34. `src/server/vpn_util/` is dead code **[static]**

`TunManager` is declared at `src/server/mod.rs:511` and used by nothing — WireGuard uses
defguard, OpenVPN uses the `tun` crate directly. It keeps a `tokio_tun` dependency alive for
no consumer.

### 36. Registry `resolve()` needs adopting in the startup path **[static]**

`d58854ca` added `ServerRegistry::resolve()` / `ClientRegistry::resolve()`, which distinguish
"not compiled into this build" from "no such protocol" and offer a did-you-mean suggestion.
`src/cli/server_startup.rs` still uses the older `parse_from_str` + `get` pair at roughly
`:52` and `:227`, so callers keep getting the bare `Unknown protocol: arp`. Two-line adoption,
described in that commit.

### 37. Static handlers cannot interpolate event data **[verified]**

`execute_static_handler` (`src/llm/event_handler_executor.rs:243`) emits its configured actions
verbatim, with no substitution from the triggering event. That makes static mode unusable for
every request/response protocol needing a correlation id — DNS `query_id`, DHCP/BOOTP `xid`,
SNMP `request-id`, STUN/NTP transaction fields — because the reply cannot echo the client's
random value. The DNS family's own `StartupExamples` taught `"query_id": 0`, i.e. actively
documented a broken configuration, until `6a384617` replaced them.

Script handlers do not have this problem (they receive the event on stdin), so the workaround
is "use a script", but that means spawning an interpreter to copy one field. A small
templating substitution (e.g. `{{event.query_id}}`) in static actions would make the cheapest
deterministic path viable for the whole UDP family. Until then, say so plainly in the static
handler's documentation.

### 38. DNS responses omitted the question section **[fixed — `6a384617`, recorded as a lesson]**

RFC 1035 §4.1.2 requires a response to repeat the question, and glibc, systemd-resolved and
`dig` all discard responses whose question doesn't match. A protocol rated **Beta** — defined
in CLAUDE.md as "human reviewed, works with real clients" — therefore did not work with real
clients, and its tests passed because they used a lenient client. Worth treating as the
canonical argument for validating Beta claims against a real off-the-shelf client rather than
against our own test harness.

### 40. Smaller protocol-level defects found in review **[static]**

- `src/server/svn/actions.rs:56` declares `PrivilegedPort(3690)`; 3690 > 1024, so the check can
  never fire. Any `PrivilegedPort` above 1023 is dead by construction — worth a debug assertion.
- `tests/server/dot/e2e_test.rs:132,155,172` hardcode `"query_id": 1` instead of using
  `respond_with_actions_from_event`, violating CLAUDE.md's dynamic-mock rule. They pass only
  because the raw TLS client never checks the id, so they prove nothing about correlation.
- No `ProtocolConnectionInfo` data is recorded for DNS, and DoT/DoH register no connections at
  all, so they are invisible to the connection list and to connection-scoped scheduled tasks.
- `'secure dns'` is claimed as a keyword by both DoT and DoH; the collision is warned about at
  startup and never resolved.

### 41. Action execution failures are swallowed **[verified]**

`src/llm/actions/executor.rs:114` drops a protocol action whose executor returns an error with
only a `warn!`. The peer then receives the protocol's default — an empty 200 for HTTP, nothing
at all for TCP — and neither the MCP caller nor the access log learns the action failed; the
log records it as though it ran. This is why the HTTP executor was deliberately made lenient
rather than strict, and it is the same root cause as item 7. Fixing it properly means
propagating action errors into the access log and the tool result.

### 45. The mock harness misroutes the pre-`open_server` documentation step **[verified]**

Reproduced at session-start commit `ea950dca` in a clean worktree, so this predates all of
today's work. The documentation step forced before `open_server` produces a prompt whose text
makes `tests/helpers/mock_ollama.rs` context extraction report `event_type: Some("http_request")`.
An `instruction contains` rule therefore misses, an `on_event` rule matches instead, and
`send_http_response` is returned to the *startup* call, which rejects it as an unknown action —
so no server ever starts. This breaks all 10 `tests/server/http/*` tests, all 4 DNS tests, and
7 in `tests/examples/`. It is the single highest-value test fix available: one change in the
mock helper or the docs-gate flow turns several protocol suites green at once. Closely related
to item 39.

### 46. Feature declarations are incomplete, and `--all-features` hides it **[verified — 2 found, both fixed]**

Two protocols did not build with the single-protocol command CLAUDE.md mandates
(`--no-default-features --features <protocol>`), while building fine under `--all-features`
because another enabled feature happened to supply what they needed through Cargo feature
unification:

- `openid = []` declared no dependencies although `src/server/openid/mod.rs` uses `urlencoding`
  at 8 sites — `E0433`, fixed in `e6353886`. Every other feature using that crate declares it.
- `usb-fido2` did not enable `ring/std`, without which `ring` does not implement
  `std::error::Error` for `Unspecified`/`KeyRejected`, so `?` into `anyhow` failed at 8 sites
  in `ctap2.rs`/`u2f.rs` — `E0277`, fixed in `b7b1d5ae`.

The class matters more than the two instances: `--all-features` is structurally incapable of
catching an under-declared feature, and it is the only build CI runs. A sweep of 30 other
protocol features found no further cases, so this is not endemic — but nothing prevents the
next one. Add a CI job that builds a rotating sample of individual protocol features, or all of
them on a schedule; it is the only thing that can catch this.

**The same blind spot applies to test targets, and there it is worse.** `--features telnet`
alone failed to *compile* two test targets (`57a4c42f`) — and a test target that does not
compile does not report failures, it simply contributes nothing, exactly like the orphaned
directories in item 5. So the sweep should be `cargo check --tests`, not `cargo check`, or the
next silent gap will be a whole target rather than a directory.

### 49. The DNS client loops until the process overflows its stack **[verified]**

`tests/client/dns/e2e_test.rs::test_dns_client_multiple_queries` drives the DNS **client**
into an unbounded loop: it issued **211 LLM calls** and then netget died with a stack
overflow. This is a client-side runaway, not a mock artifact — it surfaced only once the
mock stopped failing every test before it got that far.

Two things are wrong and both deserve fixing: whatever makes the client re-issue instead of
terminating, and the absence of any ceiling on LLM calls per client session. Servers have the
per-connection Idle/Processing/Accumulating machine to prevent re-entrancy; clients hand-roll
their own (item 7 in spirit), and evidently one of them does not converge. A hard cap with a
clear error beats an unbounded loop regardless of the root cause.

### 51. Remaining test failures after the mock fix **[verified]**

All test-side, none in `src/`:
- `server::http::test::{test_http_routing, test_http_error_responses}` key their mocks on
  `event_data["uri"]`, but the HTTP event emits `path`.
- `server::http::test::test_http_simple_get_with_logging` answers a network event with
  `write_file`, which is not in HTTP's sync action set.
- 3 × `server::http::e2e_scheduled_tasks_test` wait for the log line
  `[TASK] Created one-shot task` while NetGet emits `[TASK] Scheduled one-shot task`
  (`src/events/handler.rs:1237,1242`).

### 52. `scheduled_tasks` on `open_server` never reports task creation **[verified]**

`start_server_from_action` (`src/cli/server_startup.rs`, roughly `:480-520`) handles the
`scheduled_tasks` array by calling `state.add_task(task).await` with **no `status_tx.send(...)`
at all** — so creating a task this way is completely silent, in the TUI and over MCP alike.
The standalone `schedule_task` action does log (`src/events/handler.rs:1237,1242`), so the two
paths disagree.

Found while fixing item 51, where I had misdiagnosed three failing tests as a log-string
mismatch. The agent applied the exact string fix I specified, watched the tests still fail,
and traced it to this gap rather than accepting the premise — the right call. The tests now
assert on task *execution*, which does fire reliably, and the missing status line is left for
whoever owns `server_startup.rs`.

### 53. Test-suite state at HEAD **[verified]**

Measured in a clean worktree with `--features tcp,http,dns,udp,redis,mcp-stdio --no-fail-fast`,
so this is the committed tree, not the working tree.

`tests/server.rs` is **31 passed, 0 failed** — the protocol E2E suite is green for that feature
set, against 5/24 at session start. `--lib` 23/23, `examples` 34/34, `mcp_stdio` 9/9,
`static_handler_interpolation` 30/30, `truncate` 13/13, `prompt` and `prompt_snapshots` green.

Remaining failures, all attributed:

- **`ollama_model_test`: 20 of 25 fail.** This is a *model-evaluation* framework — it drives a
  real Ollama at `OLLAMA_BASE_URL` with `qwen2.5-coder:7b` and grades the model's answers. It
  is neither `#[ignore]`d nor feature-gated, so it fails for anyone without that exact setup,
  and would fail in CI. It should be `#[ignore]`d or moved behind the project's existing
  `--use-ollama` opt-in.
- **`logging_unit_test::test_append_to_log_action_definition`.** Asserts the action description
  contains the literal `"log file"`; the description was reworded to "append logs to a file" in
  `e75043df` (2025-12-29). Confirmed pre-existing — `e75043df` is an ancestor of this session's
  starting commit. Either assert on behavior or fix the string.
- **`scripting_executor_test`: 2 Perl cases.** This machine's Homebrew Perl lacks the `JSON`
  CPAN module (`perl -e 'use JSON'` fails standalone). Environmental, not a code defect, but the
  test should detect and skip rather than fail.
- **`client`: 5 of 21.** Includes the DNS client runaway (item 49), being fixed separately.

### 55. `SystemCapabilities` conflates two capabilities **[static]**

One `has_raw_socket_access` flag covers both raw IP sockets (ICMP, IGMP, OSPF) and L2 capture
via BPF/AF_PACKET (ARP, DataLink, IS-IS). These genuinely differ — a macOS user in the ChmodBPF
group has `/dev/bpf*` without being root. `c9a65c80` probes both and grants the flag if either
succeeds, which is permissive in the right direction but still cannot refuse an ICMP server for
a capture-only user. Splitting the flag would let each protocol declare what it actually needs.

### 57. Proxy TLS interception: what it actually does with keys **[verified]**

Recorded because "MITM proxy" invites the question and the answer was not written down
anywhere. **No private key is written to disk, and there is no fixed or hardcoded key.** The CA
key pair is generated in memory at server start (`rcgen::KeyPair::generate`) and dropped when
the server stops; per-domain leaf keys are memory-only too. Intercepted plaintext reaches
`netget.log` only at TRACE, like every other protocol.

The one disk write is the new `ca_export_path` startup parameter, and it writes the CA
**certificate** — the public half — at `0666 & ~umask`, normally `0644`, which is right for
something meant to be distributed. The private half is not written by any code path and is not
reachable from any action. So interception cannot happen silently: without an explicit trust
grant the client aborts with unknown-issuer.

Worth revisiting only if CA persistence is ever added — at that point the key file's mode and
location become a real decision rather than a non-issue.

### 58. The base BLE server ignored every profile's protocol object **[verified]**

Corrected again, and this supersedes both earlier versions of item 21. The count was never
five, or twelve — it was **all sixteen**, and the reason is structural rather than per-profile:
`BluetoothBle::spawn_with_llm_actions` hardcodes `BluetoothBleProtocol` when it calls `call_llm`
(`src/server/bluetooth_ble/mod.rs:124,142,773`). So the base's events were the only ones
emitted, the base's `.with_actions(...)` lists the only vocabulary offered, and
`BluetoothBle::execute_action` the only executor. Every profile-specific action and event in
the family was unreachable no matter what it declared.

Fixed in `3a7bbb5a`, `691de8d8`, `f17e3f1c`: fifteen profiles now delegate explicitly the way
`doh`/`dot` do. `bluetooth_ble_beacon` was left `Incomplete` at the time — `ble-peripheral-rust`
0.2 exposes no advertising-payload API, and a beacon is nothing but its advertising payload, so
delegating would have handed it a working GATT vocabulary that is precisely not a beacon. It has
since taken the third exit: it stopped using the base stack altogether, talks to BlueZ directly
through `bluer`, and calls `call_llm` with its own protocol — so a profile has exactly two
honest options, delegate the base's vocabulary or stop going through the base.

Along the way: two profiles discarded the user's instruction entirely, one had actions declared
but absent from its own match arm, several advertised a connection table that cannot be
constructed, and `execute_action` waved unknown actions through as `Custom` rather than
rejecting them.

**Lesson worth keeping:** three different shapes of "the model cannot act on this" have now
been found — hollow (`vec![]`, no delegation), declared-but-unadvertised (no `.with_actions()`),
and structurally overridden (a shared spawn hardcoding the base protocol). A single grep
detects none of them reliably. The check in CLAUDE.md now covers all three.

### 59. The BLE base teaches a UUID form that cannot parse **[verified]**

`Uuid::parse_str("180D")` fails and no 16-bit expansion helper exists in the tree, yet
`src/server/bluetooth_ble/CLAUDE.md:285` claims the shorthand is "expanded to" the 128-bit
form, and the base's own `BLUETOOTH_BLE_STARTED_EVENT` and `add_service` examples
(`src/server/bluetooth_ble/actions.rs:24,27,449`) both use it. A model copying the protocol's
own documented example gets "Invalid service UUID". Either add the expansion (`0000XXXX-0000-1000-8000-00805F9B34FB`)
or correct the examples — the same documented-but-unimplemented class as items 2 and 38.

### 60. `PrivilegeRequirement` cannot express device access **[static]**

`src/protocol/metadata.rs:7-16` offers `None`, `PrivilegedPort`, `RawSockets`, `Root`. BLE needs
Bluetooth adapter access (D-Bus/BlueZ on Linux, CoreBluetooth TCC on macOS); USB and NFC need
their own device permissions. None of these is a port or a raw socket, and claiming `Root` would
be false *and* would block users who genuinely have adapter access. All seventeen BLE protocols
are therefore left at `None`, which is also wrong. Needs an `AdapterAccess`/`DeviceAccess`
variant — related to item 55, which wants `has_raw_socket_access` split as well.

Compounding it: `src/server/bluetooth_ble/mod.rs:108` reports "Bluetooth adapter failed to power
on after 10 seconds" for all three of adapter-off, no-adapter, and permission-denied, so a user
cannot tell which.

### 61. The auth family claimed cryptography it never performed **[verified]**

None of `oauth2`, `openid`, `saml_idp`, `saml_sp` holds a signing key, and none ever did. That
is defensible for LLM-driven test servers — but three of them said otherwise in the text the
model and the user read:

- `saml_idp`'s `description()` said it "generates signed SAML assertions". A `<ds:Signature>`
  appears only if the model invents one, and it will not verify.
- `saml_sp`'s said it "validates SAML assertions", and `llm_control` listed "assertion
  validation". There is no signature, issuer, audience, expiry or replay check.
- `openid` advertised "LLM-generated JWT tokens". Nothing signs and nothing verifies; the JWKS
  is whatever keys the model invented, unrelated to any signature.

All corrected to state plainly that NetGet performs no cryptography here. Nothing is written to
disk in any of the five. Fixed across six commits.

### 62. OAuth2 turned a denial into an approval, and failed open **[verified]**

The most serious defect found this session. `/authorize` decided by scanning the model's JSON
for a `code` field. `oauth2_error_response` — the model's *only* way to refuse — has no such
field, so **a denial was indistinguishable from silence** and fell through to a hardcoded
`AUTH_CODE_123`. A client received a working authorization code for a request the model had
explicitly rejected. `/token` had the mirror defect, returning the error body with `200 OK`.

All three endpoints also failed open on no-answer: `AUTH_CODE_123`, `ACCESS_TOKEN_123`, and
introspection returning `{"active": true}` for **every** bearer token. So an LLM outage silently
issued credentials and validated anything presented to it. `src/server/oauth2/CLAUDE.md`
documented this as a feature — "ensures the server always responds correctly".

Fixed with a result envelope and fail-closed defaults; verified with `curl` that a denial now
yields `302 …?error=unauthorized_client` and `401 {"error":"invalid_client"}`. The general rule
is now in CLAUDE.md's systemic-issues list.

Note what this did to the tests: `tests/server/oauth2/e2e_test.rs:227` mocks `send_token_response`,
which is *openid*'s action name, so the action was always rejected as unknown — and the test
**passed at HEAD only because the fail-open default masked it**. It now correctly fails. A test
can be green *because* of the bug it should be catching.

### 63. Two credential-minting protocols have no tests at all **[verified]**

`saml_idp` and `saml_sp` have no `tests/` directory — no `e2e_test.rs`, no `CLAUDE.md`, no
`pub mod` line. Zero coverage for the two protocols in the repo that mint and consume
authentication assertions. Also: `tests/server/openid/e2e_test.rs:67,343` starts
`"base_stack": "http"` and mocks `http_request_received`, so it does not exercise `openid` at
all.

### 64. Injection surfaces in `saml_sp` and `oauth2` **[verified]**

`saml_sp` took `user_id` from an attacker-supplied assertion and wrote it unescaped into HTML
*and* raw into `Set-Cookie`. `oauth2`'s `parse_query_params` percent-decodes, so
`?redirect_uri=http://x/cb%0D%0A` put CRLF into the `Location` header and killed the connection
task — remotely reachable and unauthenticated. Both fixed and byte-verified with `od -c`.

### 65. `{"type": "placeholder"}` response examples remain in 54 files **[verified]**

Rendered verbatim into prompts (`src/llm/actions/tools.rs`) and MCP docs
(`src/mcp_stdio/docs.rs:399`), teaching the model an action type that does not exist. Fixed
piecemeal by protocol reviews; 54 `src/server/` files still carry one. Worth a sweep, or a
render-time suppression so a placeholder is omitted rather than shown.

### 66. `http_common` is gated too narrowly **[static]**

`src/server/mod.rs:23` gates it on `feature = "http"` or `"http2"`, so `oauth2`, `openid`,
`saml-idp` and `saml-sp` — all HTTP servers — cannot reach `build_safe_response`
(`src/server/http_common/handler.rs:135`) and have four local copies of it. Widening the gate
would collapse them.

### 67. Every protocol rated `Stable` failed inspection **[verified]**

There were exactly three. All three were checked this session, and none survived as rated:

- **OpenVPN** → `Incomplete`. Its `rustls::ServerConfig` is built, stored and never used; every
  peer derives an identical AEAD key by HKDF over three string literals in public git history.
- **WireGuard** → kept `Stable` (the tunnel is genuinely real) but its advertised LLM control
  did not exist: the events it declared were never emitted and its authorization action's
  result was consumed by nothing.
- **Tor relay** → `Experimental`. Verified against a real `tor` binary: the first thing a client
  sends after the TLS handshake is an **11-byte VERSIONS cell**, and the session loop
  `read_exact`s into a **514-byte** buffer, so it blocks forever and Tor logs
  `died in state handshaking`. It never reaches CREATE2, so the ntor handshake, circuits and
  streams — everything the rating rested on — are unreachable. Its `e2e_testing` field claimed
  "Official Tor client (tor binary)"; no Tor client appears anywhere in the repo, and the single
  E2E test is `#[ignore]`d and prints `✓` for every outcome including timeout.

The common cause is not carelessness about code — all three are substantial implementations.
It is that **no rating was ever checked against a real client**, and the mocked suite cannot
check it. `Stable` and `Beta` both assert real-client behavior, so both need a test that fails
when a real client would reject the output. That is now the rule in item 47; this is the
evidence for it.

### 68. Protocols that could never have worked with a real client **[verified]**

Beyond the ratings, several protocols had a defect that made their core function impossible,
each found only by pointing a real client at them:

- **Git** — `git_send_pack` asked the *model* for base64 packfile bytes, and `git_advertise_refs`
  had it invent SHAs unrelated to that pack. The two halves of a clone could never agree, so
  `git clone` could not succeed. Replaced with a declarative `git_repository` action; the server
  now builds a real v2 pack and computes every object ID (`src/server/git/pack.rs`). Verified
  with `git clone` + `git fsck`.
- **OSPF** — the packet checksum used Fletcher (RFC 2328 D.4, which is for LSA headers) instead
  of the one's-complement IP checksum (A.3.1). A receiver's self-check yields `0x906c` instead
  of `0`, so **FRR and BIRD dropped every packet NetGet ever sent**. The claimed "integration
  with real OSPF routers" had never happened.
- **Maven** — `send_maven_artifact` documented base64 for binaries, and the executor sent
  `body.as_bytes()`; the `body_base64` branch required a shape the executor never produced, so
  it was unreachable. A handler following the docs served base64 *text* as the JAR. Now verified
  with real `mvn`: the served JAR is a valid ZIP whose SHA-1 matches the advertised `.sha1`.
- **Torrent tracker** — BEP 23 compact peers were unimplemented, so a real client's `compact=1`
  announce received a peer list it will not use.
- **WebRTC** → `Incomplete`: `spawn` binds nothing and `accept_offer` has no caller anywhere, so
  no peer connection or data channel ever exists. **WebRTC signaling** relayed nothing —
  `register_peer` took ownership of the write half, so the read loop exited immediately and
  unregistered the peer it had just registered.

### 69. A connection-map race repeated across four protocols **[verified in one, static in three]**

`socket_file` spawned its per-connection task before inserting the connection into the map, so
early data could be processed against a missing entry. Fixed there; the same shape exists at
`src/server/tcp/mod.rs:111` vs `:254`, and by inspection in `src/server/tls/mod.rs:159/297` and
`src/server/ssh_agent/mod.rs:191/317`.

### 70. Assorted, worth fixing when nearby **[verified]**

- `src/cli/banner.rs:31` — a doctest that fails to compile (`module banner is private`), which
  breaks `cargo test --doc` repo-wide.
- ~~`--load <FILE>` is documented and nothing reads it.~~ **Wrong, and the truth was worse.**
  It *is* read (`src/cli/mod.rs:118` via `get_actions_json()`), but it built a second tokio
  runtime and `block_on`-ed inside `#[tokio::main]`, so **`--load` panicked every time it was
  used**. Fixed in `f5092b35` with a synchronous read. The lesson: "nothing reads this flag"
  was inferred from a grep of `src/bin/netget.rs` alone; the caller was one level up.
- `src/cli/server_startup.rs` prints `[SERVER] Server #N (WebRTC) listening on 0.0.0.0:0` for a
  protocol that binds nothing — any `spawn` returning a dummy address is reported as listening.
- `src/server/bgp/mod.rs` never calls `add_connection_to_server`, so BGP peers never appear in
  the TUI connection list.
- `src/server/openvpn/actions.rs:194` still shows `{"type": "no_action"}` in a startup example;
  `no_action` exists nowhere in NetGet.

### 71. Running tally of remotely-reachable crashes **[verified]**

Ten found and fixed this session, all in socket tasks where a panic is silent while the server
still reports `Running`. Collected here because the *pattern* is the finding: every one is a
length or size field taken from the wire, or a string taken from model output, used without a
bound.

| Protocol | Trigger |
|---|---|
| DHCP / BOOTP | one datagram declaring `hlen > 16`; `chaddr()` slices a `[u8; 16]` with it |
| Kafka | four zero bytes shrink a read buffer the next iteration indexes |
| MongoDB | `(message_length - 16) as usize` on a signed `i32`; `messageLength=0` → ~18 EB allocation |
| ZooKeeper | a path length cast to `usize` before validation: `-1` → `usize::MAX`, `12 + usize::MAX` wraps to `11`, passes a `len >= 11` guard, then `&payload[12..11]` panics with start > end |
| gRPC | one non-ASCII character in the model's error text; `grpc-message` → `HeaderValue`, which accepts visible ASCII only. Worse: cleanup runs *after* `serve_connection().await`, so the panic skipped it and leaked the connection as permanently `Active` |
| Cassandra | frame length read as `u32` with no cap while `read_buf` grows a `BytesMut` — declare 4 GiB, dribble, OOM |
| OAuth2 | `?redirect_uri=…%0D%0A` — percent-decoded CRLF into the `Location` header |
| Tor relay | `relay_payload[11..11 + length]` with a `u16` length up to 65535 in a 509-byte buffer |
| Bitcoin | `get_mut(..).unwrap()` after the lock was released — any peer disconnecting mid-flight |
| Proxy / MySQL | `&request_str[..200]` on lossy-decoded text; `ErrorKind::from(u16)` panics on an unknown code fed from model output |

Worth a standing check when touching any binary protocol: every length field validated against
the remaining buffer *before* widening, every `as usize` on a signed value rejected if negative,
and every model-supplied string that becomes a header validated for what that header accepts.

### 72. Two more protocols no real client can talk to **[verified]**

Same shape as Kafka and TURN, bringing that group to five.

- **ZooKeeper** → `Incomplete`. A `ConnectRequest` carries neither xid nor opcode, but
  `parse_request` reads bytes 0..4 as the xid and 4..8 as the opcode — so a connect is reported
  as `operation: "unknown"` and the `ConnectResponse` the client blocks on is never produced.
  Its E2E test hand-builds bytes over a raw `TcpStream` and never sends a ConnectRequest, which
  is exactly why this survived.
- **etcd** kept `Experimental` but was badly wired: `handle_put` looked for `etcd_put_response`
  and `handle_delete_range` for `etcd_delete_range_response`, while `execute_action` accepted
  only `etcd_range_response`/`etcd_error` and rejected both as unknown. Put could not set its
  revision, DeleteRange always reported `deleted 0`, "key not found" became an empty success,
  and `handle_txn` hardcoded `succeeded: false` — so **every distributed-lock acquisition
  failed**.

Also: Cassandra's `serialize_cell_value` took `_col_type` and ignored it, so an `int` column
given `"5"` went on the wire as the ASCII byte `0x35`.

### 73. Tests mocking another protocol's action names **[verified]**

Third instance of this exact shape, so it is a pattern rather than a slip:

- `tests/server/oauth2/e2e_test.rs:227` mocks `send_token_response` — an *openid* action name.
  It passed only because the fail-open default masked the rejection (item 62).
- `tests/server/mcp/e2e_test.rs` (7 sites) mocks `send_jsonrpc_response` — a *jsonrpc* action.
  4 of 9 MCP tests fail on it, identically before and after this session's changes.
- `tests/server/http/test.rs` answered a network event with `write_file`, which HTTP does not
  offer (fixed in `2528629`).

The action-name validation added in `0069d90c` catches this at `start_server` time for
handlers. Extending the same check to mock rules would catch it in tests.

### 73b. Final test state at HEAD **[verified]**

Measured in a clean worktree on the CI feature set (`tcp,http,dns,udp,redis,mcp-stdio`) with
`--no-fail-fast`: **289 passed, 27 failed, 26 ignored**, against 5/24 on the protocol suite at
session start.

`tests/server.rs` — the protocol E2E suite — is **fully green**. Every remaining failure is
attributed, and only five are real:

| Suite | Failing | Cause |
|---|---|---|
| `ollama_model_test` | 20 | A model-*evaluation* harness needing a real Ollama with `qwen2.5-coder:7b`. Neither `#[ignore]`d nor feature-gated, so it fails for anyone without that exact setup and would fail CI. Should move behind the existing `--use-ollama` opt-in. |
| `client` | 4 | Genuine — the only real product failures left. |
| `scripting_executor_test` | 2 | This machine's Homebrew Perl lacks the `JSON` CPAN module. Environmental; the test should detect and skip. |
| `logging_unit_test` | 1 | Asserts a description contains the literal `"log file"`; reworded in `e75043df` (2025-12-29), so failing since long before this session. |

The doctest failure that made `cargo test --doc` fail repo-wide is fixed (`f4fb7dcf`).

Gating `ollama_model_test` would take the visible failure count from 27 to 7.

### 74. Protocol review coverage: 114 of 114 **[complete]**

Every server protocol directory has now had a full 9-point review. Final demotion tally — nine
protocols were rated above what they could do:

| Protocol | Was | Now | Why |
|---|---|---|---|
| openvpn | Stable | Incomplete | no TLS handshake; identical key for every peer |
| tor_relay | Stable | Experimental | blocks forever on a real client's 11-byte VERSIONS cell |
| amqp | Experimental | Incomplete | handshake frame declares 20 bytes and writes 31 |
| kafka | Experimental | Incomplete | no LLM integration; `ApiVersions` advertises nothing |
| zookeeper | Experimental | Incomplete | reads xid/opcode out of a ConnectRequest that has neither |
| turn | Experimental | Incomplete | never binds a relay socket |
| webrtc | Experimental | Incomplete | `spawn` binds nothing; `accept_offer` has no caller |
| webdav | Experimental | Incomplete | serves a real in-process `MemFs`, never consults the model |
| vnc | Experimental | Incomplete | no LLM integration at all |
| bluetooth_ble_beacon | Experimental | Incomplete, since promoted back to Experimental | the crate could not set an advertising payload; now bypasses it with BlueZ on Linux and refuses elsewhere |

`nfc`, `bgp` and `usb_smartcard` were already `Incomplete` and remain so, correctly.

The single most common defect, across the whole sweep, was rubric item 3 — an `EventType`
that never advertised the actions answering it, leaving the model with no vocabulary. NFS was
the starkest: its event had a *comment* where its action list should be, so all ten
`nfs_*_response` actions were invisible and every operation failed.

### 75. `debug_assert!(false)` panics dev-build connection tasks **[verified]**

`src/llm/action_helper.rs:465` guards the item-56 defect: when a protocol declares sync actions
but the event advertises none, it logs at ERROR, falls back to the full sync set, and
`debug_assert!`s. The intent is right — that class of bug must not ship quietly — but the assert
fires **per connection at runtime**, inside a tokio task, where a panic is silent and leaves the
server reporting `Running`. The NFS reviewer hit exactly that.

The tradeoff is genuine, so this is recorded rather than unilaterally changed: the loud failure
is valuable, but a connection-task panic is the quietest possible way to be loud. Better would
be to assert once at server startup, where the failure is visible and attributable, and leave
the per-event path to the ERROR log plus fallback.


### 76. Peer-handle triage for servers without `io::split` **[verified]**

The peer-handle sweep (`src/server/peer_support.rs`; see `3691ffd6` pop3, `1136b036` bgp)
adopted servers whose connection loop already owned a split write half
(`Arc<Mutex<WriteHalf>>` — what `spawn_peer_command_task` wraps: a way to write bytes and to
`shutdown()` from outside the loop). Everything without `tokio::io::split` in its `mod.rs` was
skipped unexamined. Triage of those, from the code, not the CLAUDE.mds. Verdicts: **(a)** a
per-connection owned write side exists that a `peer_support` handle could wrap cheaply;
**(b)** feasible but needs plumbing (a channel or library handle instead of an `AsyncWrite`);
**(c)** not feasible (library owns the socket outright, or hyper-style request/response).

| Protocol | Conns tracked? | Write-side ownership | Verdict | Note |
|---|---|---|---|---|
| cassandra | yes | conn task owns unsplit `TcpStream`; ~12 response helpers take `&mut TcpStream` | a | mechanical `io::split` + thread `Arc<Mutex<WriteHalf>>` through helper signatures |
| postgresql | yes | `pgwire::tokio::process_socket` consumes the socket | c | handler answers queries only; no write path or close exposed |
| mssql | yes | conn task owns unsplit `TcpStream`; 6 helpers, exactly **one** `write_all` site | a | single write choke point makes the split refactor small |
| mongodb | yes | conn task owns the stream; uses borrowed `stream.split()` inside `run()` | a | swap borrowed split for `tokio::io::split` + `Arc<Mutex<WriteHalf>>`; 4 write sites |
| ssh | yes | `russh::server::run_stream` consumes the socket; its returned session handle is discarded (`Ok(_)`) | b | keep the russh handle; injected data must target a channel id, close via the handle |
| socks5 | yes | unsplit stream through handshake, then `copy_bidirectional` (passthrough) or MITM select loop | c | write halves exist mid-tunnel but the bytes belong to the relayed protocol; MITM loop could take a select arm (b) at best |
| tls | yes | **mislisted — `mod.rs:122` does `tokio::io::split` and already keeps `Arc<Mutex<WriteHalf<TlsStream>>>`** | a | cheapest win of all: the exact shape `spawn_peer_command_task` wants, just never adopted |
| ldap | **no** | session struct owns unsplit `TcpStream`; one `write_all` site | a | must add `add_connection_to_server` first — currently zero connection tracking |
| kafka | yes (+stats) | conn task owns unsplit `TcpStream`; writes funnel through one `send_response` | a | mechanically cheap; semantically only disconnect is safe — Kafka is strict correlation-id request/response, unsolicited bytes desync clients |
| smb | yes | conn task owns unsplit `TcpStream`; exactly one `write_all` site | a | same caveat: SMB2 messages carry message ids, so injection is mainly useful for disconnect |
| nfs | **no** | `nfsserve` owns RPC, framing and the TCP listener (`handle_forever`); connections never surface | c | nothing to attach a handle to |
| proxy | yes | borrowed `.split()` halves shuttling client↔destination (plus `tls_mitm.rs` variant) | c | a tunnel: injected bytes corrupt the proxied stream |
| websocket | yes | tungstenite sink owned by a dedicated writer task fed by an unbounded `WsOut` mpsc | b | cheap protocol-specific handle: translate injected actions into `WsOut` down the existing channel (`Close` included); the generic `AsyncWrite` helper cannot wrap a `Sink<Message>` |
| git | yes | hyper `http1::serve_connection` owns the socket | c | request/response; nothing to message |
| mercurial | yes | same hyper shape as git | c | — |

Other registered servers without `io::split`, grouped (same three checks, per family):

| Family | Members | Verdict | Note |
|---|---|---|---|
| hyper request/response | http, pypi, maven, snowflake, rss, dynamo, s3, sqs, elasticsearch, couchdb, yarn, spark, npm, oci_registry, kubernetes, ipp, webdav, openai, ollama, oauth2, jsonrpc, xmlrpc, openapi, openid, saml_idp, saml_sp, doh, grpc, etcd (+ mcp on axum, http2 driving `h2` directly) | c | the framework owns the connection; a "peer" lives only for one exchange |
| UDP / connectionless | udp, dns, dhcp, bootp, ntp, tftp, snmp, syslog, mdns, coap, stun, turn, sip, rtp, rip, radius, igmp, torrent_dht, openvpn, ipsec | b | no per-peer socket: a peer is an address entry on one shared `UdpSocket`; needs a UDP-shaped handle (`send_to(addr)`, no close), not the `AsyncWrite` one |
| raw / link-level | datalink, arp, icmp, isis, ospf | c | pcap/raw-socket write, no per-peer stream |
| off-network | usb\* (6), bluetooth_ble\* (16), pty, stdio, named_pipe | c | no TCP peer to message; named_pipe's response FIFO is a single fixed writer |
| library-owned dataplane | wireguard | c | `defguard_wireguard_rs` owns the tunnel |
| ws-carried | webrtc, webrtc_signaling | b | futures split of a `WebSocketStream` — same `WsOut`-channel shape as websocket |

Individually notable outside the named list: **quic** already keeps
`Arc<Mutex<quinn::SendStream>>` per stream (`mod.rs:37`) and `SendStream` is `AsyncWrite` —
verdict (a), nearly drop-in per stream. **dot** (3 write sites) and **tor_relay** (5) own
unsplit `TlsStream`s in their session structs — (a) mechanically, but **neither calls
`add_connection_to_server` at all**, so tracking comes first, as with ldap. **ssh_agent** was
also effectively mislisted: `mod.rs:152` splits its `UnixStream`, so its `WriteHalf` fits the
generic helper — (a). **mysql** splits too, but hands both halves to opensrv's
`AsyncMysqlIntermediary` — the library owns the write side, so (c) despite the split. And
three already-split servers the sweep itself has not yet adopted: `socket_file`, `hls`, `nfc`.
