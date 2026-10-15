# Protocol quality — the plan after Programme 2

Programme 2 (`PROTOCOL_ROADMAP.md`) took every protocol through an eight-point rubric by hand,
once. It found ~200 defects, and the classes that recurred are the useful output: fail-open
defaults, narrowing casts, tests that encode the bug, advertised knobs that do nothing, bounds
decided by configuration rather than by the answer, unbounded pre-auth input, and clients that
reach the vendor instead of the target.

This file is what comes next. Two principles decide what is on it:

1. **A ratchet beats a pass.** A pass finds today's instances; a ratchet finds the next one the
   day it is written. Every class Programme 2 found by hand that *can* be mechanised should be,
   and the baseline may only shrink.
2. **An independent oracle beats self-agreement.** The BLE HID descriptors, the GATT UUID keying
   and the bcdHID assertion were all green because the only parser that disagreed lived on
   someone else's machine. The cheapest way to find that class is to put an independent decoder
   in the test — and one already exists for ~109 of these protocols (see the pcap oracle).

Tick a box when the item is **verified**, not when it is written. Where an item has a number,
re-derive it before and after; the "starting point" figures below are from 15 September 2026
and drift.

---

## Starting point (measured 15 September 2026)

| Measure | Value | How derived |
|---|---|---|
| Server maturity | 39 Beta · 118 Experimental · 0 Stable — **45 Beta · 112 Experimental as of 15 Sep 2026** | `python3 scripts/beta_evidence_table.py --all` |
| Client maturity | 1 Beta · 97 Experimental | same, `src/client` |
| Servers with an LLM path | 140 | `call_llm`/`llm_client` in `mod.rs` |
| … of which log `decision=` | 113 (**27 missing**) | `decision=` literal in `mod.rs`/`actions.rs` |
| Servers with a connection cap | **2** | `MAX_CONN`/`max_connections` token |
| TCP accept-loop servers without any read/idle timeout token | **18 of 32** | `TcpListener` in `mod.rs`, no `timeout(`/`IDLE`/`READ_TIMEOUT` |
| Servers registering peer handles (`[ message ]`/`[ disconnect ]`) | 32 | `peer_support::` in `mod.rs` |
| Clients registering a command channel (`[ send ]`) | 99 | `register_command_channel(` in `mod.rs` |
| `get_dependencies()` overrides | **1** | grep |
| Hand-rolled control-character filters still in the tree | 25 | `is_ascii_control`/`is_control()` outside `utils::sanitize` |
| `#[ignore]` in `tests/**/*.rs` | 248, **105 with no reason** | grep |
| Fixed `sleep(Duration::from_secs(N))` in e2e tests | 279 | grep |
| Files that print `SKIP` and pass | 19 — **wrong: that grep counted prose *about* gates. Six real ones, all now hard failures** | `scripts/beta_evidence_table.py` |
| Fuzz targets | **0** (no `fuzz/`, no `proptest`) | — |
| Panic hook | TUI terminal-restore only — **a panic inside `tokio::spawn` is logged nowhere in `--mcp` mode** | `src/tui/event_loop.rs:73` |
| `[profile.release] overflow-checks` | **off** (wraps silently where it ships; panics where you test) | `Cargo.toml` |
| Protocols with a verified Wireshark dissector entry | 109 | `src/tui/wireshark.rs` |
| Protocols with a real third-party client binary **already on this machine** | 67 of 100 checked | `which` over a candidate table |
| Blocking CI test job | 6 protocols | `.github/workflows/ci.yml` |

## Where it stands (re-derived 16 September 2026, same commands)

| Measure | Was | Now |
|---|---|---|
| Server maturity | 39 Beta · 118 Experimental · 0 Stable | **2 Stable** · 49 Beta · 106 Experimental |
| Servers with an LLM path and no `decision=` tag | 27 | **1** (`tor_relay`, baselined) |
| Servers with a connection cap | 2 of 92 | **67 of 92** |
| TCP accept-loop servers with no read/idle timeout | 52 of 92 | **10 of 92** |
| `spawn_server_task` / `spawn_client_task` sites | 3 | **148** |
| `get_dependencies()` overrides | 1 | 4 |
| Hand-rolled control-character filters | 25 (only 12 were filters) | **12**, each with a reason |
| Bare `#[ignore]` with no reason | 105 | **0** |
| Fixed `sleep(from_secs(N))` in e2e tests | 279 | **110** (89 of them inside ignored tests) |
| Fuzz targets | 0 | **17** |
| `proptest` | absent | present, 16 codecs |
| `overflow-checks` in release | off | **on** |
| Panic hook | terminal-restore only, TUI only | **logs every panic, every mode** |
| Blocking CI jobs covering the whole tree | 0 | **1** (16 source-reading ratchets) |
| Client maturity | 1 Beta · 97 Experimental | **unchanged, now on a written bar** — audited 16 Sep, nothing qualified |
| Soak coverage | none | **4 protocol shapes × 10 000 connections**, nightly, no leak found |

**Two rows were re-derived downward on 16 September, and the reason is the session's recurring
one.** They read "**0 of 32**" and "**37**" because the ratchet they came from derived its
population as `mod.rs` containing the literal `TcpListener` — and 60 of the 92 TCP servers bind
through `create_reusable_tcp_listener`, whose call site never writes the type. The denominator
was wrong, so the numerator meant nothing. Measured across all 92 and with the token list
tightened to match *mechanisms* rather than timeout-shaped names, 52 had no read deadline and
68 had no cap; three sweeps have taken those to 22 and 55, and the rest are on the ratchet's
shrink-only baselines.

An earlier correction in the same shape is worth keeping beside it: the timeout scan once
reported `nfs` as having none, because its bounds live in `guard.rs` rather than `mod.rs`
(`FIRST_RECORD_READ_TIMEOUT` and `IDLE_BETWEEN_RECORDS_TIMEOUT` are both there). **A per-protocol
scan anchored on one filename, one type name or one spelling of a call under-reports, and a
green result over an unmeasured population is worse than no check because it is trusted.**

Two of those numbers correct `CLAUDE.md`: command-channel adoption is 99 clients, not "`tcp` and
`telnet`"; and the panic hook exists but restores the terminal rather than logging.

---

## Programme 4 (25–26 September 2026): robustness gaps the ratchets missed, real peers, new protocols

The plan was derived from the tree rather than from this file, because nearly every box above was
ticked. Numbers are from `scripts/beta_evidence_table.py` and the ratchets, before and after.

| Measure | Before | After |
|---|---|---|
| Server maturity | 2 Stable · 49 Beta · 106 Experimental | **3 Stable** (`modbus` joined) · **57 Beta** · 106 Experimental |
| Client maturity | 1 Beta · 97 Experimental | **13 Beta** · 89 Experimental |
| Registered servers / clients | 157 / 99 | 166 / 103 |
| Fuzz targets | 17 | 25 |
| Servers declaring a well-known port | 1 | every socket server with a registered port (ratcheted) |
| Pre-auth whole-process crashes found and fixed | — | 2 (`redis` RESP nesting, `mongodb` BSON nesting at 2.3 KB) |
| Real-model eval (llama3.1:8b, seed 42, 5 runs), the 15 baseline protocols | 155/225 = 69% | **210/225 = 93%** |

What landed, each verified by removing the guard and watching its test fail:

- **Robustness.** Depth guards for `redis` and `mongodb`; connection caps and real idle bounds
  for `http2`, `socket_file`, `ssh_agent`, and for six servers whose only deadline covered the
  handshake (`mqtt`, `doh`, `websocket`, `webrtc`, `webrtc_signaling`, `socks5`), with a ratchet
  for that class; declared inbound bounds for the last ten servers; `tor_relay` no longer admits a
  circuit when the model fails; every connectionless server declares what a failure sends;
  `http2` bounds concurrent streams and shares one body budget per connection; NetGet's own MQTT
  and WebSocket clients keep their transport alive while a turn is parked; startup parameters
  that carry secrets are masked in the log.
- **Usability.** MCP tools for what only the dashboard could do (`send_to_client`,
  `send_to_peer`, `disconnect_peer`, `list_intercepts`, `answer_intercept`, `fail_intercept`);
  non-interactive `--run-for` / `--exit-after-events` and a `--load` hang fixed; well-known
  default ports resolved in one place; declared parameter defaults pre-filled in the form; every
  start path refuses a definitively missing dependency.
- **Evidence.** A `RealServer` test helper, and twelve clients newly Beta against real
  third-party servers (Mosquitto, valkey, etcd, nginx, PostgreSQL, MySQL, slapd, OpenSSH,
  memcached, libcoap, pymodbus, FreeRADIUS) — every one of which found a client defect.
- **New servers, each Beta on a real client:** `dict`, `gemini`, `prometheus`, `docker`,
  `vault`, `beanstalkd`, `zabbix`, `gearman`, `bolt`.

The eval figure combines the committed full run (`EVAL_RESULTS.md`, 241/350 across 25
protocols) with a targeted `tcp`/`telnet` rerun after `tcp` and `tls` went back to raising their
connect event only with `send_first`: the full run predates that change and shows `tcp` at
6/15, the rerun 15/15. Raising the event on every connection was built, measured and kept for
`telnet` only (every telnet banner case had been 0/5).

The eval now also covers `smtp`, `pop3`, `imap`, `nntp`, `memcached`, `mqtt`, `coap`, `modbus`,
`snmp`, `sip` and `websocket` (25 cases, 36 protocols in all). Their first measurement is 30 of 125
runs (24%), every case either 5/5 or 0/5, and none of the failures is the harness: each probe
passes against a mock that answers correctly. The dominant failure is the model reusing the wrong
action (SMTP and NNTP answering commands with the greeting action) or copying an action's own
example values (SNMP, CoAP, memcached stats), which the eval's `copied_example_content` diagnosis
now labels; it had never fired before.

**A description round (27 September 2026) acted on both measurements.** Two techniques did most
of the work: an `answer_with` field in each event naming the answer that one request takes, and
examples rewritten as placeholders so the model stops copying them as data. Commands with exactly
one correct answer (SMTP EHLO, IMAP CAPABILITY, NNTP CAPABILITIES and MODE READER, POP3 CAPA) are
now answered by NetGet itself, which removes the failure and the model call. Before and after,
passes out of 5 per case:

| Protocols | Cases at 5/5 before | Cases at 5/5 after |
|---|---:|---:|
| coap, modbus, snmp, sip, websocket, docker, beanstalkd, gemini, bolt, zabbix | 7 of 24 | 20 of 24 |
| smtp, pop3, imap, nntp, memcached, mqtt | 4 of 15 | 7 of 15, and 13 of 15 at 3/5 or better |

Two protocol defects surfaced on the way and are fixed: `sip` sent every status with the reason
phrase "OK", and a `websocket` accept naming a subprotocol the client never offered became a 503.

**The three cases that round left open were closed on 29-30 September 2026**, and none of them by
rewording. Each was read from the failing runs and then from the captured prompt replayed against
Ollama (llama3.1:8b, seed 42) with one thing changed at a time, before the eval was run:

| Case | Before | After | What changed |
|---|---:|---:|---|
| `modbus/illegal-address` | 3/5 (1/5 at the round's close) | **5/5** | a read is answered with the device's registers **keyed by address**, and NetGet answers exception 2 for a requested address the map lacks. The model's answer — the whole device, ten zeros — did not change; it is now read correctly |
| `docker/inspect-missing` | 0/5 | **5/5** | each route's `docker_api_request` offers only the action that answers it and `send_docker_error`; offered all eight, the model answered the inspect with `send_docker_volumes` |
| `imap/list-folders` | 3/5 | **5/5**, and 5/5 again | `LIST`/`SELECT` offered only their own data action and the tagged response; a completion carrying another tag (the model copied an example's `A001`) is written with the command's own |
| `imap/inbox-count` | 4/5 | **5/5**, and 5/5 again | the same |

Every other case of the three protocols stayed at 5/5 (`modbus/holding-registers`,
`docker/ps-running-container`, `docker/ps-all-includes-stopped`). The pattern is the one to carry
forward: **where the eval shows a model reusing the wrong action, stop offering it.** Every
`call_llm` offers the model exactly `event.event_type.actions`, and a protocol can raise the same
event id with a narrower list per request (`docker::actions::event_for_resource`,
`imap::actions::command_event`) — handlers keep matching the id, and the declared event keeps the
full list for documentation. Two things the round cost, both worth knowing before the next one:

- **A description that reads as a verb becomes a name.** A docker route described as "lists
  containers" was answered with an invented `list_containers` tool call beside the right action,
  which the LLM layer rejects as unknown — `ps-all-includes-stopped` fell to 1/5 until the
  descriptions named the CLI command (`docker ps`) instead.
- **A loaded machine reads as a model failure.** One IMAP after-run scored `list-folders` 0/5
  with every run killed at the 240 s probe timeout before LIST was asked: model calls were
  taking ~35 s, and the greeting alone takes up to five of them, because the model attaches a
  `generate_random uuid` tool call to every answer — the same call the shared response-format
  prompt's "both tools and actions" example shows, which looks like where it comes from — and
  the conversation loop re-asks while a tool call is pending, keeping every iteration's actions. That is a cross-protocol latency multiplier and
  the next thing worth measuring; it is in `src/llm/`, not in any protocol.

The first measurement of the new servers is the next thing to act on: `gemini`, `bolt`,
`beanstalkd` and `docker` scored 0/15, `zabbix` 3/10, `gearman` 7/10, and `dict`,
`prometheus` and `vault` 10/15.

Not done, and why:

- **`smb`'s response headers put MessageId at offset 20, not 24**, so no real SMB client can
  match a reply. Found while bounding its WRITE path; the fix agent was not launched.
- **NSQ, Nostr and OTLP servers** were planned and not built.
- **The registry-audit runner is Ubuntu 22.04**, and five evidence suites first failed there on
  older tools (nginx 1.18, tshark 3.6, gearmand 1.1.19, libcoap 4.2.1, a Python library's
  missing import). Each is fixed in CI or in the test; the lesson is that a Beta rating's
  evidence has to be read in that job's log, because the job reports green regardless.

## Tier 0 — central mechanisms that protect every protocol at once

These are one file each and change the failure mode for all 140 servers. Do these first; they
are cheaper than any per-protocol sweep and several of the sweeps below become ratchets only
once these exist.

- [x] **A logging panic hook, installed in every mode.** `std::panic::set_hook` that writes the
  panic message, the thread and a backtrace at ERROR through `tracing`, then chains to the
  default hook. *Why:* `tokio::spawn` swallows panics, and Programme 2 found three families
  (`block_on` in USB, `blocking_lock` in SMB, `.unwrap()` inside spawned client tasks) where the
  task died, the server stayed `Running`, the log showed success and the peer hung. The TUI's
  hook only restores the terminal; `--mcp` has none. *Verify:* a test that panics inside a
  spawned connection task and asserts the message reaches `netget.log`. *Effort:* S.

- [x] **`overflow-checks = true` in `[profile.release]`.** *Why:* STOMP's `content-length:
  18446744073709551615` panicked in every test build and wrapped harmlessly where it shipped —
  backwards from where you want to find it. With the panic hook above, an overflow in production
  becomes a logged task death instead of a silent wrong answer. Measure the cost on a hot path
  (`tuntap`, `rawip`) before and after; expect <2%. *Effort:* S.

- [x] **`log_template.rs` strips control characters from every interpolated value.** *Why:*
  LLDP, CDP and HSRP each fixed injection into their own log lines locally; the shared template
  renderer is the one place that protects all 140 at once, including the ones nobody has looked
  at. A forged newline in a log line is a forged log entry. *Verify:* a test renders a template
  with `\r\nERROR fake` in a field and asserts one line. *Effort:* S.

- [x] **Migrate the 25 hand-rolled control-character filters to `utils::sanitize`, then ratchet.**
  *Why:* six protocols had six semantics before the shared module existed, and the one told to
  be copied (`whois`) had none. The ratchet fails on any new `is_ascii_control`/`is_control()`
  filter outside `src/utils/`. *Effort:* M (mechanical, but each site needs the right variant —
  `line_field` vs `strip_controls` is a correctness choice, not style).

- [x] **Per-connection tasks tracked and aborted on `stop_server`.** A `JoinSet` on the server's
  entry in `AppState`, every `tokio::spawn` for a connection registered into it, aborted by
  `remove_server`. *Why:* `CLAUDE.md` records that `stop_server` does not cancel in-flight
  connections. A stopped server that keeps answering is worse than one that refuses to start.
  *Verify:* start, connect a peer that never sends, stop, assert the peer reads EOF within 1s.
  *Effort:* M — the registration is one line per protocol, but there are ~140 of them; do the
  shared accept-loop helpers first so most inherit it.
  **Done 15 Sep 2026**: mechanism plus the whole sweep (145 sites, 115 protocols), the
  peer-side contract on four protocols, and `tests/detached_task_drift_test.rs` as the ratchet.
  What is still detached is enumerated with a reason in Done, below — the one open gap is a
  task awaited inside a `select!` by a registered parent, because aborting a parent does not
  abort its children.

- [x] **`decision=` tagging on the 27 servers that have an LLM path and no tag.** The list is
  in the measurement script; `ftp`, `http`, `telnet`, `udp`, `mqtt`, `ntp` and `tftp` are the
  ones that matter most because they are Beta. *Why:* without the tag, a backend outage and a
  model refusal are the same log line, and `grep decision=fail_closed` — the one diagnostic this
  repo teaches — finds nothing. *Verify:* make it a ratchet: any `mod.rs` containing `call_llm`
  must contain `decision=`. *Effort:* M.

- [x] **Silent-on-failure becomes metadata, not prose.** `ProtocolMetadataV2::failure_mode`
  (`Answers(WireFailure category)` / `DeliberatelySilent { reason }`), declared by every server.
  *Why:* `CLAUDE.md` carries a list of 20 deliberately-silent protocols that was found wrong
  in both directions (NDP logged its own transmit failure as `model_silent`; several BLE
  profiles were on it by family membership rather than by decision). A declaration is
  checkable; a paragraph is not. *Verify:* `wire_failure_test` reads the declaration and asserts
  a `DeliberatelySilent` server writes nothing on the LLM-error path, and an `Answers` server
  writes its category. *Effort:* M.

## Tier 1 — independent oracles

- [x] **The pcap oracle: every frame NetGet emits is dissected by tshark without error.** A test
  helper that captures what a server writes (from the test's own socket — no capture privilege
  needed), wraps it in a synthetic pcap with the right link type and port, runs
  `tshark -r x.pcap -V -d <decode-as>` using the *already-verified* names in
  `src/tui/wireshark.rs`, and fails on `[Malformed Packet]` or any `Expert Info (Error)`.
  *Why:* this is an independent decoder for **109 protocols at once**, written by people who
  have read every RFC, and it is already installed. It would have caught the HID descriptors,
  the transposed pad bytes, the big-endian bcdHID, CDP's EtherType-as-length, and every "wrong
  flags bit" class Programme 2 had to reason about by hand — those are exactly what a dissector
  flags. *Verify:* the helper itself gets a test that feeds it a deliberately truncated DNS reply
  and asserts it fails. *Effort:* M for the helper, then S per protocol to adopt (one call at
  the end of an existing e2e test). Start with the 39 Beta servers — a Beta whose frames tshark
  rejects is misrated.

- [x] **Fuzz targets for every pre-authentication decoder.** *(harness + 17 targets landed
  15 September 2026; `fuzz/`, `.github/workflows/fuzz.yml`, `fuzz/README.md`.)* `cargo-fuzz`
  with `libfuzzer`, its own workspace root so `cargo test` at the repository root never sees
  it, dispatch-only job at 300s per target, one matrix job each, crash artefact and grown
  corpus uploaded. Every target ran 60s clean locally before merging; none crashed. The harness was
  itself verified by removing `utils::bencode`'s depth guard and confirming the fuzzer finds
  the overflow — the same discipline the AMQP field-table bound was checked with, and the
  only thing that distinguishes "found nothing" from "not looking".

  **Landed:** bencode, SNMP BER, AMQP field tables, NATS framing, STOMP framing, RADIUS
  attributes, DNS wire format, LLDP, CDP, HSRP, Modbus, CoAP, M3UA, BGP, NDEF, ISO 7816
  APDUs, the NFS RPC record guard. Four of those are *guard pairs* — they drive NetGet's
  screen and then hand whatever it accepted to the decoder it guards, which is the contract
  that matters; a target asserting only that the guard does not panic tests the easy half.

  **Still open, and neither is a NetGet decoder defect:**
  - **No USB protocol can be fuzzed at all.** `usb-fido2` → `usb-common` → `usbip` → `nusb`,
    and nusb 0.2.7 (newest published) has a `#[cfg(fuzzing)]` helper that does not typecheck
    (E0271). cargo-fuzz sets `--cfg fuzzing` graph-wide, so the build dies before reaching
    NetGet. Costs CTAPHID reassembly and — the one worth returning for — CTAP2's
    `serde_cbor::from_slice` behind a one-byte command check, which is the unguarded-recursion
    class with no guard in front of it.
  - **SIP, SMB, MSSQL and torrent-tracker parsers are private** on private return types.
    Reaching them costs more visibility surface than a fuzz target should buy unilaterally;
    `SmbServer::parse_smb2_path`/`parse_smb2_username` are hand-rolled offset arithmetic on
    pre-auth CREATE and SESSION_SETUP bodies and are the best of them.

  Also recorded in `fuzz/README.md`: **ASan deadlocks before `main` on macOS 26/27**, so
  local runs need `-s none`. It presents as a slow fuzzer rather than a broken one — no
  banner, no corpus growth, ~25% CPU, sailing past `-max_total_time` — and cost a full
  debugging pass. Stack-overflow detection is unaffected, since libFuzzer's signal handler
  catches the guard-page `SIGSEGV` with or without ASan.

- [x] **Property tests for every codec that has both directions.** `proptest` round-trips:
  `decode(encode(x)) == x` for arbitrary `x`, and `encode` output length ≤ the declared bound.
  *Why:* `m3ua` had `MAX_MESSAGE_LEN` on decode and nothing on encode; the property would have
  said so. *Effort:* M.

- [x] **Hard-fail the skip-when-missing gates.** *(15 September 2026.)* The "19 files" figure
  counted every file containing the string `SKIP`, most of which were prose *about* gates.
  Re-derived, the real skip-and-pass gates guarding a third-party client were six, and all six
  are now hard failures naming the binary, the install command and why a skip is unacceptable:
  `websocket` (websocat), `memcached` (memcat/memstat/memping), `pypi` (pip), the `grpc` client
  (protoc), plus two `#[ignore]`d-for-"run manually" tests, which are the same gate with better
  manners — `rtsp` (ffprobe) and `hls` (curl). `oci_registry`, `maven`, `kubernetes`, `radius`,
  `dns`, `gopher`, `npm`, `openvpn` and the `nats` client had already been converted.
  `registry-audit` now installs crane, websocat, ffmpeg, libmemcached-tools, maven, npm,
  freeradius-utils, dig, curl, pip, openvpn and tor, and runs the real-client suites.

  **Left as skips, with the reason** — none is a binary-availability gate:
  privilege (`arp`, `icmp`, `ospf`, `datalink` need root or `CAP_NET_RAW`), device presence
  (`bluetooth`, `nfc`, `smb` injection halves), platform (`can` skips where the host *has*
  `AF_CAN`, which is correct), Cargo feature (`oauth2` client), opt-in (`USE_OLLAMA`), and
  `tests/scripting_*` (python3/node — outside the protocol tree, but they are real gates and
  both interpreters are installed here).

  **Re-verified across all 50 Beta protocols, 16 September 2026, and it holds.** Anchoring the
  pattern on the attribute (`^\s*#\[ignore` / `^\s*#\[cfg_attr(.*ignore`) rather than the bare
  word, no Beta protocol's test directory contains a real `#[ignore]` or a real
  `SKIP: … not installed` return. The three apparent hits are all prose: `mqtt` and `websocket`
  carry doc comments explaining *why* they refuse to skip, and `etcd` has a redundant
  `#[cfg_attr(not(feature = "etcd"), ignore)]` on a file already gated `#![cfg(feature = "etcd")]`.

  The unanchored grep is what produced the original "19 files", and it produced ten false
  positives again here. **A comment quoting the thing you are grepping for is the most common
  false positive in this repository** — the same mistake that made the test-location policy read
  as violated, and that reported every test directory as orphaned.

- [ ] **A second independent client for every Beta rating that rests on one.** One client can
  agree with one bug: HTTP with `curl` *and* Python `http.client`; DNS with `dig` *and* the
  system resolver; Redis with `redis-cli` *and* `redis-rs`. *Why:* two implementations that
  disagree with each other but agree with NetGet is the strongest evidence short of the spec.
  Cheap where the binary is already installed. *Effort:* S each.

  **Started, and the first one paid for the whole item.** `etcd` was Beta on `etcd-client`
  alone, which is tonic. Adding `etcdctl` (grpc-go) showed it could not complete a *single* RPC
  carrying a body: the server put `grpc-status` in the initial HEADERS and never emitted
  trailers. `grpc` had the identical defect, found the same day by `grpcurl`. In both, the error
  path was accidentally correct — an empty body is Trailers-Only — so only the success path was
  broken, and the failure paths were the ones the suites asserted on. Both are fixed and both
  now carry two clients. etcd went Experimental and back to Beta in a week; grpc went
  Experimental → Beta. The remaining single-client Betas are the rest of this item.

  **16 September 2026 — `postgresql` and `redis` each have a second client, and neither found a
  defect.** `psql` 14 / libpq against postgresql and `redis-cli` (valkey-cli 9.1.2) against redis
  both completed a real session on first contact with no server change required —
  `tests/server/postgresql/real_client_test.rs` and `tests/server/redis/real_client_test.rs`,
  both hard-failing when the binary is absent. That is the honest outcome and it is worth
  recording as loudly as a bug would be: the etcd/grpc result taught that a second client
  *often* finds something, not that it always does.

  Each test was verified non-vacuous by breaking the server and watching the real client's own
  rendering change — postgresql's `encode_value` made to send `Some("")` for a JSON `null` (psql
  printed `2,bob,f,` instead of `2,bob,f,<NULL>`), redis's `encode_null` made to emit
  `$0\r\n\r\n` (redis-cli printed `""` instead of `(nil)`). What psql adds is the
  `sslmode=prefer` SSLRequest exchange that `NoTls` skips and the rendered result rather than the
  deserialised one; what redis-cli adds is the type read off the wire (`(nil)` vs `""`,
  `(integer) 7` vs `"7"`) and a whole session asserted as one ordered list. Neither reaches
  postgresql's extended query protocol — psql 14 has no `\bind` — so that still rests on
  tokio-postgres alone.

  **The DNS family, same day, and the one that mattered most was the cheapest.** `kdig` (Knot
  DNS, CZ.NIC — a separate implementation from ISC's `dig`) is now the second peer for **three**
  protocols:

  - **`dot`** — its own `e2e_testing` had named `kdig +tls` as the one thing that would close its
    gap, and recorded that it was not installed. `rustls` proved the transport; the DNS message
    was hand-assembled over **hickory-proto, the codec the server encodes with**, so that half
    proved our encoder agrees with our decoder.
  - **`doh`** — same circularity, plus **ALPN was unproven** because the reqwest test connects
    with `http2_prior_knowledge()`, which skips ALPN entirely. kdig negotiates it. Changing the
    advertised protocol from `h2` to `http/1.1` now fails the test with kdig's own TLS alert, and
    kdig drives **both** RFC 8484 encodings it chose for itself.
  - **`dns`** — already had `dig`, so this is the second *third-party* resolver rather than the
    first, and it is what puts dns on the Stable shortlist beside `coap` and `modbus`.

  Each was verified by answering with a fixed transaction id instead of the client's, at which
  point the resolver discards the reply — the class of defect a round-trip through our own codec
  cannot see, because our decoder does not care what id it reads.

  **Two traps in driving kdig, each of which cost a cycle**, recorded because they present as
  server bugs: `+https` takes `[authority][/path]`, and the authority becomes the **TLS SNI**, so
  an IP literal there is rejected by rustls with a fatal alert that looks exactly like a cipher
  or ALPN mismatch; a *name* there instead switches kdig to a validating profile that a
  self-signed certificate cannot satisfy. The path alone keeps the opportunistic profile.

  **`mysql` was the item's reference case and it is now closed, which is the third protocol this
  week to be found broken against the client a user would actually reach for.** The server
  offered `mysql_native_password`, whose client plugin MySQL 9.0 deleted, so the real `mysql`
  9.3 CLI could not connect at all — `ERROR 2059 … Authentication plugin cannot be loaded`. It
  now offers `caching_sha2_password`, and `tests/server/mysql/real_client_test.rs` drives the
  real CLI through a session.

  Two things from that repair generalise, and both are about how the fix was found:

  - **Reverting the obvious line did not reproduce the failure.** The client survives a greeting
    it cannot honour — it answers naming its own plugin — and dies on the `AuthSwitchRequest`
    that follows. A regression test asserting on the advertised plugin name would have been
    green against the bug, so the test asserts on what the client printed.
  - **The fix broke a bound that only one test could see.** The new writer had no
    `poll_write_vectored`, so tokio forwarded only the first slice and every packet went out as
    a bare 4-byte header. Real clients reassemble, so nothing else in the suite could notice;
    `packet_limit_test.rs` caught it.

  And it is a statement about packets, not about security: **that server authenticates nothing**
  — no password is stored or compared and the model is not consulted. `caching_sha2.rs` says so
  in its first paragraph, and the metadata repeats it, because "offers caching_sha2_password"
  reads like "checks a password" to anyone skimming.

  **The AWS family and `http`, 16 September 2026, none of which found a defect.** `sqs`, `dynamo`
  and `s3` each gained the real `aws` CLI — botocore, a different SDK generation with a different
  serialiser — and `http` gained **two**: `curl` and Python's `http.client`.

  Each test was verified non-vacuous by breaking the reply and watching the client's own
  rendering change: a renamed `MessageId`, a DynamoDB `N` attribute sent as a JSON number rather
  than a string, a third object added to an S3 listing, a changed custom header. What each second
  client adds is *rendering* rather than deserialisation — a field name a generated deserialiser
  tolerates is a missing column there. `s3` is the most valuable of the four, because it is the
  one AWS protocol whose reply is a hand-written **XML document**.

  **The AWS tests carry three guards and they are not decorative.** The project CLAUDE.md records
  that the DynamoDB *client* dropped its target, let the SDK resolve
  `https://dynamodb.<region>.amazonaws.com`, and signed with ambient credentials — a client
  pointed at localhost issuing real reads and writes against real AWS. So: `--endpoint-url` on
  every call, the port asserted non-zero before the CLI is spawned, and credentials, region,
  profile and the EC2 metadata service overridden in the child's environment.

  One trap worth knowing: **`AWS_PROFILE=""` is not "no profile"**. The CLI looks for a profile
  named the empty string and exits `The config profile () could not be found` before touching the
  network. The variable has to be *removed* from the child's environment.

  All three evidence fields now also say the thing the tests cannot: **no signature is validated
  anywhere in the cloud family.** Every request is served unconditionally, and neither
  `Authorization` nor `X-Amz-Date` reaches the event, so the model cannot make that decision
  either.

  **September 22 2026 added four more: `ssh`, `imap`, `ldap` and `webdav`**, each with the
  non-vacuity check recorded in the test's own doc comment:

  | protocol | second client | broken to prove the test is not vacuous | what the client then did |
  |---|---|---|---|
  | `ssh` | the OpenSSH `ssh` binary | `llm_auth_decision`'s accepted branch → `Ok(!allowed)`; separately, `exec_request`'s success exit status → `69` | `Permission denied`, exit 255 on the admitted session; and — for the second break — **stdout stayed byte-for-byte correct while only `$?` moved** |
  | `imap` | python3 stdlib `imaplib` | `body.len()` → `body.chars().count()` for the FETCH literal; separately, the `* n EXISTS` line removed from SELECT | `('OK', [None])` from `m.fetch()` and from `m.select()` — **the tagged completion was right both times** |
  | `ldap` | OpenLDAP `ldapsearch` | the attribute `SET OF` truncated to its first value; separately, `encode_ber_length` forced to the short form | one `objectClass` line instead of three; then no LDIF at all, exit 254, `ldap_result: Local error (-2)` |
  | `webdav` | `curl -X PROPFIND` | `xml_escape` dropped from `displayname`; separately, `percent_encode_path` dropped from `href` | still `207`, but the body stopped being well-formed XML (`Cannot find ';' after '&'`); then a well-formed body whose href read `/documents/notes & drafts.txt` |

  **`ssh` was the one that found something — twice.**

  1. **A live bug, fixed: `ssh host cmd` failed with exit 255 about one run in five.** NetGet
     sent `SSH_MSG_CHANNEL_CLOSE` **twice** on an exec channel — once from `exec_request` with
     the exit status, once from `channel_eof` when the client's own EOF arrived. RFC 4254 §5.3
     allows one per party, and by the time the second arrives the peer has usually freed the
     channel, so OpenSSH disconnects with `oclose packet referred to nonexistent channel 0`.
     It failed **after** the output and `exit-status 0` had arrived intact, which is exactly
     why it read as a flake: the assertion that caught it was the *exit status*, and
     everything byte-level still passed. libssh2 ignores the second CLOSE.
     `SshHandler::close_channel_once` is the fix — measured 4 failures in 20 runs before, 0 in
     25 after — and the test additionally asserts OpenSSH's stderr carries no channel protocol
     error, which is the surviving-but-noisy form of the same bug and shows on *every* run.

     The general shape is worth keeping: **an intermittent failure in a brand-new real-client
     test is the finding, not the noise.** Four runs in twenty is what a "load flake" looks
     like, and the root `CLAUDE.md` says so — every test on this repository's old
     "only fails under load" list turned out to have a defect underneath it.

  2. **A deviation, not fixed:** NetGet applies `normalize_line_endings` on the *exec* path,
     where no PTY exists, so `ssh host cmd` returns CRLF where a real `sshd` returns LF and
     `OUT=$(ssh host cmd)` keeps a stray `\r`. libssh2 could never have seen it — its tests
     compare the output against a string the same test wrote, so CRLF on both sides agrees
     with itself. `src/server/ssh/mod.rs` implements no `pty_request` handler, so the server
     cannot tell an exec channel from a PTY one and the honest fix is channel bookkeeping
     rather than a one-line edit. The test asserts the behaviour **and names it as a
     deviation**, so a fix fails a test that describes the defect rather than quietly
     satisfying one that never looked.

  The other three completed their sessions on first contact with no server change required.
  What that pass cost beyond the tests: one unconditional `quick-xml` dev-dependency (its
  `[dependencies]` entry is optional and only `saml`/`xmlrpc` turn it on, so a test gated on
  `webdav` alone could not see it), and one corrected metadata claim — `ldap`'s `e2e_testing`
  had named "the ldapsearch/ldapadd command-line tools" as evidence while nothing asserting
  drove them.

  Running total: `etcd`, `grpc`, `mysql`, `postgresql`, `redis`, `dns`, `doh`, `dot`, `http`,
  `sqs`, `dynamo`, `s3`, `ssh`, `imap`, `ldap` and `webdav` have two clients or more. **Four of
  the sixteen turned out to be broken against a conformant implementation** — `etcd`, `grpc`
  and `mysql` outright, and `ssh` one run in five — which is the answer to whether this item
  was worth doing.

  **The rest of the item, as a map rather than a wish.** Measured against what is installed on
  this machine, the single-client Betas fall into three groups.

  *A second client exists and is installed — this is the work:*

  | protocol | current peer | second peer | note |
  |---|---|---|---|
  | ~~`ssh`~~ | libssh2 (ssh2 crate) | OpenSSH `ssh` | **done** — `tests/server/ssh/real_client_test.rs` |
  | ~~`http`~~ | reqwest | `curl` **and** python3 `http.client` | **done** |
  | ~~`imap`~~ | async-imap | python3 `imaplib` (stdlib) | **done** — `tests/server/imap/real_client_test.rs` |
  | ~~`ldap`~~ | ldap3 | `ldapsearch` | **done** — `tests/server/ldap/real_client_test.rs`; the metadata's false claim is corrected in the same commit |
  | ~~`webdav`~~ | reqwest_dav | `curl -X PROPFIND` | **done** — `tests/server/webdav/real_client_test.rs`. Generic HTTP, but PROPFIND/MKCOL/COPY are WebDAV verbs, not HTTP ones |
  | ~~`sqs`, `dynamo`, `s3`~~ | AWS SDK crates | `aws` CLI | **done** — **handle with care** — the root CLAUDE.md records a client that signed real requests against real AWS because it dropped its target. Pin `--endpoint-url`, a dummy region and dummy credentials. |

  Every row of that table is now struck through: there is no single-client Beta left whose
  second client is already installed on this machine. What remains is the two groups below.

  *Blocked by the tooling, measured not assumed:*

  - **`ntp`** — `sntp` and `ntpdate` are installed and **neither accepts a port**; both reject
    `127.0.0.1:12345` as an unresolvable name and go to 123. A test binds an ephemeral port, so
    aiming either means running as root. Same shape as `dhcp`, which is why `dhcp` is not Beta.
  - **`webrtc`** — browser interop is the missing evidence and there is no headless second
    implementation to point at.
  - **`quic`**, **`mssql`**, **`cassandra`**, **`stomp`**, **`nats`**, **`zookeeper`**,
    **`amqp`**, **`memcached`** — a second implementation exists in the world; none is installed,
    and several (cqlsh, zkCli, sqlcmd) drag a runtime behind them.

  *Already resting on the reference implementation, so a second is a nicety rather than the
  point:* `git`, `npm`, `maven`, `oci_registry`, `kubernetes`, `radius`, `snmp`, `whois`, `sip`,
  `stun`, `rtsp`, `torrent_tracker`, `memcached`, `svn`.

  **`tcp` and `udp` are deliberately not on any of these lists.** For them the transport *is* the
  protocol, so the OS stack is the independent implementation and a second client would be
  testing tokio.

## Tier 2 — resource bounds, swept and ratcheted

Programme 2 bounded what it found. These are the bounds every connection-oriented server should
declare, whether or not anyone has looked at it.

- [x] **Idle and first-read timeouts on every TCP server without any.** *(Done 22 September
  2026 — `TIMEOUT_BASELINE` in `tests/tcp_server_bounds_ratchet_test.rs` is empty, and `SWEPT`
  pins 38 protocols against losing either bound.)* Started at 52 of 92; five agent sweeps closed
  it. The numbers were argued per protocol rather than copied, and three ended up nowhere near
  the 300s the early slices settled on: `xmpp`'s idle bound is 900s because a silent XMPP
  session is normal and neither ejabberd nor Prosody closes one at all; `usb/*` takes **1800s**
  because USB/IP has no keepalive and a drive a host imported but never mounted issues no URB;
  and the USB first-byte bound went *down* to 30s, argued from the fact that NetGet has no
  USB/IP client and `src/protocol/dual.rs` excludes those servers from `[ + client ]` pairing,
  so no silent parked peer can exist there. Two bounds nobody asked for turned up on the way: a
  USB message's fixed tail was read with `read_exact` and no bound at all, and `nfc` gave a
  2-byte length prefix the established-connection bound rather than the first-byte one.

  (Historical — the state when this item was last open.) **10 left of 92, measured 22 September 2026** — down from 52 across four agent sweeps:
  `nfc`, `ollama`, `openai`, `rtsp`, `xmpp`, and the five USB/IP servers (`usb/keyboard`,
  `usb/mouse`, `usb/msc`, `usb/serial`, `usb/smartcard`). The USB five are one shape and should
  be done together; `ollama` and `openai` are hyper servers and want etcd's `peek` +
  `ConnectionActivity` pattern rather than a deadline on hyper's reads.

  Originally: `cassandra`, `db2`,
  `etcd`, `kafka`, `m3ua`, `mcp`, `memcached`, `mssql`, `mysql`, `nfs`, `postgresql`, `redis`,
  `smb`, `svn`, `tls`, `tor_relay`, `torrent_peer`, `zookeeper`. `whois`'s
  `FIRST_QUERY_READ_TIMEOUT`/`IDLE_AFTER_REPLY_TIMEOUT` pair is the shape. *Why:* a peer that
  connects and says nothing holds a connection, a task and a state entry forever, and 128 of
  them is a free denial of service on a server with no connection cap. *Verify:* ratchet — any
  `mod.rs` with `TcpListener` must reference a timeout constant. *Effort:* M.

- [x] **Re-examine every first-byte bound against "the peer is NetGet's own client, parked for a
  human".** *(Done 22 September 2026.)* **The criterion this item was opened with was itself the
  wrong test, and that is the finding.** "The server speaks first" exempted `ftp`, `nntp` and
  `pop3` in their own docs — but the greeting is *ours*, and sending it says nothing about
  whether the peer will answer. All three NetGet clients read it in their read loop and write
  nothing until a person types.

  The criterion is now four states, because a byte count conflates the two harmless ones with
  the dangerous one: **lazy** (no socket until it sends), **speaks inside `connect()`** (bytes
  on the wire before any model turn), **connected and silent** (the defect), and **no client at
  all**. Measured across every server with such a bound: 22 lazy, 20 speaks-inside-connect, 10
  connected-and-silent, 13 no client. Each `src/server/*/CLAUDE.md` bounds table records which
  it faces, and `tests/silent_peer_probe_test.rs` measures it per protocol rather than leaving
  it as prose — one test per feature, accepts and bytes counted separately, 5.15s for all of
  them. Nine servers were raised to 300s: `tcp`, `telnet`, `ldap`, `whois`, `redis`, `ftp`,
  `nntp`, `pop3`, `torrent_peer`, plus `tls`'s first *application* record (its handshake wait
  stays at 60s — that phase involves no model and no person and is the cheap phase to abuse).

  (Historical — the reasoning this item opened with.) The bounds sweeps
  argued each first-byte deadline against a **stranger** holding a socket, which is the right
  threat and the wrong peer for this product. The dashboard offers `[ + <proto> client ]` under
  a server's peers with `[ send message ]` beneath it, so the peer is frequently NetGet's own
  client that has connected, been answered with nothing, and is waiting for a person to type.
  It has sent zero bytes the whole time.

  **Measured:** 46 servers carry a 30-second first-byte bound and 10 carry 60; of those, **36
  have a NetGet client wired for `[ send ]`** — `cassandra`, `couchdb`, `elasticsearch`, `etcd`,
  `git`, `grpc`, `http`, `jsonrpc`, `kafka`, `kubernetes`, `ldap`, `maven`, `mcp`, `mongodb`,
  `mssql`, `nats`, `npm`, `oauth2`, `openapi`, `pypi`, `redis`, `rss`, `s3`, `smb`, `sqs`,
  `stomp`, `vnc`, `webdav`, `whois`, `xmlrpc` at 30s, and `bitcoin`, `dc`, `ftp`, `imap`, `irc`,
  `nntp`, `pop3`, `postgresql`, `ssh`, `tls` at 60.

  Derive it rather than trusting the list:

  ```bash
  grep -l register_command_channel src/client/*/mod.rs     # clients a human can drive
  grep -rn 'const FIRST_.*from_secs' src/server/*/mod.rs   # the bounds
  ```

  **This is not a call to raise them all, and the two exemptions first written here were both
  the wrong test.** "The server speaks first" and "the client registers no command channel" fit
  **none** of the protocols later measured: every client examined registers a command channel,
  and a greeting of *ours* does nothing to make the *peer* speak. A first-byte bound can only
  close a peer that is **connected and silent**, so the question is the narrower one: *can
  NetGet's own client of this protocol ever be a connected-and-silent peer?*

  **Three states, and a byte count alone conflates the first with the third — measure accepts
  and bytes separately.**

  - **lazy** — no socket at all until the client sends. A `reqwest`-based client, an AWS or
    `kube` SDK config, a tonic channel built with `connect_lazy`. There is no connection for
    the bound to close. Measured: `elasticsearch`, `s3`, `sqs`, `etcd`, `smb`, `http`,
    `jsonrpc`, `maven`, `npm`, `pypi`, `webdav`, `xmlrpc`, `bitcoin`, `git`, `kubernetes`,
    `oauth2`, `openapi`, `rss`, `dynamodb`, `saml`, `ipp`, `spark`, `yarn`.
  - **speaks inside `connect()`** — connected, and the client's own Rust or its library puts
    the first bytes on the wire before any model turn or keystroke. Measured: `postgresql`
    (StartupMessage), `mssql` (PRELOGIN), `cassandra` (OPTIONS), `mongodb`'s SDAM `hello`,
    `couchdb` (an HTTP request), `imap` (LOGIN), `irc` (NICK/USER), `kafka` (ApiVersions),
    `nats` (CONNECT), `stomp` (CONNECT), `tls` (ClientHello), `mysql` (HandshakeResponse41),
    `zookeeper` (ConnectRequest), `ssh` (ident + userauth), `vnc` (the RFB version reply),
    `nfs` (GETPORT + MNT), `grpc` (tonic's eager `connect()`), `mcp` (`initialize`),
    `openidconnect` (discovery), `dc` (`$Key`/`$ValidateNick`), `db2` (EXCSAT through ACCRDB),
    `snowflake` (login-request).
  - **connected and silent** — a socket is open and the client writes nothing until a model
    action or a human's `[ send message ]`. **This is the defect**: 30 or 60 seconds is shorter
    than the 300 a `manual` rule gives that same person (`src/state/intercepts.rs`), so the
    server drops a peer the operator is still looking at. Measured: `redis` (1 accept, 0
    bytes), `tcp`, `telnet`, `ldap`, `whois`, `ftp`, `nntp`, `pop3`, `torrent_peer`, and `tls`
    at the application layer.

  A fourth, simpler exemption: **no NetGet client of this protocol at all** — `m3ua`,
  `memcached`, `modbus`, `oci_registry`, `rdp`, `reverse_shell`,
  `svn`, `mercurial`, `saml_sp` (the SAML client plays the SP role and targets an IdP). Note
  that `svn`, `mercurial` and `oracle` have a `src/client/<p>/` directory holding only a
  `CLAUDE.md`, so a directory listing over-reports.

  **Two traps the classification itself produced.** A server-speaks-first protocol is *not*
  exempt: `ftp`, `nntp` and `pop3` each write a greeting on accept and their own clients still
  read it and say nothing, which is exactly the case the bound closes. And where a client
  speaks only *after* its connected-event model turn — `dc` — it is exempt because the
  dashboard answers a `<proto>_connected` event with a zero-action static rule
  (`src/tui/modal/form.rs`), not because the turn is fast.

  Derive it per protocol rather than trusting the lists above: read `connect()` and ask whether
  it opens a socket, and whether anything writes to it before the function returns.

  `tcp`, `redis`, `ldap` and `whois` are done and are the worked examples: default raised to
  300s, and both bounds made declared startup parameters so the value is the operator's rather
  than ours. Each `src/server/<p>/CLAUDE.md` with a first-byte bound now records which of the
  four states its own client is in, beneath the bounds table. *Effort:* M.

  **Still open (22 September 2026), each a measured connected-and-silent client against a short
  bound:** `ftp` (60s), `nntp` (60s), `pop3` (60s), `torrent_peer` (30s), `tls` (60s, the
  application half of `FIRST_RECORD_READ_TIMEOUT`) and `telnet` (120s, and the only one of the
  five originally-changed protocols with no `first_byte_timeout_secs` to raise it with).

- [x] **A connection cap on every accept loop.** *(Done 22 September 2026 — `CAP_BASELINE` is
  empty.)* Started at 68 of 92. Every cap was verified twice by mutation: raised to `100_000`,
  every test fails on its refusal assertion; restored with the permits leaked via
  `std::mem::forget`, every test fails on the slot never coming back.

  **The refusals are the interesting half, and seven protocols deliberately say nothing.**
  `ident` closes without a word because every RFC 1413 reply opens by echoing the query's port
  pair and a refused peer has sent no query; `mongodb` and `llmnr` would have to invent the
  field that addresses the reply, which a real client discards rather than surfaces, so the peer
  would wait out its own timeout instead of learning anything; `smtp`, `doh` and `dot` are
  TLS-first, where plaintext is a decode error rather than a refusal and RFC 8446 §6.2 defines
  no alert meaning "at capacity"; `nfc` because every frame it can write is a card response and
  one arriving unprompted desynchronises the ifdhandler. `ipp` declined IPP's own
  `server-error-busy` for the same class of reason — every IPP status echoes a `request-id` the
  refused peer never sent.

  One test-design trap is worth keeping: for the five handshaking protocols the held
  connections complete **real** TLS or RFC 6455 handshakes, because a merely-connected peer is
  evicted by the handshake deadline within 10–15s and would free slots on its own, passing the
  slot-return assertion for a reason unrelated to the permit.

  (Original.) A shared `accept_bounded(listener, max)` helper
  in `server/` that every accept loop calls, refusing past the cap with the protocol's own
  "busy" vocabulary where one exists (SMTP 421, HTTP 503, RESP `LOADING`) and a close where none
  does. *Why:* the NFS guard chose 256 for a reason; nothing else chose anything. *Effort:* M.

  **Re-opened 16 September 2026, along with the timeout item above, because the ratchet that
  closed both could not see two thirds of the tree.** Its derivation was
  `mod_src.contains("TcpListener")`, and most servers here bind through
  `create_reusable_tcp_listener`, whose return type is a `TcpListener` but whose call site never
  writes one. So it walked **32** servers while **92** open a TCP accept loop, and the 60 it
  could not see include `http`, `tcp`, `telnet`, `ssh`, `ldap`, `imap`, `grpc`, `modbus`, `git`
  and `kubernetes`. **47 of them have neither bound.**

  Measured across all 92: 52 named no read deadline, 68 had no connection cap. The ratchet's
  derivation is fixed and both baselines record the debt, shrink-only.

  **25 left, measured 22 September 2026**, down from 68: `amqp`, `bgp`, `doh`, `dot`, `finger`,
  `gopher`, `hls`, `ident`, `ipp`, `llmnr`, `mongodb`, `mqtt`, `nfc`, `ollama`, `openai`,
  `proxy`, `rtsp`, `smtp`, `socks5`, `torrent_tracker`, `webrtc`, `webrtc_signaling`,
  `websocket`, `whois`, `xmpp`. Note `doh`, `dot` and `llmnr` among them: a cap is about
  *accepting*, so a protocol that already bounds its reads still needs one.

  This is the session's clearest instance of the recurring failure: **the test counted a token,
  not the thing**, and a green result over an unmeasured population is worse than no check,
  because it is trusted. The same shape produced "19 skip gates", "6 peer handles" and the
  orphaned-test derivation that reported every directory.

- [x] **Max message / frame size declared in metadata and asserted by a test.** *(16 September
  2026.)* `ProtocolMetadataV2::max_inbound_bytes` with a builder method; **85 of 158 server
  protocols declare one**, and `tests/max_inbound_bytes_declaration_test.rs` is the shrink-only
  ratchet, with a reason on every baseline entry.

  **The "81 do not" figure above was an artefact of the pattern used to derive it.** Anchoring
  on `MAX_*_LEN|SIZE|BYTES` misses `ftp`'s `MAX_COMMAND_LINE`, `irc`'s `MAX_IRC_READ_LINE`,
  `bgp`'s `BGP_MAX_MESSAGE_LEN`, `ldap`'s `MAX_LDAP_MESSAGE`, `webdav`'s `MAX_REQUEST_BODY` and
  `torrent_peer`'s `MAX_PENDING`. Matching any `const MAX_*` gives 59, not 81. The inverse error
  is in the same count: several of the 72 "declared" consts bound a *field* or a prompt
  truncation rather than a message — `datalink`'s `MAX_HEX_BYTES_TO_MODEL`, `mcp`'s
  `MAX_TRACE_BYTES`, `memcached`'s `MAX_VALUE_LEN`, `smb`'s `MAX_WRITE_LEN` — so declaring them
  would have surfaced a number that is not the bound. Both directions are why the item said to
  derive the target first.

  Classifying all 59 by hand found **five protocols with a genuinely unbounded read**, and the
  five do not resemble each other: `pop3`, `nntp` and `imap` each called
  `AsyncBufReadExt::read_line`, which grows its `String` until it finds a `\n` and caps nothing
  (bounded now, via a shared `utils::line_reader`, since `ftp`, `irc` and `smtp` had each
  hand-rolled the same fix); `ssh`'s per-channel echo buffer accumulated across packets beneath
  russh's per-packet bound; and the **USB/IP family** allocated `vec![0; transfer_buffer_length]`
  from a peer u32 inside `usbip` 0.9.0 — 4 GiB from a 48-byte header, pre-auth, on six
  protocols. That one needed a screening guard (`src/server/usb/guard.rs`), because the crate
  owns the framing.

  Two more remain, reported rather than fixed because another agent held those files: `mysql`
  (opensrv-mysql has no max-packet check at all) and `tls` (`conn.queued_data` grows uncapped
  while an LLM call is in flight, which a manual intercept holds open for 300s).

- [x] **A generic bound+1 test over the registry.** *(16 September 2026 —
  `tests/max_inbound_bytes_bound_plus_one_test.rs`.)* It reads `max_inbound_bytes` off the
  registry, starts each declaring protocol on port 0, sends `bound + 1` bytes and asserts the
  server **decided** — closed the connection or wrote something back — with **zero model calls
  attributable to the message**. At `--all-features`: **55 probed, 29 skipped, 3 findings**.
  (54/28 before the same day's `mysql` and `tls` bounds merged in — the point of walking the
  registry is that the two new numbers were probed without anyone editing this test: `tls`
  passes, `mysql`'s 64 MiB is over the cap and is listed as skipped.)

  The item predicted the hard part correctly and it turned out to have two answers rather than
  none. A generic test cannot know each protocol's refusal vocabulary, so it asserts the thing
  every protocol shares — *the bytes past the bound do not reach the model and do not leave the
  connection parked holding them* — and two shapes are enough to reach the bound at all: raw
  bytes for a framed or line-oriented protocol, and a well-formed HTTP request whose
  `Content-Length` declares `bound + 1` for the ~25 whose number is `MAX_REQUEST_BODY_BYTES`
  (raw junk would be refused at the request line, passing while asserting the HTTP parser). It
  does **not** prove the declared number is the one that fired, which is why it is an addition
  to the per-protocol tests and not a replacement.

  **Skipped, all enumerated by the test on every run:** 21 not a TCP stream (UDP, SCTP,
  link-level, USB, NFC — derived from `stack_name()`, not listed by hand), 7 whose bound is past
  the 8 MiB probe cap (`cassandra` 256 MiB, `kafka` 100 MiB, `mysql`/`redis`/`websocket` 64 MiB,
  `mongodb` 48 MiB, `mqtt` 16 MiB), and `grpc`, which will not start without a `proto_schema`.

  **Three real findings, baselined shrink-only rather than exempted** (all outside the boundary
  of the pass that wrote the test, so reported):

  - **`bitcoin`** — a decode error leaves the peer connected with nothing written.
    `try_parse_bitcoin_message` correctly returns `Err` for bad magic, and its own doc comment
    says the caller "drops the connection instead of buffering forever" — but the `Err` arm in
    the read loop logs, sets `ConnectionState::Idle` and returns, leaving the socket open. 4 MB
    of junk is neither answered nor refused. The comment describes the fix that was not made.
  - **`xmpp`** — one 256 KiB write buys ~50 model calls. The read loop's own comment says "for
    simplicity, we'll pass the entire buffer to LLM for parsing", so every read raises
    `xmpp_data_received` carrying the whole accumulated buffer, whose prompt grows toward
    256 KiB. `MAX_XMPP_BUFFER_BYTES` does fire and close the connection — after all of those
    round trips. **The bound caps memory and not the model bill**, which is the half its
    declaration implies it has.
  - **`proxy`** — one model call lands after an over-bound request head. The bound itself fires;
    what the probe cannot settle from outside is whether that call is the connection's own
    arriving late or one the refused head provoked. Needs a human read.

  **Four traps it was built around, three of which it fell into first** — recorded because each
  produced a confident wrong answer:

  1. **Count from a baseline, not from zero.** NNTP and SVN *generate their greeting*, so the
     first run charged a connect-time model call to the payload and reported five protocols as
     enforcing nothing. All five were correct.
  2. **A privileged default port is not a reason to skip.** Everything starts on port 0, so
     `PrivilegedPort(80)` never applies — treating it as a skip cost seventeen protocols
     including `http`, `imap`, `ftp`, `smtp`, `ssh`, `telnet` and `whois`, which is exactly the
     quiet under-coverage the item was written against.
  3. **The registry's name is the display form** (`"Bitcoin P2P"`, `"XML-RPC"`, `"SSH Agent"`),
     not the source directory. Keyed on the directory, every exemption table matched nothing —
     and the USB/NFC entries *appeared* to work only because the transport rule caught them
     first. They are deleted; a reason nothing reaches is a stale reason.
  4. **Wait for the listener.** A connect refused in the gap between bind and accept reads
     exactly like the refusal being probed for — a false pass.

  One exemption is a claim rather than an accident and is documented as such: `tcp`'s
  `MAX_QUEUED_BYTES` bounds data queued behind an *in-flight* LLM call, not one message, so TCP
  answering each read is the design working. `STREAMING_BOUND` holds that, and only the
  zero-calls half is waived — it is still required to decide about the connection.

- [x] **A soak test per protocol family.** *(16 September 2026 —
  `tests/connection_soak_test.rs`, `.github/workflows/nightly-soak.yml`.)* Ten thousand short
  connections against each of four shapes: `tcp` (a reader NetGet wrote), `http` (hyper's
  `serve_connection`, the shape ~30 protocols share), `redis` (a session with its own framing)
  and `dns` (datagram, `.connectionless()`). ~25 s each by construction, ~100 s for the four,
  `#[ignore]`d with a reason and run serially by `nightly-soak.yml`.

  Asserted: the tracked-connection map does not grow with connections served, the registered-task
  count stays a function of *live* connections, RSS is flat, the map returns to zero once traffic
  stops, `recent_connections` holds its cap, and the port rebinds after stop. Measured across two
  full runs: map slope **0.000–0.005** entries per connection, RSS **0–73 B/conn**, peak
  registered tasks **5–33** against ten thousand served. No leak found — the
  `spawn_server_task` sweep's `retain`-on-register pruning holds at the ten thousandth
  connection.

  **Three things it taught, each of which nearly made it a bad test.**

  1. **The reaper is part of the system under test.** With no cleanup tick running, all three
     stream protocols grow the connection map at **exactly 1.0 entries per connection served**,
     and RSS by ~1.4 KB per connection — 34 MiB to 48 MiB over ten thousand HTTP connections.
     That is not a leak, it is the ten-second retention window with nothing reaping it, and a
     test calling it a leak would have been `ospf`'s mistake in a new place. The harness runs the
     reaper at the production values and paces the load to outlast it, so the question becomes
     the one worth asking: steady state, or total ever served? It is steady state, at
     rate × retention. **The 1.0 is still worth knowing** — between two ticks a busy server holds
     one entry per connection in that window, all of it under the single global `AppState` lock,
     and nothing bounds it but the tick.
  2. **RSS steps; it does not slope.** A single ~0.9 MiB allocator arena step between adjacent
     samples reads as ~300 B/conn spread over the measurement window, above any honest rate
     budget, with the map perfectly flat either side. The verdict therefore needs a rate **and**
     an absolute floor, which puts the real sensitivity of the RSS check at about 1 KB/conn
     against a ~1.4 KB/conn defect. The counters are the sharp instruments; RSS is the backstop
     for what they cannot count.
  3. **An abrupt `drop` on a socket is not a close.** The first version wrote, half-closed and
     dropped, and both ends logged `ECONNRESET` after a few hundred connections — the kernel
     sends RST rather than FIN when a socket with unread inbound data is closed. It presented
     exactly as a server defect. Draining to EOF before dropping made it vanish; the server was
     never at fault.

  Pacing is load-bearing and not a throughput knob: a clean close leaves the *test* in
  `TIME_WAIT` for 2·MSL, and macOS has 16 384 ephemeral ports against a 15-second MSL, so an
  unpaced soak exhausts the range and reports `EADDRNOTAVAIL` — a kernel bookkeeping limit
  wearing a leak's clothes.

- [x] **Stop releases the port, every protocol.** *(the generic test exists, and the
  `spawn_server_task` sweep landed 15 Sep 2026 — 145 sites, 115 protocols; see Done)* A generic test: start on port 0, read the
  bound port, stop, bind that port again within 1s. *Why:* `register_server_task` is
  "required for `stop_server` to actually release the socket" and adoption has never been
  measured. *Effort:* S — one parametrised test over the registry.

## Tier 3 — evidence and maturity

- [x] **Define Stable, then earn it for five protocols.** Zero are Stable and three have lost
  it. The bar should be written down before anything is promoted: (1) two independent
  third-party clients complete a real session, hard-fail when absent; (2) the pcap oracle is
  green; (3) a fuzz target exists and has run; (4) every declared bound has a test; (5) the
  protocol's CLAUDE.md has been verified claim-by-claim within the last pass; (6) no
  `#[ignore]` in its suite. Candidates with the cheapest path: `whois`, `gopher`, `finger`,
  `dns`, `http`, `tcp`, `ntp`, `redis`. *Effort:* M each.

- [x] **Beta for the Experimental servers whose evidence already executed.** *(15 September
  2026 — partial: the six whose evidence was already in the tree. The ones that need a test
  written are still open, below.)* 39 Beta → 45.

  - `websocket` — websocat 1.14.1, which links `websocket`/`websocket-base` (rust-websocket)
    and **not** tungstenite, read out of the installed binary. So it is not the circular case;
    the server frames with tokio-tungstenite and shares none of it.
  - `memcached` — libmemcached's C tools. CLAUDE.md listed it under "no independent peer at
    all"; it had one, behind a skip gate. Two different failures, conflated.
  - `rtsp` — ffprobe completes OPTIONS/DESCRIBE/SETUP/PLAY and reads RTP.
  - `oci_registry` — crane re-hashes every manifest and blob and errors on a mismatch.
  - `maven` — real `mvn` resolves, checksum-verifies and now **unpacks** the artifact; the
    fixture became a real zip served over `body_base64`, which was the one gap its own
    `metadata()` named.
  - `ssh` — libssh2 (the `ssh2` crate binds the C library; russh is the *server's*) completes
    auth and a full SFTP exchange. Held at Experimental by a stale comment in its own test
    file describing a bug fixed long before.

  **Considered and deliberately not promoted**, which is the more useful half of the list:
  `hls` (curl is generic HTTP — needs ffprobe, which reads HLS natively), `pypi` (pip reaches
  and parses the PEP 503 page, but `pip index versions` is experimental and the wheel served
  is a stub), `openvpn` (the server implements only the front of the protocol — CLAUDE.md's
  standing ruling), `xmpp` (xmpp-parsers is a parser and XMPP has a session, unlike `rss`),
  `grpc`/`bgp`/`torrent_dht`/`xmlrpc` (codecs), `tls` (rustls both sides).

  Still one test away, client installed, nothing written: `ipp` (ipptool), `syslog` (logger),
  `finger`/`ident` (finger, nc), `ftp` (ftp), `telnet` (telnet), `smb` (smbclient),
  `netbios_ns` (nmblookup), `irc` (irssi), `nfs` (showmount/rpcinfo unprivileged; `mount_nfs`
  needs root — record that), `socks5`/`http2`/`proxy` (curl, but see the generic-HTTP rule),
  `mdns` (dns-sd), `tor_relay` (tor, currently `#[ignore]`d), `rsync`/`sftp` as clients.

- [x] **Install the missing clients and do the same.** *(16 September 2026.)* Installed and
  driven: `mosquitto`, `nats`, `kcat`, `mongosh`, `etcd` (etcdctl), `grpcurl`, `coap-client`,
  `mbpoll`, `stuntman`, `wakeonlan`, `aria2`, `sipsak`, `mercurial`, `subversion`. All are in
  `ci.yml`'s `registry-audit` job except `subversion`, whose test is `#[ignore]`d because a real
  `svn` cannot get past its **own first message** against this server.

  Promoted on the new clients: `kafka` (kcat), `stun` (stunclient), `sip` (sipsak),
  `torrent_tracker` (aria2c), `grpc` and `etcd` (grpcurl / etcdctl, after the trailers fix).
  Refused with a reason rather than promoted: `mercurial` (real `hg` completes the handshake,
  but `hg clone` dies asking for a capability the server hardcodes away — the `openvpn`
  precedent, only the front of the protocol), `wol` (one-way, so nothing NetGet emits is ever
  read by an independent implementation; `wakeonlan` writes our *input*, which is the opposite
  of the `rss` case), `lldp` (`lldpcli` is not an LLDP speaker at all, just the control program
  for a local daemon over a unix socket, so the real peer would need root and a feth pair), and
  `svn` (the blocker is a real defect: its capability tuple ends in a space with no newline and
  our `read_line` never returns).

- [x] **Client maturity — the bar is written down; applying it promoted nothing.**
  *(16 September 2026. The bar is in `CLAUDE.md`'s maturity section, beside the server one.)*
  Four conditions: a real third-party **server** as the peer, and not the crate NetGet's client
  is built on; the test fails rather than skips or `#[ignore]`s when that peer is absent; a real
  session rather than a connect; and the client's use of the model's answer asserted **on the
  wire**, because `client_event_wiring_test` exists for the six that discarded it.

  **Audited all 98. No promotion. `nats` remains the only Beta, and that is the finding.** Five
  *servers* had sat at Experimental with the evidence already in the tree, so the same was
  expected here; the client tree is simply not in that state. It divides four ways:

  - **Circular, ~60 protocols** — `redis`, `postgresql`, `mysql`, `mongodb`, `imap`, `ftp`,
    `irc`, `http`, `whois` and the rest drive NetGet's own server of the same protocol.
    `jsonrpc`, `openapi`, `bitcoin`, `elasticsearch` and `rss` drive NetGet's *HTTP* server —
    same-project *and* generic HTTP, two disqualifications at once.
  - **Real peer, unreachable evidence** — `mqtt` (Mosquitto in Docker), `smtp` (Python `smtpd`),
    `ssh` (external `sshd`), `smb`, `xmpp`, `ldap`, `s3`, `dynamodb`, `sqs`, `tor`. Each names a
    genuine third-party server and **every one of those tests is `#[ignore]`d**. This is the
    cheapest path to a second Beta client, and the work is un-ignoring them — which means
    standing the peer up wherever the suite runs.
  - **Real peer, wrong peer** — `tls` (a `tokio_rustls::TlsAcceptor` against a client that *is* a
    `tokio_rustls::TlsConnector`: rustls agreeing with rustls, the `ssh`/russh case) and `oauth2`
    (an `axum` router, generic HTTP and in this script's own `INFRASTRUCTURE` set).
  - **Public internet** — `dot`, `git`, `npm`, `pypi`, `maven`, `ntp`, all `#[ignore]`d for the
    right reason: localhost only. A local mirror makes these evidence; the public endpoint never
    will.

  Zero skip-and-pass gates exist under `tests/client/` — the only two `SKIP` hits are prose in
  `nats`' header explaining why one was refused. So the client tree does not have the server
  tree's silent-pass problem. It has an `#[ignore]` problem, which is at least visible.

  **Installed on this machine**, so the remaining cost is a number rather than a guess:
  `nats-server`, `redis-server` (valkey), `postgres`, `mysqld`, `nginx`, `sshd`, `httpd`,
  `unbound`, `smbd`, `tor`, `openvpn`, `slapd`, libmemcached's tools. **Missing:** `mosquitto`,
  `vsftpd`, `memcached`, `etcd`, `mongod`, and MinIO or LocalStack for the AWS clients. Nothing
  was installed — hard-failing a gate makes that binary a requirement wherever the suite runs,
  which belongs to whoever owns the CI image.

- [x] **Make `beta_evidence_table.py` client-aware.** *(16 September 2026 — `--side
  {server,client}`.)* The path swap was the four places this item named, and it was **not the
  whole change**, because the two bars are not the same. The client bar adds two conditions the
  server bar does not have, and both had to become checks:

  - **The peer must not be NetGet's own server.** `self-served` is detected from the test
    building a `ServerForm`, calling `start_netget_server`, or sending an `open_server` action,
    and it is blocking when nothing else backs the rating up. Derived count: **62 of 97**, against
    the hand audit's "~60" — so the hand figure was close, and is now generated.
  - **`#[ignore]` disqualifies, not merely flags.** Peers are attributed **per file**, so a peer
    named only in files where every test is ignored is reported as unreachable. The aggregate
    count cannot see this: `nats` and `mqtt` both name a real third-party server, and one of
    them runs.

  Server output is byte-identical to the previous version apart from three deliberate
  corrections, which is the check that the split did not change the side that was already right.

  **The run also found two false positives in the existing scan**, both of the kind its own
  comments warn about, and both of which would have put a client on the promotion list:
  `rcgen` and `dirs` are test fixtures rather than peers (a certificate generator and a
  home-directory locator) — `rcgen` made the `tls` client look independently peered when its
  actual peer is a `tokio_rustls::TlsAcceptor` against a `tokio_rustls::TlsConnector`, the
  rustls-agreeing-with-rustls case this file already names; and an inline `quinn::rustls::…`
  used purely as a **re-export** to install a crypto provider made the `kubernetes` client
  report `quinn` as its peer, in a suite that starts no server at all. An inline `a::b::` where
  `b` is itself a dependency now reads as reaching for `b`.

  **The derived client picture, which is the point of the item:**

  | group | count |
  |---|---|
  | Beta | **1** (`nats`) |
  | real peer, evidence runs — promotion candidates | **0** |
  | real peer, unreachable (`#[ignore]`d or skip-gated) | 1 (`mqtt`) |
  | wrong peer: generic HTTP, or the client's own crate | 9 |
  | self-served: the peer is NetGet's own server | 62 |
  | no peer of any kind in its tests | 25 |

  The zero in the second row is the finding. The hand audit reached it in September and this
  reaches it from source, which is the difference between believing it and being able to re-run
  it. What remains un-checkable by any scan is the fourth client condition — that the client
  *acts* on the model's answer, asserted on the wire — and the script says so rather than
  implying it passed.

- [x] **Re-derive the "not promoted" list in `CLAUDE.md`.** *(15 September 2026.)*
  `scripts/beta_evidence_table.py` generates it: per protocol, the binaries and crates its
  tests drive, which of those the server also imports, which are `optional = true`, the
  `#[ignore]` count and any skip-and-pass gate. `--check` fails only on what a script can be
  sure of; a shared peer and an optional dependency are review flags, because `quic`/quinn and
  `webrtc`/webrtc-rs are accepted uses of the server's own crate in the opposite role and no
  static rule separates those from `ssh`/russh. `registry-audit` runs it advisory, with
  `--experimental-with-evidence` for candidates. CLAUDE.md's Beta section now points at it.

  **What it found on its first run, for someone to act on:** `doh` and `dot` are Beta on
  `hickory_proto`, which their servers also use — the circular case, and `dig +https` /
  `dig +tls` are on this machine. `tcp` and `udp` are Beta with no third-party peer at all
  (their tests hand-write the socket work, which CLAUDE.md classes as an independent reading
  of the spec, not an independent implementation). Neither was touched here: demoting a
  protocol needs the test read, not a scan.

## Tier 4 — usability for the model

Robustness against a hostile peer is half of it. The other half is whether the model can drive
the protocol at all — and the mock never tells you, because the mock is scripted.

- [x] **A real-model eval per protocol, tracked as a number.** `./test-e2e.sh --use-ollama`
  exists. Make it a harness: for each protocol, N canonical operator instructions ("serve a
  page saying hello", "answer example.com with 1.2.3.4", "accept user alice, reject everyone
  else"), run against a small local model, drive with the real client, score pass/fail.
  Publish the per-protocol success rate in `PROTOCOL_ROADMAP.md` and re-run nightly. *Why:*
  this is the only measurement of "the model can use it" in the tree, and every prompt-quality
  change is currently unmeasured. It is also the measurement that catches an action
  description the model misreads — the `send_first` "not typically needed" wording, the
  `{{event.xid}}` placeholder — before a user does. *Effort:* L for the harness; S per
  protocol to add instructions.

- [x] **Action and parameter description ratchet.** Every parameter: a description of at
  least one sentence, a `type_hint` from the known set, an `example`; every action: an
  example its executor accepts (exists), a `log_template`. Every event: every field the model
  is told to echo back is a field the event carries. *Why:* the model chooses from the
  description alone. *Effort:* S — extend `executable_examples_test`.

- [x] **Every startup example actually starts.** `startup_examples_validation_test` checks
  shape. A second test spawns each example against the mock and asserts `ServerStatus::Running`
  within 5s, for every protocol that needs no system library. *Why:* ten BLE examples were
  inert for a reason no shape check can see. *Effort:* M.

- [x] **Peer handles on every connection-oriented server.** **13 of 32 TCP servers have one**
  (re-derived 15 Sep; the earlier figure of 32 counted every `peer_support::` mention, including
  removal calls and prose). Missing: `cassandra`, `doh`, `dot`, `etcd`, `kafka`, `llmnr`, `mcp`,
  `mongodb`, `mssql`, `mysql`, `nfs`, `postgresql`, `proxy`, `smb`, `tls`, `tor_relay`,
  `torrent_tracker`, `webrtc`, `webrtc_signaling`. The dashboard greys
  out `[ message ]`/`[ disconnect ]` on the rest and says why. *Why:* the operator cannot reach
  a parked peer without one, and manual-first is the dashboard's whole premise. *Effort:* S
  each — the `whois` diff is ~40 lines.

- [x] **`get_dependencies()` on the 17 device protocols and every system-library one.** One
  override exists. *Why:* the exclusion-with-install-hint mechanism is fully plumbed and does
  nothing; a model offered `nfc` on a machine with no reader gets a runtime error instead of
  never being offered it. *Effort:* S each.

## Tier 5 — test-suite hygiene

The suite is the evidence. Where it lies, the ratings lie.

- [x] **A reason on every `#[ignore]`.** 105 of 248 have none. Each becomes
  `#[ignore = "claims the BLE adapter"]` or is un-ignored. *Verify:* ratchet — bare
  `#[ignore]` fails. *Effort:* S, mechanical.

- [x] **Replace the 279 fixed `sleep(from_secs(N))` in e2e tests with a condition.**
  `wait_for_mocks`, `wait_for_any`, `wait_for_stat`, `wait_for_log`. *Why:* this is where every
  load-flake came from, and `m3ua`'s suite went 6s → 0.46s when its three sleeps became waits.
  *Verify:* ratchet — no `sleep(Duration::from_secs(` in `tests/server` or `tests/client`
  outside a helper. *Effort:* M, mechanical but wide.

- [x] **`verify_mocks` after every `with_mock`.** A test that configures a mock and never
  verifies it asserts nothing about the model. *Verify:* source ratchet. *Effort:* S.

- [x] **The blocking CI test job covers every protocol that needs no system library.** It runs
  6 of 116. `modbus` and `coap` are Beta on evidence CI never executes. Split into a matrix by
  family so each job stays under the runner's memory; keep the six-protocol job as the fast
  gate. Make `registry-audit` blocking once it is green three runs in a row. *Effort:* M.

- [x] **`single-feature` over all 116, not 14.** *(16 September 2026.)* **133 features verified
  standalone** with `cargo check --locked --no-default-features --features <f> --tests`, one at
  a time, every one of them green — so there is no under-declared feature in the tree today.
  The job is split because the check does not fit a PR gate: `single-feature` keeps 24 in
  `SINGLE_FEATURE_CORE` under the 30-minute timeout, and `single-feature-full` runs all 133
  on a manual `workflow_dispatch` (`timeout-minutes: 300`). Both loop rather than matrix,
  so each feature reuses the previous one's dependency graph.

  **Two things the sweep corrected in `CLAUDE.md`'s system-library table**, both in the
  direction of under-counting protocols that *are* checkable: `zookeeper` is listed under
  `protoc` and needs none — `build.rs` compiles protos only under `#[cfg(feature = "etcd")]`,
  the same error the table already records for `kubernetes` — and the `libpcap` row names
  three features when seven carry `dep:pcap` (`lldp`, `cdp`, `stp` and `eapol` as well).

  **Still unverified, and deliberately not in either list:** the 7 `libpcap` features, the 18
  `bluetooth-ble*`, `nfc-client`, `smb-client`, `grpc`, `etcd`, the 7 `usb*` and `can` — 36 in
  all. The rule the job states is that a feature is listed only after somebody built it, and
  for these nobody on a macOS machine can: `ble-peripheral-rust` compiles CoreBluetooth there
  and bluer/D-Bus in CI, so a local green proves nothing about the code the runner would see,
  and `can`/socketcan does not build at all. Installing the libraries in CI would compile some
  of them but would put unverified entries in a blocking gate. They are not unwatched —
  `registry-audit` builds `--all-features` with those libraries — but what it cannot see is a
  *standalone* dependency gap, so that hole is real and stated rather than closed.

- [ ] **Five consecutive full sweeps, any failure investigated.** (This said
  `--test-threads=100`, which is right for one protocol and wrong for the whole tree: at 100 an
  `--all-features` sweep was killed by the OS for memory pressure on a 96 GB machine, because
  ~29 test binaries each link the whole 137-protocol library. Use **32**.) Not
  labelled — investigated. The tuntap/rawip 60s failures turned out to be build contention;
  the doh client failures turned out to be the keychain. Both were "flaky" until someone
  looked. *Effort:* M.

## Tier 6 — documentation truth

- [x] **Every backtick path in a `CLAUDE.md` must exist.** A ratchet over
  `src/**/CLAUDE.md` and `tests/**/CLAUDE.md`: any `` `path/to/file.rs` `` or
  `` `fn_name` `` that names a file must resolve. *Why:* the `remote` test doc described three
  btleplug tests that did not exist; the `openai` server doc said "no LLM prompting" beside a
  table of LLM call budgets. A path check catches the first class outright. *Effort:* S.

- [x] **Test counts in docs are generated or absent.** "22 tests" was wrong in three files.
  Either a script updates them or the docs stop stating them. *Effort:* S.

- [ ] **Per-protocol CLAUDE.md claim audit as a recurring pass, not a one-off.** Programme 2
  verified them once. Schedule it: every protocol's two docs re-read against source every
  quarter, with the drift recorded. *Effort:* L, recurring.

  **A pass ran 16 September 2026 and the drift it found all ran in one direction: the docs
  understated the code.** `imap`'s evidence field described a hand-written prober where
  async-imap had been driving eleven tests for months; `ntp`'s called an asserting suite a
  smoke test; `http`'s said connection tasks are untracked beside three `spawn_server_task`
  call sites; the root file's ratchet table listed baselines of 6, 20 and 18 that were all
  zero. **Understating is the dangerous direction** — it tells the next person to build around
  an absence that is not there.

  One claim ran the other way and is the one that matters: `ldap` cited "the ldapsearch/ldapadd
  command-line tools" as evidence, and nothing asserting drives them. `ldapsearch` appears only
  in `tests/eval/`, the real-model harness, which skips unless `NETGET_USE_OLLAMA=1` and
  reports rather than asserts. **An eval probe is not maturity evidence**, and it is the
  easiest thing in this tree to mistake for one.

  **Do not try to mechanise this by matching names in the prose — it was tried and it does not
  work.** A scan comparing binaries named in each `e2e_testing` string against the peers
  `scripts/beta_evidence_table.py` finds in the tests produces exactly two hits on the current
  tree, and **both are false positives**: `http` names `mysql` while *discussing* the three
  protocols a second client caught, and `ntp` names `sntp` and `ntpdate` while explaining that
  neither can be pointed at an ephemeral port. A field that argues about a client reads
  identically to one that claims it. Shipping a check with a 100% false-positive rate is worse
  than shipping none, because it trains people to edit the baseline rather than the code — the
  same reason the startup-param scan uses the conservative rule.

  What *is* mechanical is already built and now blocking: `beta_evidence_table.py --check`
  reads what the tests drive rather than what the docs say, which is the right direction to
  measure in.

  **One thing about this item that was vague is now a number.** "Re-read every protocol's two
  docs" gives no way to start. Measured 22 September 2026, over `tests/server/*/CLAUDE.md`
  against the `.rs` files sitting beside each:

  | | count |
  |---|---|
  | docs naming **every** one of their test files | 65 |
  | docs naming some but not all | 71 |
  | docs naming **none** of them | **21** → **0** |

  ```bash
  python3 - <<'EOF'
  import pathlib
  for d in sorted(pathlib.Path('tests/server').iterdir()):
      doc = d / 'CLAUDE.md'
      if not d.is_dir() or not doc.exists(): continue
      text = doc.read_text(errors='ignore')
      files = [f.name for f in d.glob('*.rs') if f.name != 'mod.rs']
      if files and not any(f in text or f[:-3] in text for f in files):
          print(d.name, files)
  EOF
  ```

  **The 21 were where to start**, because a doc that names none of its own tests is not stale in
  a detail — it is describing something else. **All 21 are done (22 September 2026), and the
  measure is now zero**: every test directory's `CLAUDE.md` names at least one of its own test
  files. Re-run the snippet above to confirm rather than trusting this line.

  Doing them was not a formatting exercise. Four of `irc`'s five unmentioned files exist because
  of a defect; `ldap`'s unmentioned `result_code_range_test.rs` guards a narrowing cast where
  `256 as u8` encoded LDAP **success**; `git`'s status line read "all 5 tests pass" beside a
  second file with two more. **The files a doc omits skew toward the ones a reader most needs**,
  because a defect-driven test arrives with the pass that found it and that pass edits the
  protocol's doc rather than the tests' one. `tcp` is the mechanism in one sentence:
  `connection_bounds_test.rs` landed with the bounds sweep and nothing pointed at it afterwards.

  **Deliberately not made a ratchet.** The only bar a scan can enforce here is "names at least
  one file", which someone satisfies by naming one and ignoring five — a gate weak enough to
  dilute the ones that do work. The number is the useful artefact; re-run the snippet to see it
  move.

- [x] **Correct `CLAUDE.md` on the two counts this file measured**: command-channel adoption is
  99 clients; the panic hook does not log. *Effort:* S.

## Tier 7 — the classes Programme 2 found, as ratchets

Each of these was found by hand in several protocols. Each can be a shrink-only source scan.

- [x] **Affirmative default on a status field.** `unwrap_or("90")`, `unwrap_or(200)`,
  `unwrap_or(true)`, `unwrap_or(0)` on a field named `status`/`code`/`result`/`sw1`/`sw2`/
  `ok`/`success`/`allowed`. *Why:* NFC and usb-smartcard each had it in two layers. *Effort:* S.

- [x] **Configuration-decides-the-bound.** Any budget or escalation gate that inspects
  `event_handlers` rather than the handler's *result*. *Why:* tuntap. Hard to scan generically;
  scan for the idiom (`handlers.iter().any(` inside a budget path). *Effort:* S.

- [x] **Vendor-default fallback in clients.** Any client wrapping an SDK whose `remote_addr` can
  be empty without an `Err`. *Why:* DynamoDB, then openai, then openapi. *Effort:* S.

- [x] **Recursive decoder without a depth counter.** The crude scan found 973 self-referencing
  functions; refine to functions that both recurse and take `&[u8]`/`&mut Reader`, and require
  a `depth` parameter or a `MAX_*_DEPTH` in scope. *Why:* six stack overflows, and `catch_unwind`
  cannot see a seventh. *Effort:* M.

- [x] **Example drifts from const.** Any `get_startup_examples()` containing a hex literal longer
  than 16 bytes that is not produced by `hex::encode(CONST)`. *Why:* four of five HID profiles.
  *Effort:* S.

---

## Suggested sequencing — Programme 3

**Week 1 — Tier 0.** Seven items, all central, all small or medium. After this, a task panic is
visible, an overflow is a logged death rather than a wrong answer, and a log line cannot be
forged from any protocol. Nothing per-protocol yet.

**Week 2 — the pcap oracle and the fuzz harness.** Build both helpers, adopt the oracle in the 39
Beta suites, land the first ten fuzz targets. This is where the next HID-descriptor-class defect
gets found, and it is found by tshark rather than by an agent reasoning about bytes.

**Weeks 3–4 — the sweeps, as agents in worktrees.** Timeouts, connection caps, `decision=` tags,
sanitizer migration, peer handles, `#[ignore]` reasons, sleep → wait. Each is mechanical per
protocol and each ends in a ratchet, so the batch structure from Programme 2 applies directly:
one agent per family, reporting across boundaries, merged with `--no-ff`.

**Week 5 — evidence.** Hard-fail the 19 skip gates, promote what the 67 installed clients
already prove, install the 33 missing ones, define Stable and earn it for five.

**Ongoing — the real-model eval.** Start it in week 2 with five protocols and grow it; it is the
only number in this repository that says whether the model can drive the thing at all.

---

## Done

Move items here with the date and the commit or PR that verified them.

**22 September 2026 — the full sweep earned its keep: three failures, three real defects.**

172 targets, 3926 passed, 3 failed. None was noise, and each failed in a different way that is
worth keeping:

- **`tcp` dropped the peer this server most often has.** The bounds sweep gave it a 30-second
  deadline on a peer that has sent nothing, argued from generic TCP being client-speaks-first.
  True of a stranger; false of the dashboard's own `[ + tcp client ]`, which connects, says
  nothing and waits for a person to type. The default is now 300s — the window a `manual` rule
  gives a human — and both bounds are declared startup parameters, because the right value is a
  property of who is on the other end.
- **A test waited for the wrong condition.** `coap`'s fail-closed test used `wait_for_any` on
  two `decision=` tags and then asserted **both**, so the first tag satisfied the wait while the
  second was still in flight. `wait_for_all` now exists beside it. The other 45 multi-needle
  sites were checked: all wait on alternative spellings of one fact and assert with `||`, which
  is what the any-variant is for.
- **A ratchet fired on a protocol it had no business flagging** — see the hex-drift entries.

**Two things about diagnosing the `tcp` one generalise.** It looked like flakiness and was not:
the test takes ~38 seconds to drive the MCP surface, so it is *slow* rather than racy, and a
slow test crosses a real deadline every time. **An isolation run and a baseline run were both
needed** — isolation showed it was deterministic, and running it at the commit before the merge
showed it was new. Either alone would have supported the wrong conclusion.


**22 September 2026 — a fuzz target is the one test nothing else builds, and seventeen were in
that position.**

`fuzz/` is deliberately its own workspace, named under the root `[workspace] exclude`, so no
root-level `cargo build`, `test` or `check` reaches it. `.github/workflows/fuzz.yml` is
`workflow_dispatch` only. Between the two, **nothing compiled these targets on any schedule** —
which is how `coap_message.rs` stopped building hours after it was written, when
`CoapMessage::encode` became fallible, and stayed broken for weeks while the Stable bar's
condition 3 was being satisfied by a target that could not run.

The isolation that caused it is correct and stays: a fuzzer is a search, not a check, and
gating a merge on "did 300 seconds turn something up" fails honest PRs at random. What was
missing is the cheap half. `ci.yml`'s blocking `ratchets` job now runs
`cargo check --manifest-path fuzz/Cargo.toml --all-targets` — stable, about two minutes cold,
no nightly, because linking libFuzzer is what needs nightly and `cargo check` does not link.

Verified both ways: all seventeen compile today, and one call with a changed signature — the
coap class exactly — fails the check.

**The general shape is worth more than the fix.** Ask of any artefact cited as evidence: *what
builds it, and when?* If the answer is "a workflow someone dispatches" or "a developer locally",
it is not being built, and its evidence is a claim about the past.


**16–22 September 2026 — `coap` and `dns` are Stable. No protocol has ever held that rating on
this bar before.**

All three protocols that held it historically lost it, each because nobody had written down what
it required. The bar is six conditions; these two were taken through all six, and the two that
were left — a test per declared bound, and both `CLAUDE.md` files re-verified against source —
are the ones that found bugs:

- **`coap` declared `max_inbound_bytes` and enforced nothing.** A declared bound with no test is
  a comment, which is exactly what condition 4 exists to catch.
- **`dns` fell open** when the model answered with something the server could not send.
- **The `coap` fuzz target had not compiled since `encode` became fallible**, so condition 3 —
  "a fuzz target exists and has run clean" — was satisfied on paper by a target that could not
  run at all. Worth remembering as its own class: a fuzz target is the one kind of test nothing
  else in CI exercises, so it rots silently.

Each bound was verified by removing it and watching the test fail.

**And the bounds sweep is done.** Four agent slices took the TCP servers from 52 of 92 with no
read deadline to **10**, and from 2 with a connection cap to **67**. The remainder are on the
ratchet's shrink-only baselines with reasons rather than silence.


**16 September 2026 — circular-evidence audit across all 50 Beta ratings.**

Method: for each Beta protocol, diff the external crates imported by `src/server/<p>/*.rs`
against those imported by `tests/server/<p>/*.rs`. An overlap means the test's peer may be the
crate the server frames with — the `ssh`/russh case, where a rating looked earned because nobody
checked what the test drove as opposed to what the server linked.

Five overlaps, and **four are already disclosed in the protocol's own metadata**, which is the
outcome the bar was written for:

| protocol | shared crate | verdict |
|---|---|---|
| `dns` | hickory-proto | rating rests on `dig` (BIND), which is independent |
| `doh` | hickory-proto | `e2e_testing` already says the DNS half is decoded with the server's own codec and is inherited from `dns`, which dig validates |
| `dot` | hickory-proto | same, and it names what would close it: `kdig +tls` from knot-dnsutils |
| `grpc` | prost, prost-reflect | rating now rests on grpcurl (grpc-go); prost builds the request message only |
| `webrtc` | webrtc-rs, tokio-tungstenite | the quinn precedent, already recorded in the root CLAUDE.md: the peer is the same library in the opposite role completing a real handshake |

**One bad claim, and it was in the opposite direction from circularity.** `ldap`'s `e2e_testing`
named "the ldapsearch/ldapadd command-line tools" as evidence. Nothing asserting drives them:
`ldapsearch` appears only in `tests/eval/`, the real-model harness, which **skips unless
`NETGET_USE_OLLAMA=1` and reports rather than asserts** — its own header says it must never gate
a PR. A citation a reader cannot find, backed by a harness that passes by skipping. Corrected;
the rating stands on `ldap3`, which is genuinely independent of `ldap3_proto` despite the name.

**The eval suite drives `redis-cli`, `psql`, `mysql`, `ipptool`, `whois` and `ftp` too.** Only
`whois` is also cited by a maturity claim, and that one is sound — a real `whois` binary runs in
its own e2e test. **An eval probe is a useful signal and is not maturity evidence**; it is the
easiest thing in this tree to mistake for one.

`kdig` is now installed, so `dot`'s named gap is one test away.


**16 September 2026 — the last four dead startup parameters, and a credential in the prompt.**

`startup_param_drift_test`'s baseline is empty. Each of the four was a knob the dashboard
offered, the protocol's own examples set, and nothing read:

- **`bitcoin` `rpc_user` / `rpc_password`.** bitcoind's RPC is auth-mandatory — every
  unauthenticated request gets `401` — so authenticated Bitcoin Core RPC could not work at all
  through this client. The documented alternative was broken too, and less visibly: the client's
  own comment says it accepts `http://user:pass@host:port`, and **reqwest does not derive Basic
  auth from URL userinfo**, so the one form operators were told to use also 401'd with nothing
  saying why. One fix covers both — take the credential out of the URL, send it as a header.
- **`ipp` `printer_path`.** IPP addresses a queue, not a host.
- **`isis` `interface`.** The client passed `remote_addr` as the capture device.

**The part worth carrying forward is what the bitcoin fix exposed on the way past.** The
userinfo URL was stored in `rpc_url`, which the dashboard renders on the client's facts line;
echoed to the status stream on connect; and put into the `bitcoin_client_connected` event, which
is handed to **the model**. A password in the prompt is not a display bug, and nothing about the
dead-parameter task would have found it — it surfaced only because making the credential *work*
meant following where it goes. **When you make a secret functional, trace every place it lands.**

Verified by removing the `basic_auth` call and watching both wire tests fail with their own
messages.


**16 September 2026 — the gRPC trailers class, found by a second client.**

Two servers, `etcd` and `grpc`, wrote `grpc-status` into the **initial** HEADERS and then sent a
DATA frame, so the stream ended with no trailing HEADERS at all. gRPC requires the status of any
reply carrying a message to arrive in trailers. tonic tolerates the header placement; grpc-go
refuses outright, so neither `etcdctl` nor `grpcurl` could complete a single successful call —
not a corner of the API, the first Put and every unary RPC.

Both now build the success reply as a two-frame body (the length-prefixed message, then
`Frame::trailers`) boxed into a `BoxBody`, because `Full<Bytes>` cannot emit trailers at all.
Both keep the Trailers-Only shape for errors, where the status legitimately rides in the initial
headers. `etcd` returned to Beta and `grpc` reached it, each on two independent clients.

Three things this cost and is worth not paying twice:

- **The failure path was accidentally correct.** An error has an empty body, which makes it
  Trailers-Only by construction — so every `llm_failure` and `unanswered_request` test passed,
  and those were the ones doing the asserting. Only the success path was broken.
- **A test held the defect in place by asserting it.** `test_grpc_unary_rpc_basic` checked
  `grpc-status: 0` on the *initial* headers. It drives reqwest, which exposes no trailers API,
  so it could not have checked the right place even if someone had wanted to. It now asserts
  that header is **absent**.
- **"No second client available to test against" was a task, not a conclusion.** Both protocols'
  CLAUDE.md files said grpc-go "may not" accept this and that nobody should touch it without a
  Go client. Installing one took a minute.

Each fix was verified by removing the trailers frame and watching the real client fail with its
own error message, which is the same technique the AMQP field-table depth bound used.


**15 September 2026 — Tier 0, first four.**

- **Logging panic hook** (`src/panic_log.rs`, `tests/panic_is_logged_test.rs`). Installed from
  `init_logging`, which every entry point calls, and chains to whatever hook it replaced so the
  dashboard's terminal-restore hook still runs. `payload_of` handles the `String` arm as well as
  `&'static str`, because `panic!("{}", x)` produces a `String` — a hook that downcasts only to
  `&str` reports every *formatted* panic, which is most real ones, as unreadable.
- **`overflow-checks = true` in release.** Cargo's default is the opposite of what a server
  wants.
- **Control-character stripping in `log_template.rs`** (`tests/log_template_injection_test.rs`).
  Applied at the substitution point, so every placeholder form — plain, nested, `json()`,
  `hex()`, `preview()` — is covered by one change.
- **`AppState::spawn_server_task` / `spawn_client_task`**, with TCP converted as the reference
  (`tests/stop_server_stops_connections_test.rs`). The registry was already correct; protocols
  simply were not calling it for connections.

  **The new test caught a defect in that conversion before it landed**, and the shape is worth
  keeping. Two of three converted sites ended `});` rather than `}).await`, which *constructs*
  the future and never polls it — so the TCP reader task would never have run and every TCP
  server would have accepted connections and then ignored them. It compiled, because an
  unawaited future is a warning rather than an error, and the existing suite stayed green
  because those tests do not depend on the accept loop spawning the reader. Only an assertion
  from the **peer's** side distinguishes a live connection from an aborted one.

  **The sweep landed the same day.** 145 sites converted across 113 server protocols and 2 clients — every bare
  `tokio::spawn` *statement* in `src/{server,client}/*/mod.rs` that had a `server_id` or
  `client_id` to register against. The flagging rule was measured before it became a gate: it
  named 136 sites, 135 of which were the defect, so the false-positive rate is 0.7% and the
  baseline in `tests/detached_task_drift_test.rs` has exactly one entry (SSH's
  `Option<ServerId>`, whose `None` arm has no server to own the task).

  `tests/stop_server_stops_connections_test.rs` now covers `telnet`, `whois` and `http` beside
  TCP — a reader netget wrote, a session with its own read deadline, and hyper's
  `serve_connection`, which is the shape ~30 protocols share.

  **Deliberately still detached, each with a reason** (all recorded in the commit and in
  `CLAUDE.md`): the per-connection **writer** tasks are `.await`ed on the exit path, so they
  need a `JoinHandle` — and they already end when the registered reader is aborted and drops
  their channel; `bluetooth_ble`'s radio dispatcher is process-wide and must outlive any one
  server, the only task in either tree detached by design; and the USB/IP session tasks plus
  `postgresql`'s pgwire task are awaited inside a `select!`, so registering them means
  restructuring a shutdown handshake rather than wrapping a spawn. Those last are children of a
  registered connection task, and **aborting a parent does not abort its children**, so that
  gap is open rather than closed.

- **15 Sep 2026 — Tier 1, "hard-fail the skip-when-missing gates".** Six real gates converted
  (`websocket`/websocat, `memcached`/libmemcached, `pypi`/pip, `grpc` client/protoc, plus the
  two `#[ignore]`d-for-"run manually" tests, `rtsp`/ffprobe and `hls`/curl). `registry-audit`
  installs the clients and runs the real-client suites. The ones left are privilege, device,
  platform and feature gates, not binary-availability gates.
- **15 Sep 2026 — Tier 3, "Beta for what already had the evidence".** `websocket`, `memcached`,
  `rtsp`, `oci_registry`, `maven`, `ssh`. Every `e2e_testing` field now names its client, says
  the test is neither ignored nor skip-gated, and says what is still unproven.
- **15 Sep 2026 — Tier 3, "re-derive the not-promoted list".** `scripts/beta_evidence_table.py`.

**15 September 2026 — Tier 1, the two oracles.**

- **The pcap oracle** (`tests/helpers/pcap_oracle.rs`, `tests/pcap_oracle_test.rs`), adopted in
  22 protocols across 25 files, twelve of them Beta. Two failure mechanisms, because they catch
  different things: Expert Info at Warn or above, and the requested dissector being **absent
  from `frame.protocols`** for a direction that carried bytes — the second has no expert info
  behind it at all, which is why an 802.3 frame carrying an EtherType where the length belongs
  dissects as `eth:ethertype:data` in silence. That is the CDP defect, and silence is why a
  human had to find it.

  It found a malformed IMAP literal no existing assertion could see: `{50}` declared for a
  46-octet body, which desynchronises a conforming client permanently. Every assertion in that
  file is a `contains()` on a trimmed line, so all of them passed.

  **Every other protocol's frames were accepted** — the first independent confirmation that
  Programme 2's link-layer fixes hold.

- **17 fuzz targets** (`fuzz/`), all 60s clean at ~1.9M executions, `src/` byte-identical.

  **The finding worth carrying: a naive fuzzing setup would have run green forever.**
  Coverage-guided fuzzing gives *no gradient toward nesting* — a value nested 10,000 deep runs
  the same basic blocks as one nested 3 deep, so libFuzzer discards it. Measured with the
  bencode guard removed: seeds alone found nothing in 300s and 15.5M executions; adding one
  32 KiB depth bomb found the SIGSEGV in **2.8 seconds**. The corpus is the difference between
  a harness that finds the stack-overflow class and one that only looks like it does.

  Also: ASan deadlocks before `main` on macOS 27 and presents as a *slow* fuzzer, not a broken
  one — no banner, no corpus growth, sailing past `-max_total_time`. Use `-s none` locally.

**15 September 2026 — the ratchets caught three fail-opens on merged code.** `sqs` was the
DynamoDB defect verbatim in the next AWS client (a client pointed at localhost issuing real
operations against real AWS, signed with ambient credentials); `spark` defaulted an absent
status to 200 *and* narrowed it unchecked; `zookeeper` defaulted `error_code` to 0, which is
`Ok`. All fixed rather than baselined. Each appeared as "new" at one line and "gone" at another
because merges had shifted the file — the shrink-only halves firing in both directions at once.

**15 September 2026 — the real-model eval, and the defect it found instead.**

`tests/eval/` — 16 protocols, 46 cases, each a plain-English operator instruction driven by a
real third-party client, scored as a **pass rate over N runs** because NetGet passes no
temperature or seed to Ollama. One rule: an instruction may never name an action, a parameter
or an event, or the descriptions stop being what is under test. A deliberately *small* model,
because a strong one papers over a bad description by guessing what was meant.

**Result: 7 of 54 passed; 50 of 54 would have passed with a lenient parse.** 43 of the 47
misses were one upstream defect — `ActionResponse::from_str` required the **whole** string to
be a single JSON value, and small models append an explanation after the JSON constantly. The
model named the right action with the right parameters every time and NetGet discarded the
reply as `Invalid JSON`, which to the protocol is indistinguishable from a backend failure.

**No test in the suite could have found this.** Every mock returns exactly the JSON its test
author wrote, so the mock and the parser agree by construction. The defect lives in the gap
between a mock and a model — which is the whole argument for this harness existing. Fixed;
`tests/action_response_trailing_prose_test.rs` pins it, including the three guards that stop
the widening from swallowing genuine failures.

The near-miss is worth keeping: **the fenced form already worked**, because the fence stripper
cuts at the closing backticks. The same model producing the same answer succeeded or failed on
whether it used a code fence, which is why this read as a formatting quirk for so long.

**The second finding is the class the harness was actually built for.** Told to serve a gopher
menu whose first item is labelled "Welcome to NetGet", the model emitted all four items of
`send_gopher_menu`'s **declared example** and none of the requested label. That is the
`{{event.xid}}` defect wearing better clothes: a placeholder looks wrong on the wire and
someone eventually notices, while plausible prose does not, and nothing downstream can tell a
copied example from an intended answer. The classifier now names it automatically.

**Follow-up this implies:** an action's `example` is rendered into the model's tool list, so it
should be *obviously* a placeholder (`example.com`) rather than plausible content a model might
reasonably ship. That is a sweep, not a ratchet — worth measuring once the parser fix lets the
eval see past it.

**15 September 2026 — the second wave.**

- **The four fail-opens** (`rtp`, `npm`/`pypi`, `imap`, `usb`). rtp's budget bypass was the
  tuntap defect unrepaired, and is **measured**: five datagrams under `llm_max_per_minute: 0`
  produced **5** model calls on the old gate and **0** on the repaired one, with a control at
  ceiling 30 giving 5 either way. Moving the dispatch also had to move `pipe::dispatch_pipes`
  and the access-log write, or a handler-answered datagram would have silently stopped firing
  pipes and vanished from `list_access_logs`.
- **The ten codec counterexamples**, all fixed by refusing rather than truncating. Fixing
  m3ua's encode bound exposed a third defect: `MAX_USER_DATA_LEN` forgot a body is a whole
  number of 4-octet words, so a payload at exactly the documented limit encoded one byte past
  the ceiling — the "padding is not in the length" trap, met by the code that documents it.
- **145 spawn sites registered** across 113 servers and 2 clients. Every site proved to end
  `.await` by building at `--all-features` with `-D unused_must_use`, because that is the lint
  that catches the mistake I made converting TCP.
- **16 sanitizer sites migrated**, and the re-derivation corrected this file: of 25 grep hits
  only 12 were filters, and four filters the grep never saw matched `'\t' | '\r' | '\n'`
  directly instead of calling `is_control`.
- **354 startup examples across 118 protocols all reach `Running`.** No example was
  unstartable; both failures were the test's own bugs.
- **The whole-tree ratchets are a blocking CI job.** They read source, so they cover all ~137
  servers and ~98 clients at any feature set — unlike `registry-audit`, which needs
  `--all-features` and five system libraries and is `continue-on-error`, so a green PR never
  meant those audits passed.

**Three findings landed on this programme's own work, which is the useful part:**

1. `f397328e` (mine) added `ProtocolMetadataV2::failure_mode` and missed the one site that
   builds the struct by **literal** rather than through the builder, so `HEAD` did not compile
   at `--all-features`. I had only built narrow feature sets. Two independent parties hit it.
2. `send_first`'s ratchet had the **coverage-guard defect it was written to replace** — it
   walked the registry, so a narrow feature set made it red for unrelated reasons.
3. That ratchet then caught **its own comment**: prose quoting `let _send_first = …` was
   reported as the defect it documents. Third time this repository has hit the
   matching-prose-about-the-pattern false positive.

**16 September 2026 — the second wave, and the defects it surfaced.**

Six agents closed the remaining tracker items; four more closed what those six found. The
pattern worth noting is that **most of the value came from the second set** — the defects were
surfaced by doing the work, not by planning it.

- **78 orphaned `netget` processes** were found alive, accumulated over ten hours, holding ports
  and quietly oversubscribing the machine *while load-sensitive test failures were being
  investigated on it*. The harness now ties each child to its parent's lifetime with a pipe held
  `FD_CLOEXEC` and a shell blocked on `read` — macOS has no `PR_SET_PDEATHSIG`, and every obvious
  substitute fails because **the thing that would do the killing is the process that died**.

  Why they accumulated *slowly*: a chatty netget usually died within a second because it
  **panicked writing a status line to a stdout pipe with no reader**, while a quiet one never
  wrote and never learned. Which orphans persisted was a lottery. That panic is now fixed — it
  killed the servers doing work and spared the ones merely holding a port.

- **`helpers/common.rs::cleanup_stray_processes` was `pkill -f "target/.*/netget"`** — the exact
  command `CLAUDE.md` forbids, matching the maintainer's own `--mcp` session. **It had no
  callers, which is the only reason it never fired.**

- **A bare TCP connect to a USB/IP server cost two model calls.** Attach fired on `accept()` and
  detach on close, so three silent connects plus an `OP_REQ_DEVLIST` cost seven. USB/IP
  authenticates nothing. Now zero: the attach event hangs off the first *admitted*
  `OP_REQ_IMPORT`, and deliberately not off `OP_REQ_DEVLIST`, which is what a scanner sends.

- **`ipp` refused correctly and the peer never saw it.** Closing a socket with unread data sends
  `RST`, which discards the response bytes already written — so all the care IPP takes to
  express a refusal twice was spent on a message nobody received. It now drains before closing
  (nginx's `lingering_close`). The test had to use a raw socket rather than `reqwest`: a hyper
  client polls the read side while writing and can parse the 413 before the RST lands, which was
  5 failures in 8 runs versus 5 in 5.

- **The `reqwest` build cost was mis-diagnosed in `CLAUDE.md` for a long time.** Measured: not
  the keychain, not the root store, not TLS at all — it is the **system-proxy probe** through
  configd, 657 ms at 100 concurrent processes, 0.090 ms with `.no_proxy()`. And it was a
  *correctness* bug too: with a proxy configured, loopback requests went to the proxy.

  The agent sent to add a client cache **measured and refused it**, which was the right call.

**Three items of my own measurement were wrong**, all the same shape — counting a token rather
than the thing:

| I said | Actually | Because |
|---|---|---|
| 19 TCP servers lack peer handles | 52 of 92 | anchored on the literal `TcpListener`; 62 servers bind through a helper |
| 81 protocols lack a size bound | 59, of which ~10 need one | the pattern missed `MAX_COMMAND_LINE`, `BGP_MAX_MESSAGE_LEN`, … |
| 5 orphaned netget processes | 78 | looked in one target dir |

And one process failure worth keeping: **a "final sweep" I reported as running had died with
`ld: write() failed, errno=28` and exited 0, having run zero tests.** Six concurrent
`--all-features` target dirs is ~150 GiB and I started a seventh. `CLAUDE.md` warns about
exactly this; the guard is to parse for a non-zero *target count*, never to grep only for
failures.
