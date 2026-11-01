# Fuzzing NetGet's pre-authentication decoders

Every one of NetGet's eight known stack overflows — AMQP field tables, NATS blank lines,
STOMP framing, SNMP BER, xmlrpc, bencode, RESP arrays, BSON documents — was found by a
human reasoning about one decoder at a time. This directory is the machine that finds the
next one.

**Why a fuzzer and not a test.** A Rust stack overflow is a `SIGSEGV` against the guard
page, not a panic. `catch_unwind` cannot see it, `tokio::spawn` cannot contain it, and
the whole NetGet process dies. No other test in this repository can observe that class:
a `#[test]` that overflows takes the test binary with it and reports nothing useful.
libFuzzer runs each input in a process it is willing to lose, writes the input that
killed it to a file, and keeps going.

Every decoder targeted here is reachable **before any authentication**, most of them on
the first packet of a connection or on a single unauthenticated UDP datagram.

## Running one locally

Needs a nightly toolchain (libFuzzer's sanitizer support ships only there) and
`cargo install cargo-fuzz`.

```bash
cd fuzz
cargo +nightly fuzz list                              # the targets
cargo +nightly fuzz run -s none bencode_structure     # until you stop it or it crashes
```

### On macOS, `-s none` is required

**AddressSanitizer deadlocks before `main` on macOS 26/27 (Tahoe).** cargo-fuzz's default
is `-s address`, and on this OS every target hangs at startup, forever, having executed
zero inputs. The stack is ASan re-entering its own initialiser:

```
__asan::AsanInitInternal → InitializeShadowMemory → MemoryRangeIsAvailable
  → MemoryMappingLayout::Next → get_dyld_hdr → dyld_shared_cache_iterate_text_swift
  → _Block_copy → malloc → __sanitizer_mz_malloc → __asan::AsanInitFromRtl
  → StaticSpinMutex::LockSlow → sched_yield (forever)
```

ASan's init walks the dyld shared cache, dyld allocates, the allocation is routed back
into ASan, and ASan's non-recursive init spinlock deadlocks against itself.

This is worth recognising because **it looks exactly like a slow fuzzer, not a broken
one**: no banner (libFuzzer block-buffers when redirected), no corpus growth, no crash
artefact, and ~25% CPU because `sched_yield` is a syscall. It cost a full debugging pass
here. The tells are a run that sails past `-max_total_time` and a corpus directory that
never gains a file.

`-s none` disables ASan and the targets run normally (~1,500 exec/s). What that costs is
heap-overflow and use-after-free detection — which these targets barely need, since every
decoder driven here is safe Rust. **Stack-overflow detection is unaffected**, because a
Rust stack overflow is a `SIGSEGV` against the guard page that libFuzzer's own signal
handler catches with or without ASan. That is the class this harness exists for, so the
macOS workaround loses nothing that matters.

Linux is unaffected; the dispatched CI job runs on `ubuntu-22.04` with ASan enabled.

Bound it the way CI does — and note `-timeout`, which is not optional in practice:

```bash
cargo +nightly fuzz run -s none bencode_structure -- \
    -max_total_time=60 -timeout=25 -rss_limit_mb=2048
```

**`-max_total_time` alone does not bound the run.** libFuzzer checks the wall clock
only *between* executions, so a single input that never returns runs forever and looks
exactly like a slow-but-healthy search. `-timeout=25` turns that into a reported crash
with the offending input saved. If a run overruns its budget with no output, suspect a
hang rather than a slow machine.

**`crc-fast` fails to link on macOS** (`Undefined symbols … ___sanitizer_cov_8bit_counters_init`):
it builds a `cdylib`, and an instrumented dylib cannot see libFuzzer's symbols at link time.
Let the dylib resolve them at load time, and make sure the toolchain on `PATH` is the one you
asked for — `rustup run` does not put its `cargo` ahead of Homebrew's, and a mixed toolchain
fails the same link with a different error:

```bash
cd fuzz && PATH=~/.rustup/toolchains/nightly-aarch64-apple-darwin/bin:$PATH \
  RUSTC_WRAPPER= RUSTFLAGS='-Clink-arg=-Wl,-undefined,dynamic_lookup' \
  cargo fuzz build -s none <target>
```

`fuzz/Cargo.lock` is not committed, so it drifts from the root one; copy the root
`Cargo.lock` over it first to fuzz the versions NetGet actually ships (a newer `libc`
broke `nix` 0.8 and a newer `crc-fast` changed its crate type).

`cargo fuzz` prints nothing until it exits when you redirect stdout to a file, because
libFuzzer block-buffers. Watch `corpus/<target>/` growing instead, or leave it on a tty.

## When it crashes

A crash is a **live defect**, not a flake. libFuzzer writes the exact input to
`fuzz/artifacts/<target>/crash-<sha1>`, and that file is the valuable output.

```bash
# 1. Confirm it reproduces.
cargo +nightly fuzz run -s none bencode_structure artifacts/bencode_structure/crash-abc123

# 2. Shrink it to the smallest input that still crashes. Do this before reading it —
#    a 4 KB crash is unreadable and its 9-byte minimisation usually names the bug.
cargo +nightly fuzz tmin -s none bencode_structure artifacts/bencode_structure/crash-abc123

# 3. Look at what it actually is.
xxd artifacts/bencode_structure/minimized-from-abc123
```

Then, in order:

1. **Write the minimised input into a test in `tests/`** — per `CLAUDE.md`, tests live
   there and never in `src/`. The existing regression tests for this class are
   `tests/server/torrent_dht/bencode_depth_guard_test.rs` and
   `tests/client/xmlrpc/response_guard_test.rs`; copy their shape.
2. **Fix the decoder.** For unbounded recursion the fix is a depth counter, never a
   bigger stack — `src/utils/bencode.rs` is the reference: it walks the bytes
   iteratively, allocates nothing, and refuses anything past `MAX_BENCODE_DEPTH`
   before the real decoder is handed a single byte.
3. **Verify the bound by removing it.** This repository's convention, and it is worth
   keeping: delete the guard, re-run the fuzzer, and confirm it dies. A bound nobody has
   watched fail is a bound nobody knows is load-bearing. The AMQP field-table limit, the
   xmlrpc depth limit and this harness itself were all checked that way.
4. **Commit the crashing input into `corpus/<target>/`** so the case is never lost.

If the crash is inside a third-party crate (`hickory-proto`, `rasn`, `serde_bencode`,
`netgauze`), the finding still belongs to NetGet: the exposure is ours. Report it
upstream *and* add a structural screen on our side of the socket, which is what
`src/server/nfs/guard.rs` does for `nfsserve` and what `utils::bencode` does for
`serde_bencode`. Waiting for an upstream release is not a mitigation.

## The targets

Twenty-two, chosen by exposure. "Guard pair" marks the ones that drive a NetGet guard and
then hand whatever it accepted to the decoder it guards — those assert the contract that
matters (*anything the guard accepts, the decoder survives*) rather than merely that the
guard does not panic, which is the easy half.

| Target | Decoder | Reached by |
|---|---|---|
| `bencode_structure` | `utils::bencode` + `serde_bencode` — **guard pair** | one UDP datagram (DHT, tracker, peer) |
| `snmp_ber` | `snmp::check_ber_structure` + `rasn` — **guard pair** | one UDP datagram |
| `amqp_field_table` | `amqp::codec` field tables, properties, string readers | connection-open, pre-auth |
| `nats_frame` | `nats::parse_frame`, blank-line skip, header block | first bytes of a TCP connection |
| `stomp_frame` | `stomp::frame::parse_frame`, header escaping | first bytes of a TCP connection |
| `radius_packet` | `radius::packet` attribute walk, `attribute_value_json` | one UDP datagram |
| `dns_message` | `utils::dns_screen` + `hickory_proto::op::Message` — **guard pair** (the screen bounds compression-pointer chains, which hickory 0.24 follows recursively) | one UDP datagram; `dns`/`dot`/`doh`/`doq`/`llmnr` |
| `cassandra_envelope` | the read loop's length bound + `cassandra::parse_request_frame` + `Envelope::from_buffer` — **guard pair** | the first CQL frame, before STARTUP |
| `mysql_session` | `mysql::packet_limit::PacketLimitReader` + `opensrv_mysql`'s whole protocol loop (reassembly, handshake, commands) — **guard pair** | the handshake response, pre-auth |
| `lldp_frame` | `lldp::codec` 802.1AB TLV walker | link-local broadcast, no handshake |
| `cdp_frame` | `cdp::codec` TLV walker + checksum | link-local broadcast, no handshake |
| `modbus_adu` | `modbus::codec` MBAP framing + PDU requests, and the encoders answering them (framing round-trip; every accepted read answerable) | first bytes of a TCP connection |
| `coap_message` | `coap::codec` option walker, encode round-trip | one UDP datagram |
| `hsrp_message` | `hsrp::codec` v1/v2 dispatch and TLV walk | one UDP datagram |
| `m3ua_message` | `m3ua::codec` header + parameter TLV walk | first bytes of a TCP connection |
| `bgp_message` | `bgp::wire::parse_header` + `netgauze` — **guard pair** | OPEN exchange, pre-session |
| `ndef_message` | `client::nfc::ndef` decode/encode round-trip | bytes read off a tag |
| `nfc_apdu` | `nfc::apdu` ISO 7816-4 length encodings | first APDU on the socket |
| `nfs_record_guard` | `nfs::guard::RecordScreen` over a *sequence* of markers | RPC record layer, pre-auth |
| `resp_frame` | `utils::resp` + `redis_protocol::resp2::decode` — **guard pair**, and differential: the guard's `Incomplete`/`Malformed` must match the decoder's | first bytes of a Redis connection |
| `bson_document` | `utils::bson_depth` + `bson::Document::from_reader` — **guard pair**, and differential: on inputs too short to be deep, the guard never refuses what `bson` accepts | first `OP_MSG` of a MongoDB connection |
| `ldap_filter` | `ldap::ldap_message_len` → `decode_ldap_message` → `parse_search_request`, whose `render_filter` is the only recursive code in an LDAP request (`MAX_FILTER_DEPTH`) | a SearchRequest, which needs no bind |
| `svn_tuple` | `svn::wire::ItemReader::read_item` (iterative) → `svn::command_event_data`, which walks the `Item` recursively (`MAX_TUPLE_DEPTH`) | the first tuple on an ra_svn connection |
| `xmlrpc_value` | `xmlrpc::parse_method_call` (iterative) → `actions::create_method_call_event`, which walks the `XmlRpcValue` recursively (`MAX_VALUE_DEPTH`) | the first POST body |
| `packstream_message` | `bolt::packstream::decode` (recursive, `MAX_PACKSTREAM_DEPTH`, declared lengths checked before allocation) and `Dechunker` (1 MiB cap), then `parse_request` and the event's JSON conversion; `encode ∘ decode` must be idempotent | HELLO, before any login |
| `smb2_request` | `smb::wire::next_in_chain` over a whole compound frame, then every `parse_*` request parser on every request in it (not only its own command's); every reply header must round-trip MessageId/TreeId/SessionId | first frame of a TCP connection; NEGOTIATE and SESSION_SETUP are pre-auth |
| `ntlmssp_token` | `smb::auth` — the NTLMSSP scan through a SPNEGO wrapper, `parse_authenticate`, and the CHALLENGE / `negTokenResp` the server builds back (its DER lengths must be exact) | SESSION_SETUP security buffer, pre-auth |

Every target is deterministic: no I/O, no sockets, no clock, no LLM. Several assert
determinism explicitly by decoding twice and comparing, because a decoder that disagrees
with itself makes every other assertion here meaningless.

## The corpus

`corpus/<target>/` holds hand-written seeds, regenerated by `seed_corpus.py` — which is
committed precisely so 116 binary blobs have a provenance. Edit the script, not the blobs:

```bash
python3 fuzz/seed_corpus.py .      # from the repository root
```

Ten targets carry **depth bombs** — `bencode_structure`, `snmp_ber`,
`amqp_field_table`, `resp_frame`, `bson_document`, `ldap_filter`, `svn_tuple`,
`xmlrpc_value`, `packstream_message`, `ntlmssp_token` — and they are the reason this harness can find anything. Coverage-guided fuzzing gives **no gradient toward nesting depth**: a value
nested 10,000 deep runs exactly the same basic blocks as one nested 3 deep, so libFuzzer
scores it as uninteresting and discards it. It will not grow one by itself.

That is measured, not assumed. With `utils::bencode`'s guard removed:

| corpus | result |
|---|---|
| seeds only, no depth bomb | **no crash** in 300s / 15.5M execs |
| seeds only, `-max_len=16384` | **no crash** in 300s / 4.7M execs |
| with a 32 KiB depth bomb | **SIGSEGV in 2.8s** |

All eight of this repository's known stack overflows are in that class, so a corpus with no
depth in it cannot find the next one. With the guards in place the bombs are refused in
microseconds; they cost the running fuzzer nothing and exist for the day a guard regresses.

They also set libFuzzer's `-max_len`, which it infers from the largest corpus entry. Under
the 4096-byte default the overflow is not merely hard to find, it is **unreachable** — the
depth needed to exhaust an 8 MiB main-thread stack is larger than the longest input
libFuzzer will generate.

**And a bomb must stay under 1 MiB, because that is where the inference stops.** libFuzzer
caps the `-max_len` it infers at 1 MiB and *truncates* larger seeds without saying so. The
first `xmlrpc_value` bomb was 40,000 levels, 1.7 MB: it arrived as malformed XML, never
reached the recursion, and with the guard removed the target ran 60 seconds "clean". At
20,000 levels (860 KB) the same build dies at once. Check a new bomb against the guardless
build, not just the guarded one.

Where a decoder does **not** nest there is nothing for a depth bomb to reach, and the corpus
says why instead: `modbus_adu` (a flat header and PDU) and `bgp_message` (no netgauze path
attribute contains attributes; ATTR_SET is unimplemented) seed every declared length at its
maximum instead; `ndef_message`'s decoder returns a nested message as hex rather than
descending into it; and `nats_frame` and `stomp_frame` are flat, but each once *recursed per
blank line*, so each carries a `blank_line_bomb` — 32 Ki blank lines ahead of a frame —
against that coming back. `ntlmssp_token`'s bomb (20 000 nested DER SEQUENCEs around an
NTLMSSP token) reaches no recursion today — the server scans SPNEGO for the NTLMSSP signature
instead of walking the DER — and is there for the day a DER walker replaces the scan.
`smb2_request` is flat too: a compound chain is linear, so its long-axis seed is a chain of
14 000 linked ECHOs.

## Proving the harness works

A fuzzing setup nobody has seen catch anything is not known to work. To re-check it,
remove a guard and confirm the fuzzer finds what the guard was there for:

```bash
# In src/utils/bencode.rs, make check_bencode_structure_with_limit return Ok(()) at the top.
cd fuzz && cargo +nightly fuzz run -s none bencode_structure -- -max_total_time=120
# Then restore the guard.
```

Done on 15 September 2026, it died in **2.8 seconds** with
`Fuzz target exited with signal: 11 (SIGSEGV)` — the guard-page stack overflow, which is
exactly the class no other test in this repository can observe. Restoring the guard makes
the same target run 60s clean at ~196,000 execs with the depth bomb still in its corpus.

`resp_frame` was checked the same way on 26 September 2026, by calling `decode` ahead of the
guard: the seed corpus alone killed it with `SIGSEGV` while loading `depth_bomb`. Restored,
it ran 60s clean at ~205,000 runs with the differential assertions holding throughout.
`bson_document` the same day, the same way: `bson::Document::from_reader` called ahead of the
guard died with `SIGSEGV` on the seed corpus; restored, 60s clean at ~153,000 runs.

`ldap_filter`, `svn_tuple` and `xmlrpc_value` on the same day, by disabling each depth check —
`render_filter`'s `depth >= MAX_FILTER_DEPTH`, `read_item`'s `stack.len() >= MAX_TUPLE_DEPTH`,
`parse_method_call`'s `>= MAX_VALUE_DEPTH`: all three died with `SIGSEGV` while loading their
seed corpus. Restored, 60s clean at ~58,000, ~90,000 and ~138,000 runs. The last two are
worth understanding, because both parsers are **iterative** and their own doc comments said
deep nesting "cannot overflow the stack". The parsers cannot; what they build can. `Item`
and `XmlRpcValue` are recursive types, and `Display`, `to_json`, the JSON conversion for the
model's event and `Drop` all walk them recursively — so the depth bound is what protects
everything downstream of the parser, and the targets drive that code, not just the parser.

`packstream_message` (Bolt) the same way on 26 September 2026: with the three
`depth > MAX_PACKSTREAM_DEPTH` checks in `bolt::packstream` removed it died with `SIGSEGV`
while loading its seed corpus (the 100 KB `depth_bomb`); restored, 60s clean at ~108,000
runs with the `encode ∘ decode` idempotence assertion holding throughout.

This is the same discipline the AMQP field-table bound and the xmlrpc depth bound were
verified with, and it is the only evidence that distinguishes "the fuzzer found nothing"
from "the fuzzer is not looking".

Two things that pass had to be got right first, and both are recorded above because each
silently produced a *false* "found nothing": the corpus needs a depth bomb, and ASan has
to be off on macOS. A harness can be green for the wrong reason in more than one way.

## What is NOT covered, and why

- **Every USB protocol, including CTAPHID reassembly and CTAP2's `serde_cbor`.**
  `usb-fido2` → `usb-common` → `usbip` → `nusb`. nusb 0.2.7, the newest published
  version, has a `#[cfg(fuzzing)]` helper that does not typecheck (E0271:
  `fuzz_parse_concatenated_config_descriptors` declares `Item = &[u8]` and returns an
  iterator of `ConfigurationDescriptor<'_>`). cargo-fuzz sets `--cfg fuzzing` across the
  whole graph, so the build fails before reaching any NetGet code. **No NetGet USB
  protocol can be fuzzed until that is fixed upstream.** CTAP2 is the one worth coming
  back for: `Ctap2Request::parse` puts a one-byte command check in front of
  `serde_cbor::from_slice`, and CBOR nests by construction with no depth limit in the
  crate — the same arithmetic that made bencode cost ~1 KB on the wire.
- **SIP, SMB, MSSQL, torrent-tracker line/body parsers.** Private functions on private
  types; reaching them needs `pub` on the function *and* its return type, which is more
  visibility surface than a fuzz target should buy on its own. Worth doing when someone
  is next in those files — `SmbServer::parse_smb2_path` and `parse_smb2_username` are
  hand-rolled offset arithmetic on pre-auth CREATE and SESSION_SETUP bodies.
- **`torrent_dht::parse_krpc_message`** is private, but its dangerous half is
  `check_bencode_structure`, which `bencode_structure` already drives directly.
- **MySQL and PostgreSQL** delegate framing to `opensrv-mysql` and `pgwire`; there is no
  NetGet byte parser to target.

## Not a merge gate

`.github/workflows/fuzz.yml` runs nightly and on manual dispatch, one job per target,
and uploads crash artefacts and the grown corpus. It is deliberately not a PR gate: a
fuzzer is a search, so gating a merge on whether it found something in 300 seconds fails
honest PRs at random. `ci.yml` is the gate. A crash from this job is a real defect on
whatever branch it appears.
