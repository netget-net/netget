# DataLink E2E Tests

## What these tests are

Two files, both **in process** — neither spawns the netget binary and neither needs Ollama.

- `e2e_test.rs` — the startup contract and the capture path, driving
  `DataLinkServer::spawn_with_llm` directly.
- `test.rs` — the declarations (binding, privilege, startup parameters, action set, registry),
  none of which need any privilege.

## What they replaced, and why it matters

This directory was the worst case found in the August 2026 completeness audit: **DataLink was
rated `Beta` on a suite with zero assertions.**

- `e2e_test.rs` had three tests that started the binary against a mock Ollama, slept 500ms,
  `println!`ed a ✅, and stopped the server. Not one `assert!`. Not one `verify_mocks()`. Its own
  comment admitted *"Mock verification not possible in subprocess tests"* — so the mock
  expectations it declared were decorative.
- `test.rs::test_arp_responder` shelled out to `arping` and printed a note on **every** outcome —
  reply, no reply, `arping` missing — then returned `Ok(())`. Its failure branch read *"No ARP
  reply received (this is expected if server isn't fully implemented)"*: a test announcing its own
  meaninglessness. It also tested an impossible premise: DataLink has **no packet-injection
  action**, so a DataLink server can never answer an ARP request. No amount of privilege would
  have made it pass. Answering ARP is `src/server/arp/`'s job.
- `test.rs::test_datalink_interface_detection` built a `format!` string and printed it.

The lesson worth keeping: a test that catches every failure and prints a note is worse than no
test, because it is counted as coverage. If a condition cannot be checked, `#[ignore]` it with a
reason — cargo then reports *ignored*, which nobody mistakes for a pass.

## Test cases

### `e2e_test.rs`

| Test | Privilege | Asserts |
|---|---|---|
| `datalink_unknown_interface_is_refused` | none | `spawn` returns `Err`; the message contains `no such capture device` and the device name |
| `datalink_startup_outcome_matches_capture_privilege` | none | `Ok` **iff** the pcap handle really opened. Unprivileged: `Err`, mentioning `failed to open pcap capture`, the interface, and `/dev/bpf*` or `CAP_NET_RAW` |
| `datalink_event_payload_reports_the_frame_and_any_truncation` | none | `packet_event_data` against literal ARP bytes: a short frame whole; a long one cut, with `truncated`/`captured_length` set and `packet_length` still true; the exact boundary uncut; and every field it emits declared on `datalink_packet_captured`. The only part of a pcap protocol that *can* be asserted with no handle |
| `datalink_invalid_bpf_filter_is_refused` | capture | an uncompilable BPF expression fails startup with `invalid BPF filter` |
| `datalink_captures_a_real_loopback_frame` | capture | a UDP datagram sent on loopback appears byte-for-byte in the captured hex, **and** the frame reaches the event path |

The second test is the one with teeth on an unprivileged machine: it asserts *both* branches, so
a regression to the old fire-and-forget `spawn_blocking` (which returned `Ok` before the pcap
handle was known to have opened) fails it immediately. The same invariant is guarded across all
four capture protocols by `tests/capture_startup_reports_failure_test.rs`.

### `test.rs`

| Test | Asserts |
|---|---|
| `datalink_default_binding_is_the_platform_loopback` | default interface is `lo0` on macOS/BSD, `lo` elsewhere; no port is declared. Hardcoding `lo` once made the default unresolvable on macOS |
| `datalink_declares_packet_capture_privilege` | requirement is `PacketCapture` (not `RawSockets` — a ChmodBPF user has one and not the other) and `is_met_by` agrees with the probe |
| `datalink_offers_only_observation_actions` | exactly `notify_operator` and `ignore_packet`, and every event type carries actions |
| `test_datalink_registration_and_startup_params` | registered under `DataLink`, claims the `datalink` keyword, declares `filter` and **not** `interface` |

## LLM call budget

**Zero.** No test here calls a model. The capture test answers `datalink_packet_captured` with a
static handler, which `call_llm` executes in-process, and points the `OllamaClient` at
`http://127.0.0.1:1` — an unroutable address, so reaching a model would itself be a failure.

## Privileges

The two `#[ignore]`d tests need a layer-2 capture handle:

- **macOS/BSD**: read access to `/dev/bpf*`. Stock macOS ships those `crw------- root:wheel`, so
  `sudo` or Wireshark's *ChmodBPF* launch daemon.
- **Linux**: root, or `sudo setcap cap_net_raw+ep <binary>`.

Note the trap the old ARP guard fell into: `pcap::Device::list()` succeeds for **any**
unprivileged user (it is `getifaddrs`), so enumerating devices proves nothing about whether
capture will work. `SystemCapabilities::detect()` opens a real handle, which is why these tests
use it.

Running them explicitly with `--ignored` on a host that still cannot capture **fails loudly**
(`require_capture`) rather than skipping: you asked for the privileged test, so reporting a pass
for something that verified nothing would be the exact defect this suite replaced.

## Running

```bash
# unprivileged (everything that can run without root)
./cargo-isolated.sh test --no-default-features --features datalink \
    --test server -- server::datalink --test-threads=100

# privileged
sudo -E ./cargo-isolated.sh test --no-default-features --features datalink \
    --test server -- server::datalink --ignored --test-threads=100
```

## Coverage gaps

- **DataLink capture has now been observed, once, deliberately.**
  `datalink_captures_a_real_loopback_frame` and `datalink_invalid_bpf_filter_is_refused` were run
  with `--ignored` on 2026-09-08 (macOS 27, user in the `access_bpf` group) and both passed: a
  loopback UDP datagram was captured, its bytes appeared in the hex the model would be shown, and
  it reached the event path. The protocol stays `Experimental` because the test is `#[ignore]`d
  and an ignored test is not evidence for a rating — see `src/server/datalink/AGENTS.md` for why
  no unprivileged capture test can exist.
- Loopback framing differs by platform (DLT_NULL on macOS/BSD, Ethernet on Linux), so the capture
  test asserts on payload bytes, not on framing. Ethernet-header parsing is untested.
- No test for BPF filters that compile but select nothing, for multiple interfaces, or for packet
  loss under load.
- Packet injection is untested because it does not exist.
