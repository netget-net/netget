# DataLink Client Tests

## Four files, split by what they need

| File | Privilege | What it covers |
|---|---|---|
| `action_test.rs` | **none** | the whole model-facing surface: every advertised action, every declared example, what `execute_action` accepts and refuses, and the event payload against literal frame bytes |
| `packet_test.rs` | **none** | the link-type framing, IPv4/TCP builder and frame decoder against literal bytes: the known-good MP_CAPABLE SYN, checksums, TCP/MPTCP options, NULL/LOOP/RAW headers, the event payload on `lo0`, probe requests, and how `remote_addr` / `filter` resolve |
| `command_channel_test.rs` | none, plus two `#[ignore]`d privileged tests | the lifecycle: `connect` refusing an interface it cannot open, and — privileged — a real acknowledged `sendpacket`, honest `[ send ]` outcomes, the capture loop actually stopping, and `probe_tcp` on loopback returning a decoded SYN-ACK and RST |
| `e2e_test.rs` | **capture access, hard-required** | the real binary against a mock model, opening a real libpcap handle on loopback and injecting real frames |

## The correction this split makes

This directory used to claim, in this file, that the tests need "**No root privileges**", do
"**No actual network traffic**", and that "**Tests don't actually inject frames**". All three
were false. `e2e_test.rs` has always spawned the netget binary, opened `lo0` through libpcap and
put ARP frames on it; it passed on the maintainer's machine because that machine is in the
`access_bpf` group, and on any other host it failed as a mock expectation that never fired —
several steps from the cause.

That is fixed in the honest direction rather than the convenient one. `e2e_test.rs` now calls
`require_capture(...)` first and **fails, loudly, with the reason** when the access is missing.
It is deliberately not a skip: this client's only end-to-end evidence is those four tests, and a
silent pass would leave the maturity rating resting on nothing (the `npm` precedent).

What was genuinely missing was a test that needs no privilege *at all* — the client's advertised
actions, its frame validation and its event payloads were covered by nothing an ordinary run
executed. That is `action_test.rs`, and it is where any new assertion about what the model sees
should go.

## Tests

### `action_test.rs` (24 tests, no privilege, no LLM)

- every declared `example`, from async actions, sync actions and every event's action list, is
  accepted by this protocol's own `execute_action`
- all four events declare actions, and each is executable
- startup parameters are exactly `interface`, `promiscuous`, `capture` and `filter`
- `PrivilegeRequirement::PacketCapture`, agreeing with the live probe — **not** `RawSockets`,
  which is a different capability (a ChmodBPF user has one and not the other)
- `inject_frame` does not tell the model to append an FCS (it used to; the interface computes
  it, so a compliant model corrupted every frame with four bytes of payload)
- a 42-byte ARP frame decodes to exactly its bytes, header checked field by field
- `ff:ff:…`, `ff-ff-…` and space-separated hex all decode — a model writing from a packet dump
  writes separators, and they carry no information
- a runt (< 14 bytes) and an over-long frame (> 65535) are refused **by name**, before libpcap
- bad hex, an unknown verb and a missing frame are refused, each naming what was wrong
- `disconnect` and `wait_for_more` map to their lifecycle results
- the event payload: a short frame reported whole; a long one cut with `truncated` and
  `captured_length` set and `frame_length` still the true length; the exact boundary uncut; and
  every field it emits declared on the events that carry it — checked against an Ethernet ARP
  frame and a `DLT_NULL` IPv4/TCP frame, so the optional decoded fields (`family`, `ip`, `tcp`)
  are covered too; required declarations must always be present, optional ones may be absent

The structured spelling of `inject_frame` (September 2026) is covered in the same file, and
these are the assertions worth knowing about:

- **`a_utf8_payload_that_looks_like_hex_goes_out_as_those_characters`** is the one the
  original defect would have failed. `"deadbeef"`, `"48656c6c6f"` and `"0123456789abcdef"` are
  each injected twice, once with `payload_encoding: "utf8"` and once with `"hex"`, and the
  test asserts the literal characters in the first case, the decoding in the second, **and
  that the two frames differ** — which is the whole argument for the field existing. Nothing
  is sniffed; a string that is valid both ways means whatever the sender said it means.
- `structured_fields_assemble_the_same_bytes_as_the_hex_spelling` builds the 42-byte ARP frame
  from `dst_mac` / `src_mac` / `ethertype: "arp"` / a hex payload, and asserts it equals the
  hex spelling byte for byte.
- `ethertype_accepts_a_name_a_number_and_a_hex_string_but_not_a_bare_one` — `"arp"`, `"ARP"`,
  `"0x0806"` and `2054` all mean the same two bytes, every name in `ETHERTYPE_NAMES` means its
  own value, and a bare `"0806"` is refused with a message saying why it is ambiguous.
- `a_payload_without_its_encoding_is_refused_rather_than_guessed` — `payload_encoding` has no
  default, so a payload without it is refused by name; a header-only frame needs neither.
- `the_structured_and_hex_spellings_cannot_be_combined` — both together is refused naming both
  and saying neither takes precedence; a half-written structured frame is refused by the name
  of the missing field rather than completed with zeros.
- `a_captured_frame_is_reported_as_fields_and_hands_straight_back` — the event's `dst_mac`,
  `src_mac`, `ethertype`, `payload` and `payload_encoding` copied verbatim into `inject_frame`
  reproduce the captured bytes, and so does `frame_hex` through the escape hatch.
  `a_printable_payload_is_reported_as_text` does the same for a payload that is text, and
  `a_runt_reports_no_header_rather_than_an_invented_one` asserts the null header for a frame
  too short to have one.
- `no_example_hands_the_model_a_frame_as_hex` is the local form of
  `tests/example_hex_drift_test.rs`: asserted against the values a running build produces
  rather than against the source text.

### `packet_test.rs` (no privilege, no LLM)

The reference vector is a SYN tcpdump reported with a correct checksum (`0x434b`):
`127.0.0.1:40000 -> 127.0.0.1:3333`, seq `0x11223344`, ip id `0x1234`, DF, options mss 16344 +
MP_CAPABLE v1 flags `0x01`.

- `the_known_good_syn_is_built_byte_for_byte_with_both_checksums` — `build_ipv4_tcp` from
  structured fields equals those 48 bytes, IPv4 checksum `0x2a92`, TCP `0x434b`; and both verify
  to 0 over the literal packet
- on `NULL` the frame is `AF_INET` in host order + the packet, and MACs are refused naming the
  link type; on Ethernet the MACs are required and come first
- defaults: `dst_ip`/`dst_port` from `remote_addr`, `src_ip` only for a loopback destination,
  SYN; bad flags, ports, IPv6 addresses, option fields and a payload without its encoding are
  refused by name; options over 40 bytes are refused
- every named option round-trips through the decoder byte for byte; MP_CAPABLE with numeric
  and named flags and both keys; MP_JOIN is named and re-encodes from the decoded form; an
  unknown kind keeps its data; a malformed length is reported, not over-read
- link types from DLT values and their pcap names; NULL host order vs LOOP network order;
  `AF_INET6` is 30 on macOS; ARP on `NULL` and anything on `LINUX_SLL` refused
- `inject_frame` on `NULL` builds the family header, refuses MACs, requires `ethertype`; on
  `RAW` the payload is the frame
- `a_null_frame_is_decoded_as_family_and_ip_not_as_fake_macs`, and the same bytes read as
  Ethernet show the invented MACs the old decoder produced
- a zero TCP checksum on loopback is `checksum_ok: null` with the offload note; off loopback it
  is `false`
- `reply_matches` accepts the SYN-ACK and refuses our own SYN; the reply filter string;
  `echoed_options` with and without MP_CAPABLE coming back
- `probe_tcp` yields the probe request with its defaults and refuses a timeout over 10s;
  `parse_target` / `resolve_capture_filter`

### `command_channel_test.rs`

| Test | Privilege | Asserts |
|---|---|---|
| `datalink_client_refuses_an_interface_it_cannot_open` | none | `create` returns `Err` naming the device; the client is `ClientStatus::Error`; **no command handle** is registered |
| `connect_outcome_on_loopback_matches_capture_privilege` | none | `Ok` **iff** the process can capture; unprivileged, the refusal names `/dev/bpf*` or `CAP_NET_RAW` |
| `injected_frame_is_transmitted` | capture (`#[ignore]`d) | `Sent { bytes_sent }` from a real acknowledged `sendpacket`; bad hex and unknown verbs still `Rejected`; the injection reaches the access log; `disconnect` stops the capture loop |
| `probe_tcp_on_loopback_returns_the_syn_ack_and_the_rst` | capture (`#[ignore]`d) | with capture **off**, a `probe_tcp` SYN carrying MP_CAPABLE to a local listener returns `Probed` with one decoded SYN-ACK and whether MP_CAPABLE was echoed; to a closed port, one RST; the connect note names the link type (`NULL` on macOS) and the remote_addr default |

The second test is the one with teeth on either kind of host: it fails if `connect` ever again
returns `Ok` without a capture handle, which is the bug this client shipped with.

The third one is worth understanding. Before the `StopSignal` fix it did not fail — it **hung
the whole test binary**, because the pcap loop had no exit path and `Runtime::drop` waits for
blocking tasks. If it ever hangs again, that is what came back.

### `e2e_test.rs` (4 tests, capture required, ≤3 LLM calls each)

1. `test_datalink_client_inject_frame_with_mocks` — startup, `datalink_connected` answered with
   an ARP frame, `datalink_frame_injected` observed
2. `test_datalink_client_promiscuous_capture_with_mocks` — promiscuous capture of loopback
   traffic the test generates itself (it used to wait on whatever happened to cross `lo0`)
3. `test_datalink_client_inject_and_respond_with_mocks` — both directions on one client
4. `test_datalink_client_disconnect_with_mocks` — inject, then disconnect

All four `wait_for_mocks(30)` then `verify_mocks()`. The "mock verification not possible in
subprocess tests" notes they used to carry were stale — the calls immediately below them do
exactly that.

## Running

```bash
# everything that runs without privilege
./cargo-isolated.sh test --test client -- client::datalink:: --test-threads=16

# the privileged injection and probe tests, on a host with BPF access
./cargo-isolated.sh test --test client -- client::datalink:: --ignored --test-threads=16
```

On a host **without** capture access the four `e2e_test.rs` tests fail with an explanation of
what they need. That is the intended behaviour; see above.

## Coverage gaps

- No test injects a frame that a third party then receives and validates. `sendpacket` returning
  `Ok` and the byte count coming back is what is asserted; nothing independent confirms the
  frame's contents on the wire. That is the gap between this client and a `Beta` rating.
- The follow-up depth cap (`MAX_INJECTION_FOLLOWUPS`) is not exercised: provoking it needs a
  model that answers every injection with another, and a live capture to inject on.
- Promiscuous-mode drop counting under load is not exercised.
