# M3UA Test Strategy

Read [`src/server/m3ua/AGENTS.md`](../../../src/server/m3ua/AGENTS.md) first.

| File | What it is evidence of | LLM calls |
|---|---|---|
| `codec_test.rs` | the M3UA wire format matches RFC 4666, asserted against literal octets | 0 |
| `transport_test.rs` | the SCTP refusal happens, and says something useful | 0 |
| `e2e_test.rs` | the association, the state machine and the fail-closed rule, over the **lab** transport | 7 |
| `ss7_codec_test.rs` | SCCP/TCAP/MAP/CAP against jSS7's captured bytes: NetGet's MAP answers equal jSS7's own; every bound; fail-closed; tshark reads NetGet's answers | 0 |
| `ss7_e2e_test.rs` | the same through a NetGet process and the mocked model, over the lab transport | 5 |
| `real_peer_test.rs` (Linux) | Restcomm jSS7 8.0.112 over real SCTP: MAP and CAMEL dialogues answered by the model, decoded by jSS7; fail-closed seen by jSS7; live capture through tshark | 0 (python policy) |
| `osmo_stp_test.rs` (Linux) | osmo-stp 1.6 as an ASP of NetGet's SGP, routing jSS7's MAP to it | 0 (python policy) |

`ss7_support.rs` holds jSS7's captured messages (cut from a dumpcap capture of jSS7 talking to
itself; they are a third party's encoding, nothing here came from NetGet) and the pcap writer for
the tshark oracle; `ss7_live.rs` the live capture, the jSS7 driver command and osmo-stp. Both are
shared with `tests/client/m3ua/` by `#[path]`.

## The real peers

`install_peers.py <dir>` builds `jss7_peer/` (Ss7Peer.java: test glue over jSS7's SCTP, M3UA,
SCCP, TCAP, MAP and CAP stacks from Maven Central and the JBoss repository; JDK 11+ and Maven)
and prints `NETGET_JSS7_PEER`. `osmo-stp` is the Ubuntu package. The tests need a kernel with
SCTP (`sudo modprobe sctp`) and dumpcap allowed to capture on loopback, and **fail** — not skip —
without any of them; on macOS they are not compiled (`mod.rs`), since there is no SCTP there.

The driver's output protocol (`READY`, `RESULT scenario=…`, `RECV op=…`, `DONE …`) is documented
at the top of `Ss7Peer.java`. Free text is percent-encoded; the JVM must run under a UTF-8 locale
or non-ASCII argv arrives mangled (`ss7_live::jss7_command` sets it — a test once read
`"Gr    e"` for `"Grüße"` until it did).

jSS7 facts that shaped the code: its AS goes active only on NTFY(AS-ACTIVE) after ASPAC ACK, so
NetGet's policy sends one; its server associations accept only the configured remote port, so
the client has `local_port`; it refuses a networkUnstructuredSsContext TC-BEGIN without
MAP-OpenInfo, so NetGet's USSD dialogues carry it; it sends invoke ids from 0 and SCCP class 1,
which NetGet mirrors.

## The ceiling

Everything real-peer runs on Linux only, in the protocol-pairs `m3ua` job. On macOS the codec,
engine and lab-transport suites run; nothing there proves the SCTP path.

## `codec_test.rs` — why literal octets, not round-trips

Every expected vector is **written out by hand from RFC 4666**, field by field, with the decode
in the comment. Round-tripping NetGet's encoder through NetGet's decoder would pass just as
happily if both were wrong in the same way — the root `AGENTS.md` names that as circular
evidence, and for M3UA it is not hypothetical.

The rule at stake is RFC 4666 section 3.2: **the Parameter Length excludes the padding that
rounds a parameter to a 4-octet boundary.** A two-octet value declares 6 and occupies 8. An
implementation that writes 8 there decodes its own traffic perfectly and corrupts every real
peer's, and no round-trip test would ever notice. `parameter_length_excludes_padding_but_message_
length_includes_it` asserts both numbers in the same test on purpose.

`data_encodes_the_routing_label_and_pads_the_user_part` is the consequential case: 15 octets of
Protocol Data declare 19 and occupy 20, and
`decoded_payload_never_includes_the_padding_octet` asserts the receive side of the same thing —
a padding octet delivered as user part is a corrupted ISUP message.

Two tests feed in messages **NetGet did not encode**
(`parses_a_hand_written_data_message_into_structured_fields`,
`parses_a_hand_written_aspup_with_asp_identifier_and_info_string`). That direction is the
genuinely non-circular one, since the input comes from the RFC.

If you add a vector: write the octets first from the RFC, then run it. If you find yourself
copying the encoder's output into the expectation, the test has stopped being evidence.

## `transport_test.rs` — the refusal is a feature

`sctp_transport_either_works_or_refuses_by_name` passes on **both** kinds of host, and asserts
something different on each. On a host without SCTP the error must name SCTP, RFC 4666, the
`transport="tcp"` escape hatch, and the fact that the escape hatch is `NON-STANDARD` — an errno
alone leaves an operator stuck. On a host with SCTP it must produce a bound listener, and it
asserts the host is not macOS, because a `SOCK_STREAM`/`IPPROTO_SCTP` socket succeeding there
would mean the probe is not probing.

`nothing_defaults_to_the_lab_transport` guards the direction that would be silent: if the
default ever flipped to TCP, an operator on a host *with* SCTP would get the lab framing without
asking, which is exactly what the refusal exists to prevent.

None of these bind a port of consequence or make an LLM call, so they are cheap and can be run
on their own:

```bash
./cargo-isolated.sh test --no-default-features --features m3ua \
    --test server -- server::m3ua::transport_test --test-threads=100
```

## `e2e_test.rs` — budget and what each test pins

Seven LLM calls across three tests, each a separate NetGet process.

**`test_m3ua_asp_comes_up_activates_and_exchanges_data`** (4 calls: startup, ASPUP, ASPAC, DATA).
The protocol end to end. The DATA rule uses `respond_with_actions_from_event` and swaps the point
codes and echoes the SLS — reading those fields off the event is simultaneously the assertion
that the routing label arrived as *structured fields* rather than as a blob. The reply's payload
is sent as `"0a0b0c"` with `encoding: "hex"` and asserted on the wire as three octets, which is
the `send_tcp_data` bug in miniature: had the executor not decoded the hex, six ASCII characters
would have gone out instead.

**BEAT and ASPIA are in this test precisely because they must cost nothing.** They are answered
in Rust; a fifth model call would have gone unmatched, and `verify_mocks` is what turns that into
a failure. Do not add a mock rule for them "just in case" — that would delete the assertion.

**`test_m3ua_silence_does_not_admit_an_asp`** (2 calls: startup, ASPUP). The policy answers
`wait_for_more`. NetGet must answer ERR `0x0d` and leave the ASP DOWN, and the ASPAC that follows
must be refused as `0x06 Unexpected Message` with **no** second model call. It also asserts
`decision=model_silent` appears in the log: the wire carries a category, and only the log can say
which of the non-answers it was.

**`test_m3ua_refuses_when_no_policy_is_configured`** (1 call: startup). `open_server` with an
empty instruction and no handlers. The ASPUP is refused and the log says
`decision=no_policy_configured`, with `verify_mocks` proving the ASPUP cost no call — there was
nothing to ask. This pins the deliberate difference from BGP, which treats the same situation as
a static default and completes its handshake.

### Rules for adding tests here

- **Distinct events per rule.** Mock rules are first-match-wins, and two rules on the same event
  with no way to tell them apart is the most common mistake in this repo. To express "then", use
  one rule with `respond_with_actions_from_event` that branches on the event.
- **`wait_for_mocks(30)` then `verify_mocks().await?`**, always. Without the second, the test
  asserts nothing about LLM interaction.
- **Build messages by hand, not through `codec`.** The helpers in `e2e_test.rs`
  (`m3ua_message`, `protocol_data`, `find_param`) reimplement the framing from the RFC, so the
  server's decoder is fed something it did not produce. Calling into `netget::server::m3ua::codec`
  here would make the e2e tests circular too.
- **127.0.0.1 and port 0 only**, and `transport: "tcp"` — the SCTP transport cannot bind on this
  machine, so a test that omits it will fail at startup, correctly.

## Running

```bash
# everything
./cargo-isolated.sh test --no-default-features --features m3ua \
    --test server -- server::m3ua --test-threads=100

# just the codec (no sockets, no processes, instant)
./cargo-isolated.sh test --no-default-features --features m3ua \
    --test server -- server::m3ua::codec_test --test-threads=100
```

The whole-tree ratchets are worth running after any change to `actions.rs`, since they walk the
registry rather than this suite:

```bash
for t in event_action_declarations_test executable_examples_test event_emit_sites_test \
         startup_param_drift_test wire_failure_test; do
  ./cargo-isolated.sh test --no-default-features --features tcp,m3ua --test $t -- --test-threads=100
done
```

`tcp,m3ua` rather than `m3ua` alone: two of those tests assert their own coverage against a
minimum protocol count and fail vacuously in a one-feature build. That failure is pre-existing
and is not about M3UA — `executable_examples_test::the_example_audit_has_something_to_inspect`
wants more than 900 examples in the build and only reaches that at `--all-features`.
