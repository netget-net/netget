# What a protocol actually offers the model

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Six ways an action or event can be declared and still never reach the model or the wire,
each found in the tree, and the tests that now hold them shut
(`tests/event_action_declarations_test.rs`, `tests/event_emit_sites_test.rs`,
`tests/executable_examples_test.rs`; the ratchet table is in `testing.md`).

## Hollow, delegating, or unreachable

Treat `Experimental` as "compiles and has a test", not "works". Before assuming a protocol
behaves, check what it actually offers the model — and check it two ways, because one grep
lies in both directions:

```bash
grep -A3 "fn get_sync_actions" src/server/<p>/actions.rs | grep -c 'vec!\[\]'  # hollow?
grep -cE "DnsProtocol|BluetoothBle::" src/server/<p>/actions.rs                # or delegating?
grep -c "\.with_actions(" src/server/<p>/actions.rs                            # reachable at all?
```

An empty `get_sync_actions()` is fine if the protocol **delegates** — `doh` and `dot` forward
`DnsProtocol`'s set verbatim, so the model sees the full DNS vocabulary. It is a trap if it
does not. And actions can be declared yet unreachable: `call_llm` builds the model's tool list
from `event.event_type.actions`, so a protocol whose event types never call `.with_actions(...)`
leaves the model unable to answer at all. That was found in 17 protocols, is now fixed
everywhere, and is guarded two ways: `EventType::with_no_actions()` marks the deliberate case,
anything else logs at ERROR and falls back, and `tests/event_action_declarations_test.rs` fails
the build on any new occurrence across every registered protocol.

## The guard that exempted the worst case

**That guard had a hole worth remembering, because it inverted the whole point.**
`audit_event_action_declarations` early-returned when `get_sync_actions()` was empty, on the
reasoning that a protocol advertising nothing is withholding nothing. It is backwards: offering
the model *no* vocabulary is the worst case, not the exempt one. `usb-fido2` had zero sync
actions, zero LLM integration and three events the model could not answer, and
`cargo test --features usb-fido2,tcp` reported **3 passed**. The rule now fails that case; re-run
at `--all-features` it flagged exactly `usb-fido2` and produced no false positives across the
other 115, and delegation is unaffected because `doh`/`dot` return a non-empty set of their own.
The `registry-audit` CI job runs these audits at `--all-features` for that reason — every other
job compiles 6 of 116, so a registry-walking test is only as wide as its feature set.

## Declared and never emitted

**A fourth variant: an event can be declared and never emitted.** Declaring actions on it then
buys nothing, because it never fires. The USB family was the live case and is now fixed —
`usb_*_detached`, `usb_msc_read`, `usb_msc_write`, `usb_keyboard_led_status` and the
`usb_serial_*` events all have real emit sites. Two of those repairs are worth knowing about,
because the protocols were more broken than "an event does not fire": `usb-mouse`'s
`handle_connection` took the socket as `_stream` and dropped it, ran no USB/IP session at all and
parked on `sleep(u64::MAX)`, while a complete handler sat unwired in `handler.rs`; and every
`usb-keyboard` action demanded `connection_id.as_u64()` while events report `"conn-2"`, so no
value the model could send would ever have worked. Check the emit side, not just the declaration:

```bash
grep -rn "_EVENT" src/server/<p>/mod.rs   # which events does the server actually raise?
```

## Clients: the tool list was built from async actions alone

**A fifth variant, on the client side, and it was the widest of all: `call_llm_for_client` built
its tool list from `get_async_actions()` alone.** It read neither `get_sync_actions()` nor
`event.event_type.actions`. **53 of the 91 registered clients** had at least one action the model
could never see — 11 hiding something protocol-specific (`irc`'s send_privmsg/notice/raw, `nfc`'s
send_apdu, `icmp`'s send_echo_request, whose async list was empty outright) and 42 hiding
`wait_for_more`, so no stream client could say "that response was partial". TFTP declared
`send_ack` sync-only, so every DATA block came back `Unknown Action` and every transfer stalled
at block 1.

**Clients union; servers narrow — and that asymmetry is deliberate.** A server has two LLM entry
points, so its async/sync split is real and `ssh_auth` can legitimately narrow to
`ssh_auth_decision`. A client has one: `call_llm_for_client` serves both the initial instruction
(`event: None`) and every network event, so no client *can* express a narrowing. Hence
`client_llm_action_set(...)` = async ∪ sync ∪ the firing event's actions. The tree confirms the
split was never meaningful there — 85 of 91 clients attach no actions to any event type, and ~40
duplicated their whole list into both methods purely to work around this.

`tests/event_action_declarations_test.rs` now walks **both** registries, and additionally
round-trips each advertised name through the protocol's own executor — which caught a sixth
variant, *advertised but unexecutable* (`ssh_agent/modify_instruction`,
`pop3/modify_pop3_instruction`, and four more that were removed as unimplementable). A static
declaration check cannot find those.

## The `bluetooth_ble_*` family: a base that hardcodes its own protocol

The whole `bluetooth_ble_*` family was a third variant: `BluetoothBle::spawn_with_llm_actions`
hardcodes `BluetoothBleProtocol` when it calls `call_llm`, so all sixteen profiles' own actions
and events were unreachable regardless of what they declared. Fifteen now delegate explicitly.
`bluetooth_ble_beacon` took the other exit: it no longer goes through the base at all, so it
calls `call_llm` with its own protocol and its own actions really are the ones offered and
executed. That is the only way a profile can own a vocabulary — delegate the base's, or stop
using the base.
