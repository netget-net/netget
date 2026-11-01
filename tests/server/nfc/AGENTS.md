# NFC Server E2E Testing

## Strategy

**One file, `e2e_test.rs`, 2 tests** — covering NFC virtual tag exchanges.
This doc did not name it until 22 September 2026, which is the starkest form of a test
directory's doc drifting: a single file, and the doc describing it without ever saying so.

The virtual tag binds a TCP socket and speaks the vsmartcard `vpcd` framing (u16 big-endian
length prefix; a 1-byte frame is a control code, anything longer is an ISO 7816-4 APDU), so a
test client is about twenty lines: write a length-prefixed frame, read a length-prefixed
frame. **No reader, no vpcd daemon, no PC/SC** — the test drives the real socket the real
protocol binds, and asserts the response APDU **bytes**.

That is the point: a stub cannot pass. Asserting `9000` arrives is not enough on its own, so
the suite also asserts a body the handler supplied, a status word the handler chose, and two
status words the *server* must produce on its own.

## What `test_nfc_virtual_tag_apdu_exchange` covers

| Step | Wire | Asserts |
|---|---|---|
| ATR | control frame `04` | the exact ATR the handler set with `set_atr` (not the built-in default) |
| SELECT by AID | `00 A4 04 00 07 D2760000850101 00` | `nfc_tag_selected` fired and its `9000` reached the reader |
| READ BINARY | `00 B0 00 00 0F` | `nfc_apdu_received` fired; body is `"Hello NFC!"` then `9000` |
| VERIFY | `00 20 00 00 06 "123456"` | the handler's refusal `6982` survives verbatim |
| GET CHALLENGE | `00 84 00 00 08` | handler answers *without* `respond_to_apdu` → tag fails **closed** with `6F00`, never `9000` |
| INTERNAL AUTHENTICATE | `00 88 00 00 08` | handler answers *with* `respond_to_apdu` but names **no status word** → still `6F00`, and the body does not reach the reader either |
| truncated APDU | `00 A4 04` | `6700`, produced locally without reaching the handler |

The ATR check is what proves `set_atr` is no longer write-only — the mock sets
`3B8180018050`, which is not the compiled-in default.

The GET CHALLENGE case is the fail-open regression test. The mock returns a valid response
containing only `notify_operator`, i.e. the handler answered but produced no APDU response. If
anyone ever adds a permissive default, that assertion turns red.

**The INTERNAL AUTHENTICATE case is the sharper half of the same test, and it used to fail.**
`sw1`/`sw2` were optional and defaulted to `"90"`/`"00"`, in `execute_action` *and* again in
`decode_status_byte`, so `{"type": "respond_to_apdu", "data_text": "AUTH OK"}` — an answer
naming no status word at all — reached the reader as `AUTH OK 90 00`. On an access-control
device that means an omission approves an authentication. Both defaults are gone; the assertion
pins that a status word is only ever one the handler spelled out.

The truncated-APDU case is last on purpose: it must not reach the LLM, so it also pins the
mock call counts below.

## LLM call budget

**7 calls, one server, one test.**

1. top-level instruction → `open_server`
2. `nfc_server_started` → `set_atr` + `set_ndef_message`
3. `nfc_tag_selected`
4. `nfc_apdu_received` (READ BINARY)
5. `nfc_apdu_received` (VERIFY)
6. `nfc_apdu_received` (GET CHALLENGE)
7. `nfc_apdu_received` (INTERNAL AUTHENTICATE)

Each rule carries `.expect_calls(1)` and the test finishes with `server.verify_mocks()`, so an
extra or missing call fails the test. Note that an action `execute_action` rejects costs **no**
extra call: `executor::execute_actions` records it as a failure and returns, and nothing in
`call_llm` re-prompts the model over a failed action (the repair loop is for unparseable JSON
and unknown action *names*). So case 7 stays at one call even though its action is refused.

## Mock rule ordering trap

The first matching rule wins, and on an *event* call `context.instruction` is the **server's**
instruction (the one passed to `open_server`), not the top-level prompt. So a rule written as
`on_instruction_containing("NFC")` would swallow every event call if the server instruction
also contained "NFC".

This suite matches `on_instruction_containing("via NFC")`, a phrase that appears only in the
top-level prompt; the server instruction is `"Answer APDU commands as a Type 4 tag"`. Keep it
that way when adding cases.

The four `nfc_apdu_received` rules are disambiguated with
`.and_event_data_contains("ins", "B0" | "20" | "84" | "88")`.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features nfc \
    --test server -- --test-threads=100 nfc
```

**If this fails with `Timeout waiting for netget startup`, re-run before believing it.**
`target/` is shared, so a concurrent build for a different feature set overwrites
`target/debug/netget` with a binary that has no `nfc` protocol compiled in; the harness then
never sees a "listening on" line and times out at 120s. It is contention, not a bug in the
test. A genuine failure shows a failed assertion within about a second.

## `wire_failure_categories_map_to_distinct_status_words`

A synchronous, socket-free companion to the E2E case. It asserts the mapping the LLM-error
branch relies on — `WireFailure::Overloaded` → `6400`, `WireFailure::Unavailable` → `6F00` —
and that the two stay different. Driving it end-to-end would mean forcing an overload out of
the mock backend, which costs an unmatched-request round trip and would break the suite's
exact LLM call budget for no extra coverage: the byte the reader sees is chosen entirely by
`ApduResponse::for_wire_failure`, so testing that function tests the wire.

## Not covered

- Interop with a real `pcscd` via `vpcd` in TCP-client mode. Needs vsmartcard installed.
- Concurrent readers on one tag (the accept loop handles them; nothing asserts it).
- Extended-length APDUs (`ApduCommand::parse` handles them; no test drives one).
