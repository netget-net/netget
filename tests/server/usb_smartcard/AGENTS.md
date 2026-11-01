# USB Smart Card (CCID) E2E Testing

## Strategy

The tests are a **real USB/IP client** written against the protocol, plus a **real CCID
client** on top of it. They speak `OP_REQ_IMPORT`, then push `USBIP_CMD_SUBMIT` URBs on the
bulk OUT and bulk IN endpoints carrying CCID messages, and assert on the bytes the reader
returns.

This is deliberate. The protocol this replaced was `Incomplete`: `Server::spawn` was
`bail!("not yet implemented")` and every test in this file was `#[ignore]`d, so the suite said
nothing either way. A test that merely opened a TCP connection and checked that an event fired
would be the only thing between a stub and a green suite.

No `usbip` kernel module, no root, no `pcscd`, no `vpcd`. Everything is loopback TCP.

## The client (`UsbIpClient` in `e2e_test.rs`)

| Method | What it does |
|---|---|
| `attach(port)` | `OP_REQ_IMPORT` for bus id `0-0-0`, reads the 320-byte `OP_REP_IMPORT` |
| `send_ccid(type, params, payload)` | builds the 10-byte CCID header, bulk OUT on endpoint 2, returns the `bSeq` it used |
| `read_ccid(timeout)` | polls bulk IN, **reassembling 64-byte packets** until `dwLength` is satisfied, returns a parsed response |
| `power_on()` | `PC_to_RDR_IccPowerOn`, asserts `bSeq` is echoed |
| `slot_status()` | `PC_to_RDR_GetSlotStatus`, asserts `bSeq` is echoed |
| `transmit_apdu(bytes)` | `PC_to_RDR_XfrBlock`, asserts `bSeq` is echoed |

Two things the client has to get right, and both are load-bearing:

- **Wire direction is not rusb's `Direction`.** On the USB/IP wire OUT is 0 and IN is 1;
  `rusb::Direction` has `In = 0`.
- **The reader uses 64-byte packets**, so a response longer than that arrives over several
  URBs. `read_ccid` reassembles by reading the CCID `dwLength` field, exactly as a host does.
  A client that assumed one URB per message would pass today and break on the first long ATR.

## Tests

| Test | Proves | LLM calls |
|---|---|---|
| `test_usb_smartcard_atr_and_apdu_exchange` | `set_atr` reaches the wire; an APDU round-trips through the handler; no answer fails closed to `6F00` | 5 |
| `test_usb_smartcard_no_card_fails_without_llm` | an empty slot is refused by the reader with no LLM call; `usb_smartcard_detached` fires | 4 |

**LLM budget: 9 calls**, under the project ceiling of 10.

### What each assertion is for

`test_usb_smartcard_atr_and_apdu_exchange`:

- The mock sets a distinctive ATR (`3B8F80014E6574476574`) and the test asserts the exact hex
  the host receives. A reader that ignored `set_atr` and returned the built-in default
  (`3B901100`) fails.
- The SELECT-by-AID response is asserted as the full byte string `"NetGet PIV" 90 00` — body
  from `data_text`, then SW1/SW2 — so both the handler's body and its status word have to
  survive the round trip.
- The VERIFY case has the mock answer with `notify_operator` and **no `respond_to_apdu`**. The
  test asserts `6F00`. This is the fail-closed path: an implementation that defaulted to `9000`
  when the handler said nothing fails here.

`test_usb_smartcard_no_card_fails_without_llm`:

- `set_card_present false` at `usb_smartcard_reader_ready`, then `bmICCStatus` must read 2
  (no ICC present).
- `IccPowerOn` must come back as `RDR_to_PC_SlotStatus` (not a data block) with
  `bmCommandStatus` = failed and `bError` = `0xFE` (`ICC_MUTE`).
- `XfrBlock` must be refused **by the reader**, not forwarded to the handler. The assertion is
  on the message type: a refusal is `RDR_to_PC_SlotStatus`, whereas anything that reached the
  handler comes back as `RDR_to_PC_DataBlock`. The mock also registers no
  `usb_smartcard_apdu_received` expectation, so a forwarded APDU would additionally get an
  HTTP 500 from the mock and show up in `verify_mocks`.

## Synchronisation

Both tests wait for `"USB smart card LLM call completed for connection"` before asserting,
because the attach event and the USB/IP import are independent: the LLM call starts as soon as
the TCP connection is accepted, well before the client sends `OP_REQ_IMPORT`.

`test_usb_smartcard_no_card_fails_without_llm` waits for that line **twice** (attach, then
detach) via `wait_for_log_count`, plus `"USB smart card host detached on connection"`.

## Mock actions

`wait_for_more` is **not** a valid action for this protocol — the harness
(`tests/helpers/mock_action_names.rs`) fails the test if a mock returns it, because the server
would reject it as unknown and the mock would prove nothing. Use `notify_operator` for a no-op
answer; it is generic, executes cleanly, and produces no `respond_to_apdu`, which is exactly
what the fail-closed assertion needs.

## Running

```bash
CARGO_TARGET_DIR=/tmp/ccid-target cargo test --no-default-features --features usb-smartcard \
    --test server -- --test-threads=100 usb_smartcard
```

Runtime is about 1 second for both tests.

Use a private `CARGO_TARGET_DIR` when other agents may be rebuilding the shared `target/`.

## Not covered

- Attaching from a real Linux host (`sudo usbip attach` + `pcscd` + `opensc-tool`) — needs
  `vhci-hcd` and root.
- The interrupt endpoint: `RDR_to_PC_NotifySlotChange` is implemented but never polled here.
- `GetParameters` / `SetParameters` / `Escape` / `Abort` (implemented, not asserted).
- Two hosts attached at once sharing the one slot.
- A response body long enough to need more than one bulk IN URB — the reassembly loop handles
  it and is exercised by ATR and APDU reads, but not by a >64-byte payload specifically.
