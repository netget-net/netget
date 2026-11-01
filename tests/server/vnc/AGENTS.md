# VNC Protocol E2E Tests

Three tests in `test.rs`, all driving the real `netget` binary over RFB 3.8 with a client
implemented in the test file. There is no usable Rust VNC *client* crate (the maintained ones
are viewers with their own event loops), so the client is written directly against RFC 6143 —
about 150 lines, and the only way to prove the bytes on the wire mean what the server claims.

## Test strategy

**Assert decoded pixels, not byte counts.** The mocked model asks for a specific background and
a specific rectangle, and the test decodes the Raw payload and compares the RGB it finds at
chosen coordinates. That is what proves the whole path: structured commands → `DisplayCanvas` →
BGRX in the announced channel order. Swapping the byte order in `render_frame` fails two of the
three tests.

**Assert the pixel format, not just the geometry.** `ServerInit` is the contract for every
rectangle that follows; a test that read only width and height could not tell a correct frame
from a byte-swapped one.

**A missing or malformed message is a failure, not a note.** `read_message` returns `Err` on any
deviation from the wire format, and every read is wrapped in a 15 s timeout. This suite used to
swallow both an error and a timeout with a printed "this may be expected", so it could not fail
no matter what the server sent.

**Silence is asserted structurally.** Steps that must produce *no* server output are followed by
a read that expects something else: if `vnc_no_change` wrongly emitted a frame, the read of the
ServerCutText finds a FramebufferUpdate first and says so. TCP ordering makes this exact.

**Geometry comes from the wire.** `test_vnc_handshake_and_server_init` passes `width`/`height`
through `startup_params` and reads them back out of ServerInit, so the test would fail if the
parameters were declared and ignored.

## LLM call budget

**Total: 10.**

| Test | Calls |
|---|---|
| `test_vnc_handshake_and_server_init` | 1 (startup) |
| `test_vnc_llm_draws_screen_and_handles_input` | 7 |
| `test_vnc_placeholder_when_model_gives_no_usable_answer` | 2 |

Every rule is `expect_calls(1)`, so a call the server should not have made fails the run. That
is how the two throttles are tested: an incremental request that is held open and a pointer
*move* both cost zero calls, and any regression that made them consult the model would push a
rule over its expected count.

**Event rules are registered before the instruction rule.** Rules match in order, and
`on_instruction_containing("vnc")` would otherwise answer a network event with `open_server`.

## Test cases

### 1. `test_vnc_handshake_and_server_init`

Full RFB 3.8 negotiation: version is exactly `RFB 003.008\n`, security type None (1) is offered
and accepted, SecurityResult is 0. Then ServerInit must report the 640×480 requested through
`startup_params`, the desktop name, and 32bpp / depth 24 / little-endian / true colour with
shifts 16-8-0.

### 2. `test_vnc_llm_draws_screen_and_handles_input`

The whole feature in one connection:

1. Full update request → the model draws screen A. Assert the rectangle covers ServerInit's
   extent, the background RGB at (10,10), the rectangle's colour at (200,160), and the
   background again just outside it at (90,90).
2. Incremental request → held open, no call, no bytes.
3. KeyEvent press → the model draws screen B, which **answers the held request**. Assert the new
   background arrives.
4. KeyEvent release → `vnc_no_change`. PointerEvent move → no call at all. PointerEvent press →
   `vnc_no_change`. None of these may put anything on the wire.
5. ClientCutText → the model answers `vnc_set_clipboard`; assert the ServerCutText text. This
   read is also what proves step 4 sent nothing.
6. Full update request → `vnc_no_change`, and the server must still answer, with screen B.
7. Assert the status stream carried the pointer *movement* even though it cost no model call.

### 3. `test_vnc_placeholder_when_model_gives_no_usable_answer`

The mock answers the framebuffer event with `notify_operator` — a valid action that draws nothing.
The client must receive the placeholder screen (`netget::server::vnc::PLACEHOLDER_BACKGROUND`,
compared against the decoded pixel) and the server must report `produced no usable action`.
This is the fail-closed path: RFB has no "no answer" reply, so silence would hang the viewer,
and a screen that looked like content would hide the failure.

It also asserts `decision=model_silent` **and** that no `decision=fail_closed_llm_error`
appears, because the backend answered here — it was the model that had nothing to say.

### 4. `test_vnc_backend_failure_is_tagged_fail_closed`

The mirror of test 3, and it exists because the *screen* cannot tell the two apart: both draw
the same placeholder. The mock answers `vnc_framebuffer_update_request` with raw text that is
not an action, so the repair loop exhausts and `call_llm` returns `Err`. The assertions are the
pair: the client still gets a full frame (silence would hang it), and the log carries
`decision=fail_closed_llm_error` with no `decision=model_*` on that event.

### `inbound_limit_test.rs` — the declared `max_inbound_bytes`

`MAX_CUT_TEXT_LEN` driven from the wire after a real RFB 3.8 handshake, on the in-process
harness in `tests/helpers/inbound_limit.rs` (a mock model that counts calls): a
`ClientCutText` of exactly `MAX_CUT_TEXT_LEN` bytes reaches the model; a header declaring
`MAX_CUT_TEXT_LEN + 1` gets the connection closed with zero model calls; a fresh connection's
`ClientCutText` is still answered. Verified by removing the `length > MAX_CUT_TEXT_LEN` check:
the connection then stays open waiting for the payload and the test fails.

## Expected runtime

~1.5 s for the whole suite against the mock harness.

## Not covered

VNC authentication (type 2), compressed encodings, `SetPixelFormat` honouring, damage-tracked
partial updates, `vnc_disconnect_client`, multiple simultaneous clients, and a real graphical
viewer (none is installed in this environment; macOS Screen Sharing requires VNC-Auth).

## Manual testing

```bash
./cargo-isolated.sh run --no-default-features --features vnc --release
# prompt: "listen on port 5900 via vnc showing a dark blue desktop with the text Hello"
vncviewer localhost:5900
```
