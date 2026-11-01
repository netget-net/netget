# USB FIDO2 E2E Tests

## What these prove, and what they do not

One question: *the model is the button on a security key — does approving actually create a
credential, and does denying actually refuse?*

The tests drive a **real USB/IP client over TCP** (`tests/helpers/usbip_client.rs`) and a
**CTAPHID client written against the wire format** (`ctaphid_client.rs`): `OP_REQ_IMPORT`, then
64-byte HID frames carrying CTAP2 CBOR and CTAP1 APDUs. Every CBOR structure is decoded
independently with `serde_cbor`, and the assertion signatures are verified with `ring` against
the public key the authenticator itself produced during registration.

**This is the device side only.** There is no `vhci-hcd`, no `/dev/hidraw*`, no libfido2 and no
browser — macOS has no USB/IP client, which is why the protocol is spoken directly. A passing run
means netget puts the right CTAP bytes on the wire and the model's decision is what determines
whether it does. It does **not** mean Chrome completes a WebAuthn ceremony against it, and it
does not mean `fido2-token -I /dev/hidraw0` works. Both remain untested.

## What this suite replaced, and why it matters

Fourteen tests. Twelve exercised `Ctap2CredentialStore`, `CtapHidHandler` and `ApprovalManager`
in isolation; two were `#[ignore]`d stubs containing only comments. **Not one of them connected
to the server.**

They passed throughout the entire period in which:

- the protocol had no LLM integration at all (`spawn_with_llm_actions` ignored `_llm_client` and
  `_app_state`),
- `get_sync_actions()` returned `vec![]`, so the model had no vocabulary,
- all three declared events had zero emit sites,
- `execute_action("approve_request")` **panicked** with *"Cannot block the current thread from
  within a runtime"* — the action the events' own examples told the model to use,
- and three CTAP2 response encodings were wrong in ways any real client rejects.

The file header even carried a stale BLOCKED banner claiming the feature did not compile.

The lesson is the one the root `AGENTS.md` keeps repeating: a suite that never opens a socket
constrains nothing about the protocol. The unit tests worth keeping are still at the bottom of
`e2e_test.rs` — PIN retry accounting, resident-key bookkeeping, CTAPHID fragmentation at its
exact limits — because those are awkward to reach over the wire. They were just never the thing
that could have caught any of the above.

## The CTAPHID client (`ctaphid_client.rs`)

Written against CTAP 2.1's HID transport section, **not** against netget's own `ctaphid` module.
Framing a request with the code under test and parsing the reply with the same code proves only
self-consistency.

At the USB/IP layer an interrupt transfer is indistinguishable from a bulk one — both are
`USBIP_CMD_SUBMIT` carrying an endpoint *number* — so the FIDO HID endpoints (IN `0x81`, OUT
`0x01`) are driven with `UsbIpClient`'s `bulk_in` / `bulk_out`.

- `attach` / `init` — import, then allocate a channel and check the nonce came back.
- `ping`, `cbor`, `msg`, `transact` — commands, with fragmentation and reassembly.
- `ctap2_get_info`, `ctap2_make_credential`, `ctap2_get_assertion` — CBOR request builders.
- `u2f_register`, `u2f_authenticate`, `parse_u2f_registration` — CTAP1 APDU builders and parser.

**KEEPALIVE is counted, not just skipped.** netget holds the host on `KEEPALIVE(UPNEEDED)` while
the model decides, as a real key does while waiting for a finger. Every reply carries
`keepalives`, and the tests assert on it in both directions: `> 0` where presence is required,
`== 0` for GetInfo and for check-only U2F authentication. "Did the device say it was waiting, or
did it just go quiet?" is exactly the distinction that matters here.

## Tests

| Test | Proves | LLM calls |
|---|---|---|
| `test_fido2_model_approval_produces_a_working_credential` | INIT capability bits follow `support_u2f`/`support_fido2`; PING round trips across frames; GetInfo advertises both versions and a 16-byte AAGUID with no KEEPALIVE; MakeCredential under approval yields `fmt="none"`, authenticator data whose RP hash is `SHA-256("example.com")` with UP+AT set and a decodable COSE_Key; GetAssertion names that credential, advances the counter, and **its signature verifies against the credential's own public key**; U2F REGISTER and AUTHENTICATE likewise, with the U2F signature verified; check-only U2F authentication raises no approval | 6 |
| `test_fido2_denial_and_silence_both_refuse` | An explicit `deny_request` yields `CTAP2_ERR_OPERATION_DENIED` (0x27) with an empty payload, and a subsequent GetAssertion reports `CTAP2_ERR_NO_CREDENTIALS` (0x2e) — so nothing was created before the decision. A model that answers with `notify_operator` and no decision produces the **same denial** after `approval_timeout_secs`, and likewise stores nothing | 4 |
| `test_approval_manager_contract` | `open`/`approve`/`deny`/`list_pending` work from a synchronous context with no runtime handle; resolving an unknown id is an error, not a silent success; an unanswered request denies | 0 |
| `test_pin_uv_support`, `test_pin_required_for_uv`, `test_resident_keys` | PIN retry counter and length limits; UV requires a *verified* PIN; credential counting and deletion across relying parties | 0 |
| `test_ctaphid_*` (5) | Fragmentation at 1, 3 and 129 frames; lossless reassembly; out-of-order continuation is an error | 0 |

**LLM budget: 10 calls**, at the project ceiling. Both network tests reuse one server and one
USB/IP session for every scenario in them.

The signature verification in the first test is the load-bearing assertion. It can only pass if
the private key was really generated, really stored against that relying party, and really used
to sign the exact bytes the host would sign — which is why it is worth two `ring` calls rather
than an assertion that the status byte was zero.

## The refusal test is the more important one

A security key that cannot say no is not a security key, and the failure mode this codebase keeps
producing is fail-open: a model that returns nothing usable falling through to a permissive
default. `test_fido2_denial_and_silence_both_refuse` pins **both** shapes — an explicit denial
and a non-answer — to the same outcome, and then checks the store is empty afterwards so that a
key pair generated *before* the decision would be caught.

It runs with `approval_timeout_secs: 3` so the silence case does not spend the 30s default.

## Synchronisation

Both network tests wait for `"USB FIDO2 LLM call completed (attach)"` before asserting: the attach event follows the peer's `OP_REQ_IMPORT`, not the TCP accept — a bare
connect costs no model call at all (see `src/server/usb/AGENTS.md` and
`tests/server/usb_keyboard/attach_on_import_test.rs`), so the log line is the only
signal that the import has been answered. The
log line puts the event kind *before* the connection id precisely so a test can wait on one
specific event with a substring match.

Approval round trips need no extra synchronisation — the CTAPHID reply cannot arrive until the
decision has been applied, so the `cbor(...)`/`msg(...)` call is the barrier. Their timeouts are
20s, comfortably over the mock's latency and the 15s approval window the first test configures.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features usb-fido2 \
    --test server -- --test-threads=100 usb_fido2
```

About 4 seconds. Needs `libusb-1.0`; not available in Claude Code for Web. **Run it twice**: the
first run after a source edit relinks the `netget` binary the tests spawn.

## Not covered

- A real Linux host: `sudo usbip attach`, `vhci-hcd`, `/dev/hidraw*`.
- libfido2 (`fido2-token -L`, `fido2-cred -M`) and browser WebAuthn.
- Attestation verification — the device sends `"none"`, so there is nothing to verify.
- ClientPIN as a protocol. The PIN tests exercise netget's development-grade PIN (SHA-256 of the
  plaintext), not PIN protocol v1's ECDH shared secret, and must not be read as conformance.
- `credentialManagement`, `GetNextAssertion` with multiple matches, `hmac-secret`, `credProtect`.
- Two hosts attached at once, and therefore the cross-connection fold in `list_credentials`.
- The `CHANNEL_BUSY` path (a second command while one is parked) and `CTAPHID CANCEL`.
