# USB FIDO2/U2F Security Key Server Implementation

## Overview

A virtual FIDO2/U2F security key exported over USB/IP. The device presents an HID interface
(class 0x03) speaking CTAPHID, and answers CTAP1 (U2F) and CTAP2 (FIDO2) commands with real
ECDSA P-256 cryptography.

The model's job is the one a human does on a real key: **approve or deny** each registration and
each authentication. That is the whole point of the protocol here — it is a policy decision about
a named relying party, which is what an LLM is actually good at, rather than a byte-level
transformation, which it is not.

**State: Experimental.** See *What is and is not verified* before trusting anything below.

## Layout

| File | What it does |
|---|---|
| `mod.rs` | Accept loop, USB/IP session, `Fido2HidHandler`, the four events, `Fido2ServerHandle` |
| `ctaphid.rs` | CTAPHID transport: 64-byte frames, channel allocation, fragmentation, KEEPALIVE |
| `u2f.rs` | CTAP1: REGISTER, AUTHENTICATE, VERSION, and the U2F credential store |
| `ctap2.rs` | CTAP2: MakeCredential, GetAssertion, GetInfo, ClientPIN, Reset, and the CTAP2 store |
| `approval.rs` | The user-presence decision: open / wait / approve / deny |
| `actions.rs` | Actions, events, metadata, `execute_action_with_state` |

## Four things that were broken, and are worth remembering

This protocol was registered, rated `Experimental`, shipped in `all-protocols`, and **could not
work in any way**.

**1. There was no LLM integration at all.** `spawn_with_llm_actions` took `_llm_client` and
`_app_state` and used neither. `get_sync_actions()` returned `vec![]` and the protocol did not
delegate, so the model had no vocabulary for any event. All three declared events had zero emit
sites. The protocol could not answer anything, and the guard that was supposed to catch exactly
this (`audit_event_action_declarations`) **early-returned when `get_sync_actions()` was empty** —
so it passed hardest on the most broken protocol in the tree. That hole is fixed; see
`src/llm/actions/protocol_trait.rs`.

**2. The model-facing actions panicked.** `execute_action({"type":"approve_request"})` did
`tokio::runtime::Handle::current().block_on(...)` — *"Cannot block the current thread from within
a runtime"* — and the events' own `response_example` taught the model to answer with exactly that
action. The CTAP2 handler did the same thing on every MakeCredential and GetAssertion. This is
the same defect documented in `src/server/usb/msc/handler.rs`: `usbip` calls the synchronous
`UsbInterfaceHandler::handle_urb` from a tokio worker, so **the whole handler path must be
synchronous**. `approval.rs` now uses `std::sync` locks throughout and `oneshot::Sender::send`,
which is itself synchronous, so nothing on the action path needs a runtime handle.

**3. `spawn` could not report failure.** `usbip::server(listen_addr, …)` was called *inside*
`tokio::spawn`, after `Ok(listen_addr)` had already been returned. A port conflict was invisible
and the server sat in `Running` having bound nothing. It binds first now, exactly as every other
USB protocol does, and runs `usbip::handler(&mut stream, server)` on the socket netget accepted.

**4. The approval manager was global and mis-scoped.** A `LazyLock<RwLock<HashMap<ServerId, …>>>`
whose lookup was `values().next()` — with two FIDO2 servers running, an action aimed at one
resolved approvals on the other — and nothing ever removed an entry. It is now a
`Fido2ServerHandle` registered with `AppState::register_server_handle` and looked up by
`server_id` in `execute_action_with_state`, so it is scoped correctly and dies with the server.

## How approval works without blocking

CTAPHID is asynchronous by design; that is what its `KEEPALIVE(0x02 = UPNEEDED)` status exists
for. A real key sends it while the user decides whether to touch the button.

```text
 host                     handler (sync)              connection task (async)
  │  CBOR MakeCredential      │                              │
  ├──────────────────────────►│  parse, needs user presence  │
  │                           ├── ApprovalDetails ──────────►│  approvals.open() → id
  │◄── KEEPALIVE(UPNEEDED) ───┤                              │  raise fido2_register_request
  │  (keeps polling IN)       │                              │  call_llm → approve_request
  │                           │◄──── resolve(Approved) ──────┤  approvals.wait() → decision
  │◄── CBOR response ─────────┤  replay the command          │
```

Three properties fall out of this and are worth stating explicitly:

- **Nothing happens before the decision.** The handler parses the command, answers the
  *question*, and replays it only once a decision exists. A denial therefore leaves the
  credential store byte-for-byte as it was — no key pair is generated, no counter moves. The
  E2E tests assert this by asking for an assertion afterwards and requiring
  `CTAP2_ERR_NO_CREDENTIALS`.
- **Replay is safe** because parsing is pure. The parked command is the raw request bytes; there
  is no half-executed state anywhere.
- **A second command while one is parked gets `CTAPHID ERR_CHANNEL_BUSY`.** Silently replacing
  the parked command would apply a decision meant for the first request to the second.
  `CTAPHID CANCEL` drops the parked command instead, which is what a host that has moved on
  expects.

### Fail-closed

`timeout_decision` is `Denied` and there is no path that turns a missing answer into an approval:

| What the model does | What the host sees |
|---|---|
| `approve_request` with the event's `approval_id` | the operation succeeds |
| `deny_request` | `CTAP2_ERR_OPERATION_DENIED` (0x27), or U2F `SW_CONDITIONS_NOT_SATISFIED` |
| anything else, or nothing, or an LLM outage | denied after `approval_timeout_secs` |

An explicit denial is structurally distinct from silence — a different action, logged as a
decision — which is the property the OAuth2 post-mortem in the root `AGENTS.md` says to preserve.

`auto_approve` exists, defaults to **false**, and has to be named in `startup_params`. It
short-circuits `wait()` and never asks.

## Which commands need user presence

| Command | Presence? | Why |
|---|---|---|
| CTAPHID INIT, PING, WINK, CANCEL | no | transport |
| CTAP2 GetInfo, ClientPIN, Reset, GetNextAssertion | no | no credential is created or used |
| CTAP2 MakeCredential | **yes** | creates a credential |
| CTAP2 GetAssertion | **yes**, after the credential lookup | signs |
| U2F REGISTER | **yes** | creates a credential |
| U2F AUTHENTICATE, `P1 = 0x03` | **yes**, after the key-handle check | signs |
| U2F AUTHENTICATE, `P1 = 0x07` (check-only) | **no** | a browser probes with check-only *before* it prompts; asking here would raise a spurious approval per probe |

GetAssertion locates credentials **before** collecting presence, per CTAP 2.1 §6.2.2 (step 9
before step 11). Beyond spec conformance that ordering avoids spending an LLM round trip on a
request the key could not have satisfied anyway. U2F AUTHENTICATE does the same with the key
handle.

## Wire-format corrections

Three encodings were wrong in ways a real client would have rejected immediately, and were only
invisible because nothing had ever spoken CTAP to this device:

- **MakeCredential response.** Was: a whole WebAuthn *attestation object* serialised into key
  `0x02`, with the AAGUID in `0x03`. CTAP 2.1 §6.1.2 says `0x01` fmt, `0x02` **authenticator
  data**, `0x03` **attStmt map** — the attestation object is what the *client* assembles from
  those three, not something the authenticator sends.
- **Attestation format.** Was `"packed"` with 71 zero bytes as the signature: a claim a relying
  party can check and will reject. It is `"none"` with an empty statement now, which is what
  every flow that does not pin an authenticator model asks for anyway.
- **GetAssertion response key `0x01`.** Was the raw credential id. It is a
  `PublicKeyCredentialDescriptor` map (`{"id": …, "type": "public-key"}`) per §6.2.2.

`capabilities` in the INIT response now follows the support flags: `CBOR` (0x04) is set when
`support_fido2` is on, `NMSG` (0x08) when `support_u2f` is off. It used to be the constant
`0x01`, so a host could not tell what the device would answer — and `support_u2f` /
`support_fido2` were accepted as startup parameters and then ignored entirely.

## Startup parameters

| Parameter | Default | Effect |
|---|---|---|
| `support_u2f` | `true` | answer CTAPHID MSG; clears `NMSG` in the INIT capabilities |
| `support_fido2` | `true` | answer CTAPHID CBOR; sets `CBOR` in the INIT capabilities |
| `auto_approve` | `false` | approve everything without asking (development only) |
| `approval_timeout_secs` | `30` | how long a request waits before being **denied** |

Both protocols off is an error at startup rather than a device that answers only INIT.

All four are optional, so all four are read with `get_optional_*`. `get_bool` **errors** on a
missing key, and mapping it over `startup_params` turned "the caller did not mention
`support_u2f`" into *"Required boolean parameter 'support_u2f' is missing"*, refusing to start a
server whose parameters were all legal. If you add a parameter, use the optional accessor.

## LLM actions

**Sync** (answer an event): `approve_request`, `deny_request`, both taking the `approval_id` the
event carried. `approval_id` is accepted as a number or as a numeric string — a small model
quoting `"1"` would otherwise fail the action, and because an unanswered request denies, that
would silently convert an approval into a denial.

**Async**: `list_pending_approvals`, `list_credentials`, `delete_credential`.

`list_credentials` reports relying party, user name, resident flag and signature counter across
every attached host — **never** a credential id, key handle or key material, because its output
reaches the model and the log. `Fido2HidHandler`'s `Debug` is hand-written and prints only the
type name for the same reason.

`save_credentials` and `load_credentials` were removed. They logged a line and returned
`NoAction`; and credential persistence would be storage implemented inside a protocol, which the
project rule forbids.

## LLM events

- `fido2_device_attached` — a host imported the device. Informational, `with_no_actions()`.
- `fido2_register_request` — `connection_id`, `approval_id`, `rp_id`, `user_name`,
  `credential_count`. Answer `approve_request` / `deny_request`.
- `fido2_authenticate_request` — same fields. Same two actions.
- `fido2_device_detached` — the session ended. Informational, `with_no_actions()`.

`rp_id` is a real domain for CTAP2. U2F only carries the SHA-256 of the origin, which is not
reversible, so it is reported as `u2f-app:<first 8 hex>` and the parameter description says so
rather than pretending to know the domain.

## Hostile input

An unavailable approval channel denies a presence request through a single direct CTAP/U2F
replay with `UserPresence::Denied`. It never calls back into `run_command` or `park`. If a
protocol handler incorrectly requests approval again after denial, the leaf helper returns
the protocol's denial response immediately (U2F `0x6985`, CTAP2 `0x27`). The call graph is
acyclic rather than relying on an enum variant to terminate recursion.

`tests/audit_server_decoder_bounds_test.rs` drives the real `UsbInterfaceHandler` entirely in
memory: absent/closed approval channels, approved/denied registrations, busy requests, malformed
payloads, and maximum/excess CTAPHID lengths. It never opens USB/IP, enumerates USB devices,
or calls a model; the existing wire tests below cover a different integration layer.

Everything on the interrupt OUT endpoint arrives from whoever attached over USB/IP, before any
user-presence decision has been made. Two bounds in `ctaphid.rs` exist because it was not:

- **`MAX_MESSAGE_SIZE` (7609).** `BCNT` is 16 bits, so a host may declare 65535 bytes, but a
  CTAPHID message is one initialization packet plus at most 128 continuations — the sequence
  number is 7 bits — and 57 + 128 * 59 is the specification's own `MAX_MSG_SIZE`. A larger
  declaration is malformed by that arithmetic and is refused with `CTAP1_ERR_INVALID_LEN`.
- **`MAX_ASSEMBLING_CHANNELS` (4).** The channel id is a field in the packet, not something the
  device hands out, so a peer may invent as many as it likes. Only a *partially* assembled
  message retains anything, so only that path is capped; re-initializing a channel that is
  already assembling replaces its buffer and is free.

Together these close a memory-exhaustion route that cost the attacker almost nothing:
`CtapHidMessage::new` called `Vec::with_capacity(bcnt)` before a single continuation packet
arrived, and the buffer lived until the message completed — which a host that simply stops
sending never does. One 64-byte packet reserved up to 64 KiB, on unlimited channels,
indefinitely. Nothing is pre-allocated from the declared size now; the buffer grows with the
bytes that actually arrive.

The same arithmetic bounds the outbound direction. `fragment_response` refuses a reply past
`MAX_MESSAGE_SIZE` with one `INVALID_LEN` frame rather than wrapping `seq` back to 0 and
truncating `BCNT` through `as u16`, which produced a well-formed-looking answer that decoded to
something else. And a refusal now carries the channel and the code it belongs to
(`CtapHidRejection`, read back with `ctaphid::rejection_of`) instead of being reported as
`INVALID_SEQ` on the broadcast channel, which is the wrong code on a channel the host is not
listening to.

`tests/server/usb_fido2/e2e_test.rs` pins both bounds, and pins that a message *at* the maximum
still fragments into its 129 packets — a guard that refused everything would satisfy the first
assertion while breaking the protocol.

**CTAP2 parameters reach `serde_cbor` only through `utils::cbor_depth::decode_bounded`.**
`Ctap2Request::parse` used to call `serde_cbor::from_slice` on whatever followed the command
byte. serde_cbor 0.11 stops itself at 128 levels, but a debug build spends ~7 KiB of stack a
level getting there, one byte of input per level. The scan in `src/utils/cbor_depth.rs` walks
the item iteratively first and refuses, before anything is decoded or allocated: nesting past
`MAX_CTAP2_CBOR_DEPTH` (8; CTAP 2.1 §8 allows four), a string, array or map declaring more than
the bytes present, indefinite-length items (CTAP2's canonical encoding forbids them), and bytes
after the item. Every refusal answers `CTAP2_ERR_INVALID_CBOR` (0x12) and logs
`decision=refused_invalid_cbor` with the reason. The guard lives outside the `libusb` tree on
purpose: `tests/ctap2_cbor_depth_test.rs` and `fuzz/fuzz_targets/ctap2_cbor.rs` reach the
server's exact decode path in every build, where nothing behind `libusb` can be fuzzed (nusb,
see `fuzz/Cargo.toml`).

## What is and is not verified

**Verified**, by `tests/server/usb_fido2/e2e_test.rs` driving USB/IP and CTAPHID directly over
TCP, with all CBOR decoded independently by `serde_cbor`:

- Enumeration, import, CTAPHID INIT (nonce echo, channel allocation, capability bits), PING
  across multiple frames.
- GetInfo: both versions advertised, 16-byte AAGUID, no KEEPALIVE.
- MakeCredential under model approval: `fmt = "none"`, authenticator data whose RP-id hash is
  `SHA-256("example.com")`, UP and AT flags set, AAGUID matching GetInfo, a COSE_Key that decodes
  to a P-256 point.
- GetAssertion under model approval: descriptor names the credential registration created, the
  counter advances, and **the signature verifies with `ring` against the public key the
  authenticator itself produced**. That last one is the assertion that makes the exercise mean
  something — it can only pass if the private key was really generated, stored and used.
- U2F REGISTER and AUTHENTICATE under model approval, with the signature likewise verified;
  check-only authentication raising **no** approval.
- Denial produces 0x27 and stores nothing; silence produces 0x27 and stores nothing, and an
  LLM outage is tagged `decision=fail_closed_llm_error` in the log — the wire cannot tell the
  three apart, so the log has to.
- KEEPALIVE is actually sent while the model decides (`keepalives > 0`).

**Not verified.** Nothing here has ever spoken to a real client:

- No `vhci-hcd`, no `usbip attach`, no `/dev/hidraw*` — macOS has no USB/IP client at all.
- No libfido2 (`fido2-token -I`, `fido2-cred -M`), no browser WebAuthn ceremony.
- Attestation is `"none"`, so a relying party that *requires* attestation gets nothing usable.
- ClientPIN is development-grade: the PIN is compared as SHA-256 of the plaintext, with none of
  PIN protocol v1's ECDH shared secret. Do not read the PIN tests as protocol conformance.
- Credentials do not survive the USB/IP session; there is no `credentialManagement`, no
  `hmac-secret`, no `credProtect`, no largeBlob.
- Multiple hosts attached at once. `Fido2ServerHandle` keeps a handler per connection and
  `list_credentials` folds across them, but no test opens two sessions.

## Build

```bash
./cargo-isolated.sh build --no-default-features --features usb-fido2
```

Needs `libusb-1.0` (the `usbip` crate links it): `brew install libusb pkg-config` on macOS,
`apt-get install libusb-1.0-0-dev pkg-config` on Debian. Not available in Claude Code for Web.

## Testing

```bash
./cargo-isolated.sh test --no-default-features --features usb-fido2 \
    --test server -- --test-threads=100 usb_fido2
```

See `tests/server/usb_fido2/AGENTS.md`.

## Manual testing against a real host (untried)

```bash
# Linux client
sudo modprobe vhci-hcd
sudo usbip list -r <netget-host>
sudo usbip attach -r <netget-host> -b 0-0-0
fido2-token -L
fido2-token -I /dev/hidraw0
fido2-cred -M -h example.com /dev/hidraw0
sudo usbip detach -p 0
```

If you run this, record what actually happened here — including the failures. The value of this
section is that it is currently empty.

## References

- **CTAP 2.1**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- **U2F raw message formats**: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
- **WebAuthn (authenticator data layout)**: https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
- **USB/IP protocol**: https://docs.kernel.org/usb/usbip_protocol.html
- **softfido** (the architecture this was originally modelled on): https://github.com/ellerh/softfido

## USB/IP is screened before the crate sees it

This server does **not** call `usbip::handler` on the accepted socket. It calls
`crate::server::usb::guard::run_guarded_usbip`, which relays the connection into the crate
through an in-memory pipe and decides every inbound USB/IP message first.

The reason is a pre-auth allocation bomb in `usbip` 0.9.0: `USBIP_CMD_SUBMIT` is 48 bytes of
header, and the crate then does `vec![0; transfer_buffer_length as usize]` and
`vec![0; 16 * number_of_packets as usize]` with no bound on either number. USB/IP authenticates
nothing, and the session task is spawned before the attach LLM call, so 48 bytes from a peer
that has not imported anything ask for 4 GiB.

The screen refuses a declared `transfer_buffer_length` over
`guard::MAX_TRANSFER_BUFFER_BYTES` (1 MiB, a NetGet policy choice) and a `number_of_packets`
over `guard::MAX_ISO_PACKETS` (1024, the Linux kernel's own `USBIP_MAX_ISO_PACKETS`), along
with unknown command words, a `direction` that is not a single bit, a non-zero `status`, and a
payload the peer announces and then stalls on. A refusal closes the connection — the screen
sits below the crate and cannot synthesise a `USBIP_RET_SUBMIT` for a sequence the crate never
saw — and logs at ERROR with a `decision=fail_closed_*` tag.

`MAX_TRANSFER_BUFFER_BYTES` is declared in `metadata()` via `.max_inbound_bytes(...)`.
`src/server/usb/AGENTS.md` has the full reasoning, the constants and what is still unguarded;
`tests/server/usb_msc/guard_test.rs` is the wire-level test.
