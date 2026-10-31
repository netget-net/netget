# The USB device family (USB/IP)

Six virtual USB devices, each its own Cargo feature, all sharing one transport: USB/IP over
TCP, spoken by the `usbip` 0.9 crate on the socket NetGet accepted. `common.rs` and
`descriptors.rs` hold the shared constant tables and descriptor builders; `guard.rs` holds the
message screen described below. Everything else is per-protocol:

| feature | directory | device |
|---|---|---|
| `usb-keyboard` | `keyboard/` | HID keyboard |
| `usb-mouse` | `mouse/` | HID mouse (boot protocol) |
| `usb-serial` | `serial/` | CDC ACM serial port |
| `usb-msc` | `msc/` | Mass storage (SCSI over Bulk-Only Transport) |
| `usb-fido2` | `fido2/` | FIDO2 / U2F security key (CTAPHID) |
| `usb-smartcard` | `smartcard/` | CCID smart card reader |

The separate `usb` feature is the USB *client* (`nusb`) in `src/client/usb`, not a server.

## The USB/IP message screen — `guard.rs`

**`usbip` 0.9.0 allocates from two numbers the peer supplies and bounds neither.** In
`UsbIpCommand::read_from_socket`, a `USBIP_CMD_SUBMIT` is a 48-byte header followed by

```rust
let mut data = vec![0; transfer_buffer_length as usize];   // peer-supplied u32
socket.read_exact(&mut data).await?;
```

and, immediately after, `vec![0; 16 * number_of_packets as usize]` — up to ~68 GiB on a 64-bit
host, wrapping on a 32-bit one. USB/IP authenticates **nothing**: `OP_REQ_IMPORT` carries a bus
id and no credential, so 48 bytes from a peer that has not even imported a device ask for
4 GiB, pre-auth and pre-model.

`usbip::handler` is generic over `T: AsyncReadExt + AsyncWriteExt + Unpin`, so — unlike
`nfsserve`, the precedent in `src/server/nfs/guard.rs` — no second listener is needed. NetGet
keeps the real socket, hands the crate a `tokio::io::duplex` pipe, and copies only admitted
messages into it. **Every one of the six protocols goes through
`guard::run_guarded_usbip(stream, server, device, peer, status_tx, on_import, deadlines)`; none
of them calls `usbip::handler` directly.**

The screen reads one whole USB/IP message at a time and decides it from the numbers the peer
*announced*, before the bytes they describe are read and before any arithmetic on them:

| bound | value | why |
|---|---|---|
| `MAX_TRANSFER_BUFFER_BYTES` | 1 MiB | **A NetGet policy choice, not a spec figure** — the field is a bare `u32` and the protocol names no ceiling. HID reports are 4-8 bytes, CTAPHID frames 64, CCID messages a few hundred; the largest legitimate transfer here is an MSC data phase, well inside this |
| `MAX_ISO_PACKETS` | 1024 | This one *is* the number other implementations use: the Linux kernel's own USB/IP stub defines `USBIP_MAX_ISO_PACKETS` as 1024 in `drivers/usb/usbip/usbip_common.h` and rejects more on the submit path in `stub_rx.c`. No device here declares an isochronous endpoint, so a working session only ever sends the two exempt values `0` and `0xFFFFFFFF` |
| `URB_BODY_TIMEOUT` | 30s | A message the peer has *begun* and then stalled on — the rest of its fixed header, and a payload it announced. The tail read used to have no bound at all, so four bytes held a connection for as long as the peer liked |
| `DEFAULT_FIRST_MESSAGE_TIMEOUT` | 30s | A peer that has only completed a TCP handshake. **Short, unlike the 300 seconds `tcp`/`telnet`/`ldap`/`whois`/`redis` settled on**, because the peer those protect — NetGet's own client parked at `[ send message ]` — cannot exist here: NetGet has no USB/IP client, `src/protocol/dual.rs` deliberately pairs no `USB-*` server with the generic USB client, and no event can park in front of the first message because the attach event follows `OP_REQ_IMPORT`. USB/IP is client-speaks-first, so a silent peer is waiting for nobody |
| `DEFAULT_IDLE_TIMEOUT` | 1800s | A peer that has spoken and then gone quiet. **Deliberately long**: USB/IP has no keepalive, nothing obliges an attached host to say anything, and a drive a host has imported and not mounted issues no URB at all — so this reaps a peer that is *gone* rather than policing one that is present. Closing an idle attached host would be the live-transfer eviction the project `AGENTS.md` records TFTP learning about |

The last two are startup parameters (`first_byte_timeout_secs`, `idle_timeout_secs`) on all five
of `usb-keyboard`, `usb-mouse`, `usb-msc`, `usb-serial` and `usb-smartcard`; `usb-fido2` takes
the defaults and declares no knob. Each protocol declares them in its own
`get_startup_parameters()` — an undeclared key is refused at startup — and reads them in its own
`spawn()`, which is what `tests/startup_param_drift_test.rs` looks for.

**The deadline covers the read and nothing else, and that is easier to guarantee here than
elsewhere in the tree**: every `UsbInterfaceHandler::handle_urb` under `src/server/usb/` is
synchronous and answers out of state the connection already holds, so no URB ever waits on an
LLM round-trip or on a 300-second `manual` park. The model call an event raises runs in the
connection task beside the screen's loop, never in front of a reply.

`tests/helpers/usbip_bounds.rs` drives both bounds from a raw socket and each protocol's
`tests/server/usb_*/connection_bounds_test.rs` calls it. Verified by removal: take the deadline
off the head read and all ten checks fail on their own windows; collapse the two bounds onto the
short one and the five idle checks fail, along with the one that holds an attached-and-quiet
host open past 30 seconds.

Two more things are refused, and both are the same class of defect one level down: the crate
`debug_assert!`s that `direction` is a single bit and that an operation-code message's `status`
is zero, so in any debug or test build either one is a **panic raised from the wire, pre-auth**,
swallowed by `tokio::spawn` while the peer hangs. The screen refuses both. An unknown command
word is refused too, so it is the screen and not the crate that decides what is USB/IP.

**A refusal closes the connection, and that is a real limitation rather than the only option.**
`USBIP_RET_SUBMIT` has a `status` field that could carry `-EINVAL`, but a well-formed reply also
has to echo the `seqnum` and `devid` of a URB the crate never saw, into a reply stream the crate
owns and multiplexes. Writing one from underneath would interleave. So the screen closes and the
log carries the reason: an ERROR with a stable tag —
`decision=fail_closed_oversized_urb`, `_oversized_iso`, `_unknown_command`, `_unknown_version`,
`_invalid_direction`, `_nonzero_status`, `_urb_stalled` — in the shape `src/server/radius/`
established.

Each protocol declares the bound to the model and the operator with
`.max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)` in its `metadata()`.

`tests/server/usb_msc/guard_test.rs` drives both bombs from the wire, and both were verified by
removing the guard from `msc/mod.rs`: unguarded, the 4 GiB allocation happens, no refusal is
logged, and both tests fail on the missing `decision=` tag.

## The connection cap — and the refusal that cannot be spoken

Every accept loop here goes through `crate::server::accept_bounded` with
`guard::MAX_USBIP_CONNECTIONS` (**32**), and the `ConnectionPermit` is moved into the connection
task (`let _permit = permit;`) so a slot is held for exactly as long as the device is exported.

32 rather than the shared `DEFAULT_MAX_CONNECTIONS` of 256, because a USB/IP connection is not a
request — it is an entire emulated device: a `usbip::UsbIpServer`, a live `UsbInterfaceHandler`
with its own session state (a CCID card, a FIDO2 credential store, a memory-mapped MSC disk),
an `AppState` connection entry, and up to `MAX_TRANSFER_BUFFER_BYTES` in flight. It is also not
a number a working deployment approaches: a virtual device is imported by *one* host, and the
only reason this is not 2 is that a host reconnecting while the previous session winds down, and
a test harness opening several at once, are both ordinary. At 32 the 1 MiB transfer bound
multiplies into 32 MiB rather than 256 MiB.

**The refusal is a plain close, and `guard::USBIP_NO_REFUSAL` is the empty slice that says so.**
USB/IP has no "busy", "try later" or "too many clients" message; its only server-to-client
messages are `OP_REP_DEVLIST`, `OP_REP_IMPORT` and the URB replies, each a positive assertion
about a device. `OP_REP_IMPORT` with a non-zero status is the closest thing to a refusal, and
sending one unprompted would be answering a question the peer has not asked — a peer that has
only completed a TCP handshake has asked nothing. So the reason lives in the log, at WARN, under
`decision=fail_closed_connection_cap`, and that log line is the diagnosis.

`tests/server/usb_keyboard/connection_cap_test.rs` fills the cap from the wire, asserts the next
connection is closed, asserts the server still exports its device afterwards, and asserts that
releasing one connection frees exactly one slot — a permit dropped early un-caps the server
silently, and a permit never released wedges it shut after 32 peers have *ever* connected.

## The attach event follows `OP_REQ_IMPORT`, not `accept()`

Every server here used to make its `*_attached` LLM call the moment `accept()` returned. A TCP
handshake therefore bought a model round-trip on a protocol with no authentication, and closing
the socket bought a second one for `*_detached`: `nc`, a health check or a port scanner spent
the operator's model budget without speaking a word of USB/IP.

The screen already classifies every inbound message, so it is the one place that knows when a
peer has asked for the device. `run_guarded_usbip` takes a `oneshot::Sender` and fires it on the
first **admitted** `OP_REQ_IMPORT`; each server hangs its attach event on that receiver inside
its existing `select!` loop, and raises `*_detached` only if the import actually happened.
`OP_REQ_DEVLIST` deliberately does not fire it — listing what a host exports is not attaching to
it, and it is exactly the enumeration a scanner would do.

Two details are load-bearing in each server: the receiving `select!` arm carries an
`if import_pending` guard, because a `oneshot::Receiver` polled after it has resolved panics and
`tokio::spawn` would swallow that panic; and the sender is dropped when the session ends, so a
peer that never imported resolves the receiver with `Err` and is correctly recorded as never
having attached.

A third: the session task the `select!` awaits is held in `utils::task_guard::AbortOnDrop` and
awaited as `usbip_task.0`. The connection task is the one `stop_server` aborts, and aborting it
drops the session's `JoinHandle`, which detaches the session rather than ending it, so without
the guard a stopped server's USB/IP sessions kept their sockets.
`tests/stop_server_stops_connections_test.rs::stopping_a_usb_server_disconnects_a_live_peer`
(built with `libusb`) asserts it from the peer's side for all six servers.

`tests/server/usb_keyboard/attach_on_import_test.rs` measures the cost directly — three silent
connects and a devlist cost **zero** model calls, one `OP_REQ_IMPORT` costs **one** — and
`tests/usb_accept_and_attach_ratchet_test.rs` holds both properties across all six servers by
reading source, so it applies at any feature set.

### What is still unguarded

- **Only framing is screened, not USB semantics.** An admitted URB still reaches the protocol's
  own `UsbInterfaceHandler`, which decides whether the endpoint, the setup packet and the
  payload make sense. A 1 MiB URB on an 8-byte interrupt endpoint is the handler's problem.
- **An admitted session is bounded at half an hour, not at a minute.** That is the right
  number for a host that has imported a device (see `DEFAULT_IDLE_TIMEOUT`), but it does mean a
  peer that sends one valid `OP_REQ_DEVLIST` buys 1800 seconds of a slot rather than 30. Lower
  `idle_timeout_secs` on a listener exposed to strangers.
- **Nothing bounds how *many* messages a peer sends.** Each is individually small and the
  screen holds none of them, but a peer can submit URBs as fast as it likes and each admitted
  one is work for the protocol's handler — and, where the handler raises an event, a model call.
