# SPICE server

**Status**: `DevelopmentState::Experimental`. Two independent clients drive it in tests that
fail rather than skip (spice-gtk and spice-html5), tshark's spice dissector reads its traffic
clean, but nobody has reviewed it against the spice-protocol headers line by line, there is no
fuzz target, and the `spice` pair job had not run in CI when this was written.

Feature `spice` (= `vnc` + `rsa` + `sha1`). `vnc` is pulled in for one function:
`crate::server::vnc::actions::parse_display_commands`, so the model draws SPICE screens with
the same command vocabulary it draws VNC screens with, and `recursive_decoder_depth_test` keeps
seeing that parser's depth bound where it already looks for it.

No well-known port: SPICE has no IANA registration and neither spice-server nor QEMU has a
default (`tests/well_known_port_declaration_test.rs` says so). QEMU's own examples use 5930.

## Files

| File | What |
|---|---|
| `wire.rs` | Shared with the client: link header/message/reply, the RSA-OAEP ticket, data headers, message numbers, message builders, a bounds-checked `Cursor`, `read_message` (size refused before allocation) |
| `keys.rs` | PC/AT set-1 scancodes both ways: decode (with 0xE0 prefixes, releases, Pause swallowed) to key names and US-layout characters; encode text and named keys |
| `mod.rs` | Accept loop, link stage, sessions, the main / display / inputs channel loops, rendering, `consult` |
| `actions.rs` | Events, actions, metadata, startup parameters |

## Wire

A session is one TCP connection per channel. Each starts with a link: client
`SpiceLinkHeader`+`SpiceLinkMess` → server `SpiceLinkReply` (error, 162-byte SubjectPublicKeyInfo
of an RSA-1024 key, caps) → client `SpiceLinkAuthMechanism` (only if both offered
`AUTH_SELECTION`) → 128-byte ticket → server `u32` link result. Common caps offered:
`AUTH_SELECTION`, `AUTH_SPICE`, `MINI_HEADER`; the mini header (`type u16, size u32`) is used
when the client offered it too, otherwise the 18-byte full header with a per-channel serial.

The ticket is the password plus NUL under RSA PKCS#1 OAEP with SHA-1 / MGF1-SHA-1 (OpenSSL's
`RSA_PKCS1_OAEP_PADDING`). One key per server, generated at spawn on the blocking pool
(spice-server makes one per link; the ticket hides the password from a passive observer and
authenticates nothing about the server either way).

Order of checks, which is deliberate: the reply is sent, the **ticket is checked before the
session id is looked up**, so a client without the password learns nothing about which
sessions exist (`BAD_CONNECTION_ID` only reaches a client that knew the password).

- **main** (connection id 0): ticket → `spice_connection_request` → `MAIN_INIT` (session id,
  mouse modes server|client, current client, no agent), `MAIN_NAME` if the client has
  `NAME_AND_UUID`, then `CHANNELS_LIST` [display 0, inputs 0] on `ATTACH_CHANNELS` and
  `MAIN_MOUSE_MODE` on `MOUSE_MODE_REQUEST`. Closing the main channel closes the session.
- **display**: `SURFACE_CREATE` (surface 0, 32-bit xRGB, PRIMARY), then each frame as **one**
  `DRAW_COPY` of an uncompressed top-down 32-bit bitmap covering the surface, then `MARK` after
  the first. One message per frame matters: spice-gtk's `spicy-screenshot` writes its file on
  the first invalidation, and a frame split into strips was captured one strip in. Client
  messages (DISPLAY_INIT, ACKs, preferences) are read and ignored.
- **inputs**: `INPUTS_INIT`, then `KEY_DOWN`/`KEY_UP` (scancode bytes packed in a `u32`, lowest
  first), `KEY_SCANCODE`, `MOUSE_POSITION` (client mode), `MOUSE_MOTION` (server mode, tracked
  and clamped), `MOUSE_PRESS`/`RELEASE`. `MOUSE_MOTION_ACK` every 4 motions — spice-gtk stops
  sending motion after 8 unacknowledged ones.

## What the model does

| Event | When | Actions |
|---|---|---|
| `spice_connection_request` | main channel linked, ticket good (or no password configured) | accept, reject, render, notify |
| `spice_display_ready` | display channel attached and no frame exists yet | render, no_change, notify, disconnect |
| `spice_key_event` | a non-modifier key goes **down** | render, no_change, notify, disconnect |
| `spice_mouse_event` | a mouse button goes **down** | render, no_change, notify, disconnect |

Only `spice_accept_connection` admits; a render without it is not an admission. A render on the
admission is the session's first screen, so a typical session costs one model call before the
user sees something. Releases and pointer motion are logged (`Sink::Both`), not modelled.

The password is a startup parameter (redacted wherever parameters print), checked in Rust; the
event says only `password_configured`. Frames are per session.

## Failing closed

Every outcome logs one `decision=` line.

| Situation | Wire | Log |
|---|---|---|
| Wrong ticket | link result `PERMISSION_DENIED`, no model call | WARN `decision=protocol_reject_bad_ticket` |
| Admission: backend down / nothing usable / refused action | `PERMISSION_DENIED` | `fail_closed_llm_error` / `model_silent` / `fail_closed_bad_action` |
| Admission: reject or disconnect | `PERMISSION_DENIED` | `model_reject` |
| First screen without a usable answer | placeholder frame (`PLACEHOLDER_BACKGROUND`, fixed caption) | as above |
| Input without a usable answer | **last frame kept**, `NOTIFY` WARN `NO_ANSWER_NOTICE` (fixed text) | as above |
| Bad magic / version / size / caps | error-only link reply | WARN `decision=protocol_error` |
| Message body over `MAX_CLIENT_MESSAGE_BYTES` | channel closed before the body is read | WARN `decision=fail_closed_message_too_large` |

Why the input case keeps the frame: SPICE's display is server-push, nothing is waiting on an
answer, and painting a placeholder over a screen the user is working in would destroy what the
model last decided. The NOTIFY keeps "no answer" distinct from `spice_no_change` on the wire.
Nothing NetGet knows (error text, backend names) reaches the peer: captions and the notice are
constants.

## Bounds

`MAX_LINK_BYTES` 4096 and 64 capability words per list on the link; `MAX_CLIENT_MESSAGE_BYTES`
64 KiB per message (the declared `max_inbound_bytes`); 30 s to the first byte, 1800 s between
messages afterwards (a viewer watching a still screen says nothing on any channel); 256
connections counting every channel. Surface 16–4096 a side and at most 3840×2160 pixels; 256
drawing commands, window nesting 4 (VNC's parser); notifications 1024 bytes.

## Limitations

No TLS port, no SASL, no cursor / playback / record / agent / USB / smartcard channels, no
image compression or streams (every frame is `width*height*4` bytes), one display and one
surface, whole-frame redraws only. Key releases and motion never reach the model. The drawing
verbs injected from the dashboard are not executed (a frame belongs to the session's display
channel); `close_connection` is.
