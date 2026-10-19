# SPICE client

**Status**: `DevelopmentState::Experimental`. One independent server drives it (QEMU's
spice-server), in a test that fails rather than skips; tshark's spice dissector reads every
channel clean. The client bar asks for real sessions against a third-party server and the model's
answer on the wire, which `tests/client/spice/real_server_test.rs` shows, but the pair job had not
run in CI when this was written and nobody has reviewed it.

Same feature (`spice`) and the same wire code as the server (`crate::server::spice::wire`,
`keys`).

## Connect

`connect()` links, inside `CONNECT_TIMEOUT` (30 s): main (connection id 0, `NAME_AND_UUID`),
reads until `MAIN_INIT` (session id, mouse modes), sends `ATTACH_CHANNELS` (and
`MOUSE_MODE_REQUEST` client if supported and not current), reads until `CHANNELS_LIST`, then
links display 0 and inputs 0 with the session id. Each wait reads at most `MAX_SETUP_MESSAGES`
(256) messages. PINGs are answered, NAME and NOTIFY kept, during setup. A refused link is an
error naming `SPICE_LINK_ERR_*` (QEMU's wrong password: "permission denied"). There is no
default port; `spice://host:port` and `host:port` are accepted.

On the display channel it sends `DISPLAY_INIT` (pixmap cache announced as `MAX_CACHE_BYTES`/4
pixels) and, when the server offers `PREF_COMPRESSION`, `PREFERRED_COMPRESSION` OFF.
spice-server honours it: QEMU then sends only uncompressed bitmaps, which is why a reading of a
QEMU screen is exact.

## Running

One reader task per channel: `SET_ACK` → `ACK_SYNC` and an `ACK` every window (spice-server
stops sending after a window unacknowledged), `PING` → `PONG`, `NOTIFY` → `spice_notify`
(sanitized with `utils::sanitize::line_field`), `MAIN_MOUSE_MODE` updates the mode, display
messages go to `display::DisplayModel`. Any channel ending ends the session with its reason.
The session task owns input and screen reads; `run_turns` asks the model, follow-ups bounded
by `MAX_FOLLOWUP_DEPTH` (8), turn queue 64.

**Batching (on by default).** Notifications and surface changes are pushed by the server and
can queue while the model answers. With batching on `run_turns` takes everything waiting
(up to `MAX_BATCH_EVENTS`, skipping events past the depth bound) and answers it in one
`call_llm_for_client_batch` call, one event per message; with it off, one per call.
`tests/client/spice/batching_test.rs` drives a main-channel server written in the test.

## What the model does

| Action | Wire |
|---|---|
| `spice_type{text}` | `KEY_DOWN`/`KEY_UP` per character, shift around shifted ones (US layout; others refused) |
| `spice_keys{keys}` | combos like `ctrl+alt+delete`, pressed in order, released in reverse |
| `spice_mouse{x,y,action,button}` | client mode: `MOUSE_POSITION`; server mode: `MOUSE_MOTION` relative to where this client last put the pointer; then `PRESS`/`RELEASE` |
| `spice_read_screen{grid,settle_ms,points}` | nothing; answers `spice_screen` once no draw arrived for `settle_ms` (at most 10 s more) |
| `disconnect` | closes every channel |

Events: `spice_connected`, `spice_surface_created`, `spice_screen`, `spice_notify`,
`spice_error`, `spice_disconnected`.

## The display model (`display.rs`)

Applied exactly to the primary surface: `SURFACE_CREATE`/`DESTROY`, `DRAW_FILL` (solid brush,
PUT), `DRAW_COPY` of BITMAP (32-bit, RGBA, 24-bit; top-down or bottom-up; nearest-neighbour
scaling) or FROM_CACHE images, `BLACKNESS`/`WHITENESS`/`INVERS`, `COPY_BITS`, all through clip
rectangles; the pixmap cache follows `CACHE_ME`, `INVAL_LIST`, `INVAL_ALL_PIXMAPS`. Everything
else is counted in `draw_ops`/`images`, adds to `undecoded`, and makes `exact: false`:
QUIC/LZ/GLZ/JPEG/LZ4 images, patterns, masks, ROPs other than PUT, streams, text, strokes,
composite. A reading is size, dominant colour and share, distinct colours, a grid of each cell's
most common colour, an FNV-1a checksum, sampled points, and the counts.

No decompressor is implemented, so there is no decompression ratio to bound: compressed images
are counted, never expanded.

## Bounds

Message body `MAX_SERVER_MESSAGE_BYTES` (36 MiB, refused before allocation); surface and image
1–4096 a side and at most 4096×2160 pixels, checked before allocating; a bitmap must fit in the
message carrying it; `MAX_CLIP_RECTS` 1024 (each is a pass over its area); 16 monitors; pixmap
cache 64 MiB, oldest evicted; link message 4096 bytes and 64 capability words.

## Not implemented

TLS (`tls-port`), SASL, cursor/playback/record/agent/USB/smartcard channels, image
decompression and video streams, off-screen surfaces (counted, not kept), Unicode typing
(SPICE has none), `KEY_SCANCODE` sending (KEY_DOWN/UP work everywhere).
