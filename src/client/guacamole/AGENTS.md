# Guacamole client (of guacd)

The server's framing in the client role: NetGet asks guacd for a VNC/RDP/SSH/telnet session
and drives it.

`connect()` runs the handshake:
- `select <protocol>`, then reads `args`;
- sends `size` (startup `width`/`height`), empty `audio`/`video`, `image png jpeg`, and
  `timezone UTC`;
- sends `connect` with each named parameter taken from startup `arguments`, and the version
  answered as `VERSION_1_3_0`.

An `error` instead of `args` or `ready` fails the connect.

## The reader task

Rust answers what needs no decision:
- every `sync` is echoed back;
- every `blob` and `clipboard` stream is acked;
- drawing instructions are counted (`display_updates`), not decoded. The handler cannot see
  the screen.

It raises:
- `guacamole_ready` at the first `sync`, with the display size and name;
- `guacamole_clipboard_received` when a clipboard stream ends;
- `guacamole_error`. For example, guacd answers 519 when the VNC server is unreachable,
  after `ready`.

**Batching (on by default).** guacd pushes clipboard changes and errors whenever it likes, so
they can queue in the event channel while the model answers an earlier one. With batching on
the dispatcher takes everything waiting when a call returns (up to `MAX_BATCH_EVENTS`) and
answers it in one `call_llm_for_client_batch` call, one event per instruction; with it off,
one event per call. The follow-up depth of a batch is its deepest event's.
`tests/client/guacamole/batching_test.rs` drives a guacd written in the test, off and on.

## Actions

- `guacamole_type`: each character pressed and released; `\n` is Return.
- `guacamole_key`: named keys, F-keys, characters, or `0x` keysyms.
- `guacamole_click`
- `guacamole_move`
- `guacamole_clipboard`
- `disconnect`: sends `disconnect`.

`actions::instructions` validates before anything is sent. A handler chain stops after 8
follow-ups.
