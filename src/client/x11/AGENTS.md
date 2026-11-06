# X11 client

NetGet as an X client: one connection to an X server over TCP (`remote_addr`, port 6000 +
display) or a Unix socket (`socket_path`, e.g. `/tmp/.X11-unix/X0`). Hand-rolled core protocol
in `wire.rs`; no `x11rb`, no Xlib. Client only: an X server is a large build and not the point.

## What the model gets

- `x11_connected` — vendor, release, protocol version and the chosen screen (root id, size).
- One `x11_result` or one `x11_error` per action. Window ids are written as `xwininfo` prints
  them (`0x200001`); `"root"` names the screen's root window.
- `x11_event` — X events for windows created with `watch` (structure, property, exposure, focus,
  keyboard, pointer). Nothing is watched by default: each event is a model turn.

Actions: create (optionally titled — WM_NAME as Latin-1 STRING and _NET_WM_NAME as UTF8_STRING —
and mapped), map, unmap, destroy, configure (move, resize, raise), get geometry, query tree (each
child with its WM_NAME, up to 256), intern atom, set / get / delete / list properties, list
extensions, bell, disconnect. Property values are structured: strings (an array is stored
NUL-separated, as WM_CLASS is), CARDINAL/INTEGER numbers, ATOM names, WINDOW ids. The property's
type is `property_type`, not `type`, which is the action's own name.

## How an action runs

`Session::perform` executes an action whole: it interns the atoms it needs (predefined atoms
from the table, others cached per connection), sends its requests, then sends GetInputFocus and
waits for that reply. X processes requests in order, so the sync reply proves everything before
it was handled; an error for a reply-less request (MapWindow on a bad id) arrives before it and
is matched to the action by sequence number (`stray_errors`, range-checked with wrapping
arithmetic). Replies are stashed by sequence so query_tree can pipeline one GetProperty per
child. An action that gets no answer within `timeout_ms` ends the connection: after that the
sequence bookkeeping cannot be trusted.

Model turns run in a separate dispatcher task fed by a queue. An event carries a depth (connect
0; an action answering an event of depth d has depth d+1; its result and the X events it causes
inherit that); events at `MAX_FOLLOWUP_DEPTH` (8) are not put to the model, so a handler that
answers every result with another action stops. Injected actions start at depth 0.

## Bounds and refusals

- A reply or generic event announcing more than `MAX_REPLY_BYTES` (1 MiB) is refused from its
  header, before its body is read, and the connection ends.
- Properties: GetProperty asks for at most 64 KiB; a value over 64 KiB is not written.
- A request larger than the server's maximum-request-length is refused before it is sent.
- A refused setup (status 0) or one demanding more authentication (status 2) fails `connect`
  with the server's own reason. MIT-MAGIC-COOKIE-1 is supported (`auth_cookie`, hex as
  `xauth list` prints it; the key is masked in logs by the `cookie` rule in `utils/redact.rs`).

Not implemented: drawing, fonts, input injection (XTEST), selections, any extension beyond
listing them, BIG-REQUESTS, and big-endian servers' byte order (NetGet always asks for `l`, which
every server must honour).

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/x11/`:

1. the peer is Xvfb (the X.Org server) — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: `xprop` and `xwininfo`, separate clients of the same server, show the window the handler chain created and titled from a property `xprop` set. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The MIT-MAGIC-COOKIE-1 test over the Unix socket did not run on macOS, where Xvfb needs a root-owned `/tmp/.X11-unix`. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
