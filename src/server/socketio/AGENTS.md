# Socket.IO server — Experimental, Socket.IO protocol v5 over Engine.IO v4

hyper HTTP/1.1 at `path` (default `/socket.io/`). `packet.rs` (shared with the client) holds
both codecs: Engine.IO packets (open, close, ping, pong, message, upgrade, noop; payloads split
on the record separator U+001E; binary refused) and Socket.IO packets
(`<type>[<nsp>,][<id>][<json>]`; binary event/ack refused; namespaces `/[A-Za-z0-9/._-]`).

Engine.IO, all in Rust:
- `EIO` must be 4 (else 400 `{"code":5}`); unknown transport code 0, unknown sid code 1, bad
  request code 3. 256 sessions; each is registered as a connection with a peer handle.
- Long-polling: the first GET opens a session (`0{"sid","upgrades":["websocket"],"pingInterval",
  "pingTimeout","maxPayload":1000000}`); a GET waits for queued packets (a ping comes within
  pingInterval) and returns them record-separated; a second GET at the same time closes the
  session; POST bodies are packet lists, answered `ok`.
- WebSocket: direct (`transport=websocket` without sid → open packet as the first frame) or by
  upgrade (`2probe` → `3probe`, a noop flushes the pending poll, then `5`), on the same
  connection task after hyper's upgrade.
- Heartbeat: the server pings every `ping_interval_ms` (25000); no pong within
  `ping_timeout_ms` (20000) closes the session (reason `ping timeout`). 256 packets queue per
  session; overflow closes it.

Socket.IO: a CONNECT to a namespace outside `namespaces` (default `/`) gets CONNECT_ERROR
`Invalid namespace` from Rust; otherwise `socketio_connect` asks the handler — `socketio_accept`
(Rust assigns the socket id, answers `0{"sid"}`, then runs any emits/joins in the same answer)
or `socketio_reject` (CONNECT_ERROR with its message); silence or a failure is CONNECT_ERROR
with a category message, never an accept. `socketio_event` carries name, arguments, whether an
ack is awaited and the socket's rooms; answers are `socketio_emit` (to sender, namespace,
`room:<r>` or `socket:<id>`, optionally excluding the sender, optionally asking the single
recipient for an ack whose answer raises `socketio_ack_received`), `socketio_ack` (sent once,
only when the client awaits one), `socketio_join`/`socketio_leave` (64 rooms per socket),
`socketio_disconnect_socket`. Leaving sockets raise `socketio_disconnect` with the reason. Peer
actions: `socketio_emit` to the session's socket in a namespace, `socketio_disconnect_socket`,
`disconnect` (the whole session).

Not implemented: binary attachments, CORS headers, Engine.IO v3 / Socket.IO v4 protocol
revisions, multi-process adapters, connection state recovery.

**Batching is `Unsupported`.** A `socketio_event` can carry an ack id the client waits on and
is owed exactly one `ACK`, and `socketio_ack` names no id: `apply` answers the one event it was
called for. In a batch the model could not say which event an ack belongs to, and events in one
session may belong to sockets in different namespaces. Each packet stays one call, in order
(`Session::inbound` serialises them).
