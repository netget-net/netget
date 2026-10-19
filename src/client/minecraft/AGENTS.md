# Minecraft client (Java Edition server-list ping and login probe)

Uses the server's `wire.rs`. Each action opens a fresh TCP connection, as a launcher's server
list does; the client instance itself holds no socket.

## Actions and events

- `minecraft_status {protocol_version?}`: handshake + status request, then a ping. Arrives as
  `minecraft_status_response` with the version, player counts, the MOTD flattened to plain
  text, the sample, whether a favicon was sent (its data is dropped), and the measured
  latency (null when the server answers status but not ping).
- `minecraft_legacy_status`: the 1.6 `FE 01 FA` + MC|PingHost ping; decodes either legacy
  reply form.
- `minecraft_login {username, protocol_version?, uuid?}`: handshake + Login Start in the
  layout of the announced protocol, then reads up to 16 packets: Set Compression switches
  framing, a login plugin request is answered "not understood" and a cookie request "no
  cookie", as a vanilla client does. Ends in `minecraft_login_result` with `outcome`
  `disconnected` (with the reason as plain text), `encryption_required` (an online-mode
  server; there is no Mojang authentication here) or `accepted` (with the assigned UUID and
  name). An accepted login is closed before the game.

## Batching

Unsupported. Every event is the result of the model's own ping or login probe, run one at a
time on a fresh connection; the server never pushes anything that could pile up.

## Bounds

A clientbound packet is refused past 3 × 32767 + 8 bytes before it is read, and a compressed
packet must inflate to exactly the size it declares, never more. Every read and write has a
30 s deadline. A failed probe is logged and reported to an injected sender; the client stays
up for the next.
