# RCON server (Source RCON, also Minecraft's RCON)

Hand-written over Tokio TCP (`wire.rs`): little-endian size, id and type, a NUL-terminated
body and an empty string. `dialect` is `source` (srcds sends an empty RESPONSE_VALUE before
every AUTH_RESPONSE) or `minecraft` (no empty packet).

## Login

With a `password` startup parameter the check is in Rust, in constant time, and the handler
never sees the attempt. Without one, `rcon_auth` asks the handler, which sees the password
supplied; failure or silence refuses. A refusal answers AUTH_RESPONSE id -1; three refusals
close the connection.

## Commands

`rcon_command` (authenticated only; a command before login closes the connection) is answered
by `rcon_response {output}`, sent as RESPONSE_VALUE packets with the request id, split at
4086 body bytes. A client's empty RESPONSE_VALUE (the multi-packet sentinel) is mirrored with
its own id after the preceding output. srcds also sends a second packet after the mirror; this
server does not, so clients that wait for it are not supported.

## Failure modes and bounds

A handler failure on a command closes the connection: RCON has no error channel, and an empty
response would read as a command that printed nothing. `decision=` tags as elsewhere.
Packets are capped at 4096 bytes (size field) and output at 1 MiB; idle deadline and the
shared connection cap apply.

## Batching (supported, off by default)

With `batching: true`, EXECCOMMAND packets a client pipelined while the model was answering are
answered in one call (`commands_already_here`, `answer_batch` in `mod.rs`); collection stops at
any other packet, so a login or the multi-packet sentinel is handled alone and the sentinel's
mirror still follows the output it marks. `rcon_response` names no command, so outputs are
matched to commands by position: the batch is sent — each output under its own request id —
only when the handler gave exactly one response per command, and otherwise the connection
closes as it does for a failed command (`decision=fail_closed_batch_mismatch`). Hence off by
default. `tests/server/rcon/batching_test.rs` covers the off control, the matched batch and
the mismatch.
