# rsh, rexec and rlogin clients

Wire code is the server's `src/server/rsh/wire.rs`. Three registrations in `actions.rs`:
`RshClientProtocol`, `RexecClientProtocol`, `RloginClientProtocol`.

## rsh / rexec (`mod.rs`)

No connection stays open: `connect` validates the parameters, raises `<p>_connected`, and every
`<p>_run {command, stdin?}` is its own connection (`run_command`):

1. connect — rsh from a reserved source port when the process can bind one (1023 down to 512,
   as `rresvport(3)`), otherwise an ordinary one; rexec from any port;
2. with `stderr` (default true) a listener on the main connection's local address, reserved
   for rsh when possible (rshd requires it), whose port is the first field;
3. every field sent at once (works with servers that connect back before reading the rest and
   with those that read everything first);
4. the status byte; on `\1` the refusal line (≤ 1 KiB). **inetutils rexecd 2.8 puts the go-ahead
   byte on the stderr connection** when there is one (it points standard error at that
   connection, then writes the byte to standard error), so the main stream starts with the
   output. For rexec with a stderr connection, a main stream that opens with anything but
   `\0`/`\1` (or ends at once) sends the client to the stderr connection for the byte, and the
   main stream's first byte is kept as output — measured against rexecd in the real-server
   suite;
5. accept the stderr connection — only from the server's address (or loopback when the server
   is on loopback: a daemon's connect-back from `INADDR_ANY` leaves from 127.0.0.1 even when the
   client dialled another 127/8 address);
6. write `stdin`, half-close, read stdout and stderr together to EOF, each capped at 1 MiB,
   the whole command at 60 s.

The result event carries stdout, stderr, `accepted`, the refusal `error`, `truncated`, the source
port and whether it was reserved. rsh-redone's in.rshd sends the go-ahead byte *before* PAM
decides, so its refusal arrives as `accepted: true` with "Authentication failure" as stdout —
that is what the server said, and the event reports it as such. A stock rshd refuses a non-reserved source port; the connected
event's `reserved_ports` says in advance whether this process can bind one, and a warning is
logged for every command sent from an ordinary port.

rexec's password comes from the `password` startup parameter (redacted wherever parameters are
printed) and is never part of an action or event.

The handler chain (result → model → command …) stops after `MAX_FOLLOWUP_DEPTH` = 8; an
injected command (`send_to_client`) restarts the count. A model failure sends nothing.

## rlogin (`rlogin.rs`)

The handshake (empty stderr field, local user, remote user, `terminal/speed`), then a `\0` or a
refusal (a refusal fails `connect` with the server's line). Output is gathered until 300 ms of
quiet (or 16 KiB) and raised as one `rlogin_output`, escape sequences removed. Typing:
`rlogin_send_line` (Enter is CR), `rlogin_send_text`, `rlogin_send_key`, `rlogin_set_window`.

Urgent data is read with `recv(MSG_OOB)` **before** each read and on a 200 ms tick: BSD stacks
refuse `MSG_OOB` once a normal read has passed the urgent mark, and an urgent byte alone does not
make a socket readable. `TIOCPKT_WINDOW` is answered with the window-size message (the
`rows`/`cols` parameters, or the last `rlogin_set_window`); every control byte is reported in the
next event's `control`.

**macOS / tokio:** a kqueue-backed tokio stream was measured missing the wake-up for data that
followed an urgent byte — the read simply never returned. The session therefore also tries a
non-blocking read on every tick, so a missed edge costs at most 200 ms rather than the session.

The chain stops after 32 model turns without an operator's input. After the server closes, the
last output still reaches the model (the dispatcher is given 10 s to finish).

Maturity: Experimental for all three, stated in each `metadata()`.
