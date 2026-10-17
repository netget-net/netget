# The BSD r-services: rsh (514), rexec (512), rlogin (513)

One module, three registrations: `actions::RshProtocol`, `actions::RexecProtocol` and
`rlogin::actions::RloginProtocol`. They share everything below the session — `rcmd(3)`'s
NUL-terminated handshake, the `\0` / `\1 text\n` status byte, the stderr connection the server
opens back to the client, the reserved-port trust model — so that lives once, in `wire.rs`
(pure, fuzzed by `fuzz/fuzz_targets/rsh_handshake.rs`, and used by the clients too) and
`mod.rs` (the shared accept loop `serve`, the field reader, the one-shot rsh/rexec session).
rlogin's interactive session is in `rlogin/` because it alone takes a peer handle: rsh and
rexec declare `request_only` (one command, one answer per connection), and the two contracts
cannot share a directory (`tests/request_only_declaration_test.rs`).

## Wire

| | rexec | rsh | rlogin |
|---|---|---|---|
| fields | stderr port, user, password, command | stderr port, client user, server user, command | empty, client user, server user, `terminal/speed` |
| caps | port ≤ 5 digits, users/password ≤ 256, command ≤ 64 KiB | same | terminal ≤ 64 |
| auth | password checked in Rust against `accounts` | the model (rhosts-style) | the model: trust, password (checked in Rust), or refuse |

- The stderr port is read first and the connection back is made **before** the other fields
  are read: glibc's `rcmd` sends the port, then waits in `accept()` before sending the rest.
  rsh-redone sends everything at once; both work. The target is the main connection's peer
  address and the named port — nothing in the handshake can redirect it. It is made from a
  reserved port when the process may bind one (rcmd(3) rejects a stderr connection from any
  other port with "protocol failure in circuit setup").
- `parse_port` refuses non-digits and values above 65535 (`rshd` folds any byte into the
  number). Empty and `0` both mean no stderr connection; without one stderr follows stdout on
  the main connection.
- The status byte is written only once the model has answered: `\0` and the output, or `\1`
  and one line. Closing half-closes and reads the client's side to EOF (bounded: 5 s, 256 KiB)
  so unread input never turns the close into a reset that destroys unread output.
- rsh and rexec carry no exit status and NetGet does not read stdin: the command answers from
  its command line.

## rlogin

There is no pty, so NetGet stands in for one in packet mode: `TIOCPKT_WINDOW` (urgent `0x80`)
once the login is accepted, `TIOCPKT_FLUSHWRITE` (urgent `0x02`) on ^C; window-size messages
(`FF FF 's' 's'` + four big-endian u16) are stripped from the keystrokes across reads
(`RloginInput`, at most 11 bytes held); `LineEditor` echoes (off for passwords and when the
model sets it off), handles DEL/BS (a whole UTF-8 character), ^U, ^C, ^D on an empty line
(logout), CR / CRLF / CR-NUL. Output's bare `\n` becomes `\r\n`.

The login decision is the model's (`rlogin_login`: trust / ask password / refuse). A password is
checked in Rust against the `accounts` startup parameter for the server user, three tries.
The password never reaches an event or the access log.

## Failure

- Handshake refused (field over its cap, bad port, unreachable stderr port): `\1` + reason,
  `decision=refused_*`, no model call.
- rexec wrong password / no accounts: `\1Login incorrect.`, `decision=refused_bad_password` /
  `refused_no_accounts`, no model call.
- Model fails, answers nothing usable, or answers something the executor refuses (e.g. output
  over 1 MiB): `\1netget: request could not be processed`, `decision=fail_closed_*` or
  `model_silent`. Never `\0`: nothing runs as though trusted.
- rlogin mid-session: a `[netget] …` notice line, session stays open (telnet's behaviour).

## Limits worth knowing

- NetGet does not refuse a non-reserved source port; it reports `reserved_source_port` so the
  model can apply the classic check. An unprivileged NetGet client is exactly that case.
- Signals the client sends on the stderr connection are not read.
- macOS: a tokio stream can miss the kqueue wake-up for data following an urgent byte. The
  server only *sends* urgent data, so it is unaffected; the client and the tests account for it
  (see `src/client/rsh/AGENTS.md`).

Maturity: Experimental for all three, stated in each `metadata()`.
