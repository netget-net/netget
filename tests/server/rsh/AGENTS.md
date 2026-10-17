# rsh, rexec and rlogin server tests

No LLM calls: the python policies in `support.rs` play the model (alice/alice trusted for rsh,
everything but `rm` for rexec, alice trusted / bob asked for a password / anyone else refused for
rlogin). The LLM endpoint is unreachable, so a request no handler answers exercises the
fail-closed path. Handshakes are written from literal bytes (`nul_fields`), never through
NetGet's encoder.

rlogin's peer is a **blocking** socket on a blocking thread (`b_read_until`, `b_urgent`): a tokio
stream on macOS was measured never waking for data that followed an urgent byte. Urgent bytes are
read before the stream passes the mark, as rlogin(1)'s SIGURG handler does — BSD refuses
`MSG_OOB` afterwards.

## e2e_test.rs (every platform)

- rsh with a stderr port: the server connects back before reading the user fields (rcmd's
  order), from the client's address; stdout on the main connection, stderr on the second; the
  event's fields. Without a port (`""` or `"0"`) stderr follows stdout. Untrusted pairs get the
  model's `\1Permission denied.`.
- Fail closed: no handler, an empty answer, an invalid answer, output over 1 MiB — all
  `\1netget: request could not be processed`, never `\0`.
- Bounds: port field 6 digits, a non-digit, 70000; user 256 accepted / 257 refused (both user
  fields); command at exactly 64 KiB answered, one byte more refused; refusals never reach the
  model. An unreachable stderr port refuses without asking the model.
- The stderr connection goes to the client's own address — the client dials the server on
  127.0.0.1 from this host's non-loopback address — and never to a decoy on 127.0.0.1 at the
  same port (needs a default route).
- rexec: the right password runs; wrong password, a prefix of it, a longer one, an unknown user
  and empty fields are all `Login incorrect.` with no model call; the password is in no event
  and not in the access log; no accounts refuses everyone; the stderr connection.
- rlogin: TIOCPKT_WINDOW out of band, the banner and prompt with CRLF, a window-size message
  split across writes, DEL, CR-NUL, ^C (FLUSHWRITE out of band, interrupt event), echo off and
  on, logout; the password path with three tries; refusals, a silent model, an rsh handshake
  on the rlogin port, a terminal field past its cap; a dead model mid-session prints a notice;
  a line past 8 KiB ends the session.
- tshark's `rsh`, `exec` and `rlogin` dissectors over both directions of each service, and the
  fields they read (user names, command, terminal, window rows and columns).

## real_client_test.rs

- Every unix: inetutils `grexec` (Homebrew's name, and the one `build-inetutils.sh` installs):
  stdout and stderr on their own streams, `-n`, the model's refusal, a wrong password.
- Linux, as root (`as_root`): inetutils `grsh` and rsh-redone's `rsh-redone-rsh` against NetGet
  on 127.0.0.31:514 — reserved source ports, the stderr connection, a refusal; inetutils
  `grlogin` and `rsh-redone-rlogin` on 127.0.0.32:513 through a pty — the password path with a
  wrong try, the trusted path, the window size each client sends after TIOCPKT_WINDOW, logout.
  rsh-redone 85's rsh accepts the stderr connection and never prints what arrives on it
  (measured against its own in.rshd and inetutils rshd too), so for it only stdout is
  asserted. The capture starts with a marker datagram it must see first: on a loaded host
  tshark announced "Capturing on" and still missed a session's opening packets.
  A loopback capture is read back with tshark: no Warn-level expert info on any rsh/rlogin
  packet, the commands and the window size dissected, and the urgent `0x80` seen as an rlogin
  control message.

Every missing client is a failure naming how to install it. The `rsh` job in
`protocol-pairs.yml` runs both files as root.
