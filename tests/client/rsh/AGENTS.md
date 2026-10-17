# rsh, rexec and rlogin client tests

No LLM calls: python handlers on the client play the model. `server_support` is the server
suite's `support.rs`.

## e2e_test.rs (every platform)

Against test-owned servers written from literal bytes:

- rsh: the model's command arrives with its fields and a stderr port; the test connects back,
  writes stdout and stderr, reads the model's stdin to EOF; the result event carries both
  streams, the source port and whether it was reserved.
- A stderr connection from a non-loopback address of this host is ignored; the server's own is
  the one whose bytes become stderr (needs a default route).
- A refusal (`\1Permission denied.`), and `stderr: false` sending an empty port field.
- A failed model call runs nothing.
- rexec sends the configured password on the wire and nowhere else (not in any event or the
  access log).
- rlogin: the handshake fields, the window request answered with the configured size, the
  model's line (Enter is CR) and ^D; a refused handshake fails `connect` with the server's line.

Against NetGet's own servers (regression, not evidence): rexec over the handler chain with a
refusal and a wrong password; the depth bound (exactly 8 commands); injected commands and a
malformed one rejected; rlogin through the password prompt to logout.

## real_server_test.rs (Linux, as root)

inetutils `grshd`/`grlogind`/`grexecd` and rsh-redone's `in.rshd`/`in.rlogind`, each behind
`inetd.py` (a one-service inetd: the connection becomes the daemon's stdin, stdout and stderr).
The test creates the account `rshtest` with a password and a `.rhosts` trusting client user
`alice` from localhost.

- rsh: `echo` on stdout and stderr (the latter over the stderr connection, which rshd demands
  come from a reserved port, as the main connection must), the account name, and a refusal for
  a client user `.rhosts` does not list.
- rexec: a command, and rexecd's own refusal of a wrong password.
- rlogin: the shell prompt, `stty size` printing the configured 33×111 (rlogind read the
  window-size message), a command, `exit`; the urgent window request reported.

Every missing daemon is a failure. The `rsh` job in `protocol-pairs.yml` runs it as root.
