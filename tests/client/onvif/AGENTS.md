# ONVIF client tests

`NETGET_RPOS` comes from `tests/server/onvif/install_peers.py`: RPOS (BreeeZe/rpos) at a pinned
commit, SHA-256 checked, `npm install --ignore-scripts` (its native serial-port and Raspberry Pi
modules are never loaded) and compiled with `tsc` (its gulp build does not run on current
Node). The test fails, not skips, without it.

- `real_server_test::netget_reads_rpos_with_a_digest_rpos_verifies` — RPOS on a free port
  (`NetworkAdapters` empty so it advertises 127.0.0.1; its RTSP server off, handing out the URI
  of an external one). RPOS checks every PasswordDigest itself and answers a bad one
  `NotAuthorized`. A python chain asks for device information, scopes, interfaces, sources and
  profiles on connect, then the stream and snapshot URIs of the profile RPOS listed; RPOS's
  answers are asserted in NetGet's events and the profile token in RPOS's own log of what it
  received (`logSoapCalls`). An injected action is answered with the result.
- `real_server_test::rpos_refuses_the_wrong_password_and_the_connection_fails` — RPOS logs the
  refusal and connect fails naming `NotAuthorized`.
- `bounds_test` — a canned device written in the test (not evidence): a reply nested past
  `MAX_DEPTH` and one past `MAX_RESPONSE` refuse the connection, exactly `MAX_RESPONSE` does
  not; a chain that never stops stops at `MAX_FOLLOWUP_DEPTH`; every signed request carries the
  device's clock (two hours ahead here) and verifies; the media service is reached by path on
  the given host though the capabilities named another.

Mutation-checked: dropping the model's actions fails `real_server_test` and the chain test;
removing the depth bound, the reply depth check or the reply size limits fails `bounds_test`.

No LLM calls.
