# DoQ server tests

Declared in `tests/server/mod.rs` (`pub mod doq`); `mod.rs` here declares the four files.
Everything binds loopback. Queries are answered by static or Python script handlers, or by an
unreachable model endpoint (`http://127.0.0.1:1`) where a backend failure is the point, so no
model is needed and no LLM call is made. `support.rs` (`Fixture`) is shared with
`tests/client/doq/`: it writes a self-signed `localhost` certificate, starts the server with it
and opens Quinn connections that trust it.

## Files

- `real_client_test.rs` — the independent evidence. Knot `kdig +quic` (libngtcp2 and Knot's
  DNS codec; `+tls-ca` and `+tls-hostname=localhost`, so it verifies the certificate) and
  AdGuard `dnsproxy` with the server as its `quic://` upstream (quic-go and miekg/dns; kdig asks
  dnsproxy over UDP, dnsproxy asks NetGet over DoQ, with `--insecure` since its Go verifier
  ignores a custom CA on macOS). Each reads A, AAAA, NXDOMAIN, an SRV answered with
  `send_dns_records`, and the SERVFAIL for an answer with nothing sendable. Both **fail** when
  their binary is missing. The dnsproxy test also counts the DoQ queries the server received.
- `bounds_test.rs` — every declared bound from both sides and every answer outcome the server's
  AGENTS.md lists; its header has the table. These use a Quinn peer with hickory messages,
  which is transport testing, not independent evidence.
- `e2e_test.rs` — parallel streams with zero ids, the question echoed, FIN and cleanup (UDP port
  released on stop); the protocol-error closes (bad length, two messages, trailing bytes,
  non-zero id, short, oversize, keepalive); the dangling-query reset and client cancellation;
  the connection cap with the idle close and ALPN; the handshake deadline holding a slot inside
  its bound and releasing it after; backend-failure SERVFAIL and AXFR NOTIMP; and the decision
  lines on the status channel.

## Running

```bash
sh scripts/test-peers/install-dnsproxy.sh /tmp/netget-peers/dnsproxy
export NETGET_DNSPROXY_BIN=/tmp/netget-peers/dnsproxy/darwin-arm64/dnsproxy   # linux-amd64 on CI
./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite \
  --test server -- server::doq:: --test-threads=8
```

`kdig` must support `+quic` (Knot 3.3+, built with libngtcp2; Homebrew's `knot` is: kdig 3.6.2
here). Finding the binary is not proof of QUIC support — the test asserts kdig reported a QUIC
exchange.

Verified 8 November 2026 on macOS arm64 with kdig 3.6.2 and dnsproxy 0.85.0.

## What breaking each fix shows

Each answer fix was reverted once and the test watched to fail: resetting the stream for an
answer with nothing sendable fails `answers_follow_the_dns_servers_rules` (the exchange errors
instead of reading SERVFAIL), as does merging several messages (two A records) and sending an
oversize answer as it comes (a NOERROR with TC); refusing non-core types with NOTIMP fails it at
the SRV query; a reset on the exchange deadline fails
`exchange_deadline_answers_inside_it_and_servfails_past_it`.

The rating is Experimental; `src/server/doq/AGENTS.md` ("Maturity") says what is missing.
