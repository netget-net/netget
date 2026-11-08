# DNS-over-HTTPS (DoH) server tests

Re-written against the test files in the November 2026 six-conditions pass. The file it
replaced still carried sections about a Python-scripted test, `reqwest v0.11`, a five-call
budget, "future enhancements" that had been made, and its own September corrections of all of
them; it now describes only what the files do.

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
    --test server -- server::doh:: --test-threads=8
```

Every file binds to 127.0.0.1 only. The certificate is self-signed; the in-process clients
accept it (`connection_bounds_test.rs`'s `NoCertificateVerification`), and kdig and dig run
without validation.

## Files

| file | peer | what it proves |
|---|---|---|
| `real_client_test.rs` | **kdig** (Knot DNS, GnuTLS, libnghttp2) and **dig** (ISC BIND, OpenSSL, libnghttp2) | each completes POST and GET for two names with two addresses, then AAAA, MX (preference 4660), TXT, CNAME and NXDOMAIN over POST, negotiating `h2` by ALPN; dig with its defaults (EDNS and a COOKIE offered) reads the OPT the server echoes. kdig's sessions go through `recording_relay` with `SSLKEYLOGFILE` and the pcap oracle decrypts them, requiring `http2` and `dns` |
| `e2e_test.rs` | reqwest 0.12 + hickory-proto | GET and POST, the 200 status and `Content-Type`, a mixed-case media type with a parameter, id and question echoed; `server_advertises_h2_alpn` checks the TLS config offers `h2` and the shared default stays ALPN-less |
| `bounds_test.rs` | rustls + h2 + hickory-proto, Python script handler | every bound past the cap and the idle bound, and every answer outcome; see below |
| `connection_bounds_test.rs` | rustls + h2 | the 256-connection cap from both sides; the idle bound on a peer that never sends the preface and on an answered connection gone quiet; a query parked for a human keeps its connection |
| `llm_failure_test.rs` | reqwest, mock model with no rule for the query | SERVFAIL in a 200, id and question echoed |

**The maturity evidence is `real_client_test.rs`.** Both tests **fail** when their binary is
absent (`brew install knot`, `brew install bind`); neither is `#[ignore]`d. reqwest proves an
HTTP server answered, not that the DNS in it is right, and everything in-process decodes with
hickory-proto, the server's own codec. Verified by breaking it: answering with a fixed
transaction id makes kdig and dig discard the reply; advertising `http/1.1` instead of `h2`
fails kdig's handshake with `TLS, handshake failed (A TLS fatal alert has been received.)`.

Driving kdig: `+https` takes `[authority][/path]`, and the authority becomes the TLS SNI. An IP
literal there is rejected by rustls with a fatal alert that looks like an ALPN mismatch; a name
switches kdig to a validating profile a self-signed certificate cannot pass. The tests pass the
path alone.

## `bounds_test.rs`

The handler answers by name, as in `tests/server/dot/bounds_test.rs` (`nothing.test`,
`junk.test`, `huge.test`, `twice.test`, `silent.test`). Each test was checked by removing what
it tests:

| test | fails when |
|---|---|
| `every_answer_outcome_is_a_dns_message_in_a_200_or_a_stated_refusal` | an answer with no sendable action is a 5xx again, unparsed or oversize bytes go out, or a query with no question is 400 |
| `the_body_cap_admits_65535_bytes_and_refuses_one_more_before_the_model` | `MAX_DOH_BODY_BYTES` is removed or lowered |
| `the_handshake_deadline_holds_a_silent_peer_for_ten_seconds_and_no_longer` | `TLS_HANDSHAKE_TIMEOUT` is removed or shortened |
| `a_peer_that_stops_reading_is_released_at_the_idle_bound_plus_the_drain` | `GOAWAY_DRAIN_TIMEOUT` is removed — the GOAWAY write never finishes and the connection is held |

## LLM calls

`real_client_test.rs`: 1 startup + 7 queries per test. `e2e_test.rs`: 1 + 3.
`llm_failure_test.rs`: 1 + an unmatched query. The in-process tests start the server through
`ServerForm` with an empty instruction and make none.

## The pcap oracle

kdig writes `SSLKEYLOGFILE` through GnuTLS; the oracle hands tshark the key log
(`PcapOracle::tls_keylog`), ALPN `h2` gives the plaintext to the `http2` dissector and the
`application/dns-message` body to `dns`. `require_named("http2")` and `require_named("dns")`
fail unless both appear in what the server sent. Not covered: the GET request's query, which
travels base64url-encoded in `:path` where no dissector reads it (the reply is covered). BIND
9.20's dig writes no key log, so its sessions are not recorded.

Condition 3 is `fuzz/fuzz_targets/dns_message.rs`: `dns_screen` then `Message::from_vec`, the
pair this server calls on every body, with `pointer_chain_bomb` and `compression_pointer_loop`
in its corpus.
