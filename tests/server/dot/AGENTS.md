# DNS-over-TLS (DoT) server tests

Re-written against the test files in the November 2026 six-conditions pass. The file it
replaced described one Python-scripted test sending three queries over one TLS session, a
`dns_response` action and a one-call budget; none of that matched the code.

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
    --test server -- server::dot:: --test-threads=8
```

Every file binds to 127.0.0.1 only. The server's certificate is self-signed; the in-process
clients accept it through `e2e_test.rs`'s `NoCertificateVerification`, and `kdig +tls` /
`dig +tls` do not authenticate it (that needs `+tls-ca`, `+tls-hostname` or `+tls-pin`).

## Files

| file | peer | what it proves |
|---|---|---|
| `real_client_test.rs` | **kdig** (Knot DNS, GnuTLS) and **dig** (ISC BIND, OpenSSL) | each completes `+tls` queries for two names with two addresses, then AAAA, MX (preference 4660), TXT, CNAME and NXDOMAIN, and renders our answer; dig runs with its defaults (EDNS and a COOKIE offered) and reads the OPT the server echoes. kdig's sessions go through `recording_relay` with `SSLKEYLOGFILE`, and the pcap oracle decrypts them and requires `dns` |
| `e2e_test.rs` | rustls + hickory-proto, in process | three queries (a new connection each), id and question echoed, each name its own address |
| `bounds_test.rs` | rustls + hickory-proto, Python script handler | every bound and every answer outcome; see below |
| `connection_bounds_test.rs` | rustls | the 256-connection cap from both sides, and a body that never finishes closed at `MESSAGE_READ_TIMEOUT` |
| `llm_failure_test.rs` | rustls, mock model with no rule for the query | SERVFAIL, id and question echoed, no answers |

**The maturity evidence is `real_client_test.rs`.** Both tests **fail** when their binary is
absent (`brew install knot`, `brew install bind`); neither is `#[ignore]`d. `e2e_test.rs` and
`bounds_test.rs` encode and decode with hickory-proto, the codec the server uses, so they prove
behaviour and bounds, not wire correctness — that is what the two resolvers and the oracle are
for. Verified by answering with a fixed transaction id instead of the client's: kdig and dig
both discard the reply and their tests fail.

## `bounds_test.rs`

A Python script handler answers every query by name, so no model is reached and every answer is
the one the test names (`nothing.test` → only `notify_operator`; `junk.test` → 12 bytes that
are not a DNS message; `huge.test` → a ~80 KB message; `twice.test` → two A actions;
`silent.test` → `ignore_query`). Each was checked by removing what it tests:

| test | fails when |
|---|---|
| `every_answer_outcome_is_one_message_or_a_decision_to_send_none` | the server goes back to writing every `Output`, skipping undecodable bytes, or writing nothing for an answer with no sendable action |
| `the_largest_message_the_prefix_can_carry_is_read_whole_and_a_zero_length_closes` | a cap below 65535 is introduced, or a zero length is read as a message |
| `an_undecodable_query_closes_its_connection_and_the_server_answers_the_next` | an undecodable message is skipped with the connection left open |
| `the_handshake_deadline_holds_a_silent_peer_for_ten_seconds_and_no_longer` | `TLS_HANDSHAKE_TIMEOUT` is removed or shortened |
| `the_idle_bound_is_the_declared_one_and_resets_on_every_query` | `idle_timeout_secs` is not read, its range is not checked, or the clock does not reset per query |
| `a_body_finished_inside_the_message_deadline_is_answered` | `MESSAGE_READ_TIMEOUT` fires early |

## LLM calls

The mocked tests make one startup call (`open_server`) and one per query: `real_client_test.rs`
2 + 1 per test, `e2e_test.rs` 3 + 1, `llm_failure_test.rs` 1 + an unmatched query. The
in-process tests (`bounds_test.rs`, `connection_bounds_test.rs`) start the server through
`ServerForm` with an empty instruction and make none.

## The pcap oracle

`real_client_test.rs` frames each recorded session on port 853, where tshark's DNS dissector
registers for TLS application data, and hands it the key log (`PcapOracle::tls_keylog`).
`require_named("dns")` fails unless DNS was dissected in what the server sent, so a key log that
did not match is a failure, not a pass on the TLS record layer. kdig writes the log through
GnuTLS. BIND 9.20's dig writes none (`SSLKEYLOGFILE` feeds `named`'s `sslkeylog` logging
category, not dig — measured against `openssl s_server`), so dig's sessions are not recorded;
kdig's carry every record type the same server code writes.

Condition 3 is `fuzz/fuzz_targets/dns_message.rs`: `dns_screen` then `Message::from_vec`, the
pair this server calls on every query, with `pointer_chain_bomb` and `compression_pointer_loop`
in its corpus.
