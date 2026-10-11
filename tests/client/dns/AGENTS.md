# DNS client tests

```bash
./cargo-isolated.sh test --no-default-features --features dns --test client -- client::dns --test-threads=8
```

| file | peer | model calls | proves |
|---|---|---|---|
| `real_server_test.rs` | ISC BIND **`named`**, unprivileged on loopback, signing its zone inline; read back with `dig` | 0 (script handler) | the client bar (below): DNSSEC-aware query, AXFR, IXFR |
| `e2e_test.rs` | NetGet's own DNS server (`open_server`) | mocked | the conversation loop: A, MX, NXDOMAIN, a follow-up query. **Self-served**: it proves the two halves agree, not that the client is right |
| `command_channel_test.rs` | NetGet's own DNS server | mocked | an injected `send_dns_query` (the dashboard's `[ send ]`) |
| `transfer_bound_test.rs` | a hand-written hostile TCP server on 127.0.0.1 | 0 | an endless AXFR of ~64 KiB TXT records ends with the `MAX_TRANSFER_BYTES` error (`passed … bytes; abandoned`), not a timeout or the record count |

This file used to describe a suite that queried 8.8.8.8 and 1.1.1.1 and "skipped gracefully"
offline. Neither had been true for a long time: `e2e_test.rs` starts NetGet's own server, and
this repository forbids external endpoints.

## real_server_test.rs — the evidence the Beta rating rests on

`named -g -c {dir}/named.conf` with one zone, `example.org`, `dnssec-policy default` and
`inline-signing yes` (named generates an ECDSA P-256 key and signs), `allow-transfer { any; }`
and `ixfr-from-differences yes`. Ready when named logs the signed zone loaded. A missing `named`
or `dig` **fails** the test naming `bind9` / `bind9-dnsutils`.

A script handler plays the model:

1. `dns_connected` → `send_dns_query {www.example.org., A, dnssec: true, recursion_desired: false}`.
   The answer must carry the A record **and** named's RRSIG over it (type covered A, algorithm
   13, signer `example.org.`) — which only arrives if the DO bit reached the wire. Removing the
   DO bit fails here.
2. That answer → `send_dns_zone_transfer {zone: example.org.}`. The AXFR's `record_count` must
   equal the number of records `dig axfr` prints from the same server, its serial must be the
   one `dig` reads, and it must contain SOA, DNSKEY, NSEC, RRSIG and MX.
3. The test edits the zone file (serial 100 → 101, `www` .80 → .81) and sends named SIGHUP;
   named computes the difference and re-signs. An **injected** `send_dns_zone_transfer
   {serial: <old>}` must come back `transfer_type: IXFR`, `form: incremental`, with the new
   serial, the old `www` address before the new one, and fewer records than the AXFR.
4. named's own log must show an AXFR and an IXFR served — condition 4 from the server's side.

**CI**: named is installed in the `dns-transfer-dnssec` protocol-pairs job. Ubuntu's AppArmor
profile confines `/usr/sbin/named` to its packaged paths, so the job unloads it, as `ci.yml`
does for mysqld and slapd.

## Mock rule ordering (`test_dns_client_multiple_queries`)

`and_event_data_contains(key, value)` is a **substring** match
(`field.contains(value)` in `tests/helpers/mock_matcher.rs`), and the mock server
answers with the **first** rule that matches — `expect_calls(N)` does not retire a
rule once it is exhausted.

So a rule keyed on `query_type == "A"` also matches an `"AAAA"` response. With the
A rule declared first, the AAAA response was answered with "send another AAAA
query", and the client looped: 211 LLM calls, then a stack overflow
(`IMPROVEMENTS.md` item 49).

**The AAAA rule must be declared before the A rule.** `"A"` does not contain
`"AAAA"`, so the first response still falls through correctly. When adding record
types here, order the rules longest-value-first, or pick values that cannot be
substrings of one another.

The client side is now defended independently — the action loop is iterative rather
than recursive, and a per-client LLM call budget (default 100, see
`src/client/llm_budget.rs`) hard-stops any non-converging client — so a mistake of
this shape now fails the mock expectations instead of killing the process.
