# Bolt tests

Strategy: the protocol mechanics (handshake, state machine, streaming, bounds, failure paths)
are driven in-process from a raw socket with **script and static handlers**, so they are
deterministic and consult no model; the independent-client evidence is Neo4j's own
`cypher-shell`; one raw-socket suite and one cypher-shell case put a **mocked model** behind the
server, because the model path is the one the protocol exists for.

The raw peer (`common::Peer`) uses NetGet's own PackStream codec, so what it proves is
mechanics. That the bytes are acceptable to something NetGet did not write is only
`real_client_test.rs`'s claim.

## Files

| File | What it proves | LLM calls |
|---|---|---|
| `common.rs` | `new_state` (dead model endpoint), `start` through `ServerForm`, `Peer` (handshake, pipelined sends, chunked receive), message builders, `GRAPH_SCRIPT` — a deterministic graph as a Python script handler | — |
| `real_client_test.rs` | `cypher-shell` 2026.09 prints exactly the handler's rows; renders a node, a relationship, a path and the same path walked backwards as graph values; prints write statistics; raises a handler-chosen `Neo.ClientError.Statement.SyntaxError` as `ClientException` with its message; refuses a wrong configured password as `AuthenticationException`; runs `:begin`/`:commit` with `-d movies` and `-P` and gets the parameter echoed back; routes over `neo4j://` back to this server; prints a mocked model's rows. **Fails, never skips**, without cypher-shell or its Java runtime | 3–4 (last test: startup, one login per pooled connection — one or two — and one query) |
| `state_machine_test.rs` | negotiation (5.8 from cypher-shell's exact proposals, 5.4, a range reaching down to 5.8, none, not Bolt); PULL `n` with `has_more` and DISCARD; stats and bookmark on a write; parameters and every plain value kind round-trip; two results in one transaction by `qid`; COMMIT with an open result is a protocol violation; FAILURE → IGNORED → RESET → usable; INTERRUPTED (messages queued ahead of RESET are IGNORED); ROUTE names the dialled address; the three admin queries answered with no handler and no decision logged; LOGOFF; a RUN before LOGON; 5.4's `{code, message}` FAILURE and TELEMETRY; 5.0 credentials in HELLO; the configured password checked by NetGet with the credential in no log line; a handler's rejection code | 0 |
| `connection_bounds_test.rs` | a RUN of exactly 1 MiB answered and 1 MiB + 1 refused before the handler; a chunk stream with no end refused at the cap; a 100,000-level depth bomb refused and the process alive, 32 levels accepted; the handshake deadline (silent and half a handshake); the idle deadline (a different number); a RUN parked on a `manual` rule closed by neither; the 256-connection cap closes the next peer unanswered and the slot comes back | 0 |
| `llm_failure_test.rs` | dead backend on a query → transient FAILURE with no leaked text, `fail_closed_llm_error`, RESET recovers; dead backend on a login → refused and closed; `model_silent`; rows narrower than `fields` → `fail_closed_invalid_answer`; a login answer to a query → `fail_closed_mismatched_reply`; a model failure code → `model_reject` | 0 (the backend is a dead port) |
| `e2e_test.rs` | a mocked model over a raw session: what the event carried comes back as a record (parameter, database, read mode, auto-commit vs `in_transaction`), no credential in the event, PULL batching of model rows, a write in a transaction, a model failure then RESET. The login rule also requires the event's `answer_with`, so it matches only when the hint reaches the model | 5 |
| `answer_with_test.rs` | the login hint names the user, scheme and credential presence, says accept unless the instructions refuse that login, and that query rules wait for the query; the query hint names the first word and whether it is a Cypher clause; a record written as an object keyed by exactly the field names is read in field order, and any other object is refused | 0 |
| `peer_inject_test.rs` | an injected answer is executed and writes nothing (the next bytes on the wire answer the next request); `close_connection` sends EOF | 0 |
| `packstream_test.rs` | the specification's literal bytes; the smallest integer form at every width boundary; wider forms decode; malformed input refused; the depth bomb (list, map, structure) and the exact limit; five oversized declared lengths refused; chunking at 65535, NOOP chunks, the 1 MiB cap on the declared size; proptest round trips through the codec and through chunking, arbitrary bytes never panic; JSON → graph structures and path indices; parameters → JSON without raw bytes; stats names; failure-code shape | 0 |

LLM budget for the whole directory: **8–9 mocked calls**.

## Verified by removing each guard

Each was removed, its tests watched failing, then restored (recorded in the feat commit):

- depth checks in `packstream.rs` → `packstream_test` and the over-the-wire bomb in
  `connection_bounds_test` abort the binary with `stack overflow`;
- `check_declared` → the LIST_32 case reports `UnexpectedEnd` after reserving four billion
  `Value`s (macOS grants the address space lazily) instead of `DeclaredLengthExceedsInput`;
- the `Dechunker` size check, both read deadlines, the connection cap, the password comparison,
  the INTERRUPTED lookahead and the FAILED state's IGNORED → fifteen tests fail between them.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt:: --test-threads=100
```

`real_client_test.rs` needs `cypher-shell` on `PATH` (searched first, then `/opt/homebrew/bin`,
`/usr/local/bin`, `/usr/bin`) and a Java 21 runtime: `brew install cypher-shell` on macOS; on
Ubuntu the release zip from `https://dist.neo4j.org/cypher-shell/cypher-shell-2026.09.0.zip`, which
is what CI's `registry-audit` installs (see `.github/workflows/ci.yml`). Each run starts a JVM
(~1–2 s), so the file dominates the suite's wall time.

The full 69-test server suite also passes with the official Community5.26.31
distribution's bundled cypher-shell5.26.31 (JavaDriver5.28.15) and OpenJDK21.0.12.1.
All eight independent CLI cases pass with both that bundle and installed
cypher-shell2026.09.0 (JavaDriver6.2.1). Native `--log` in an owned temporary HOME
supplies the independently raised exception classes for both CLI versions;
credentials use explicit environment variables, not CLI arguments, and diagnostic
output removes the fixed fixture password. The write-statistics assertion accepts
the exact native wording of these two versions for the same three update counts.
For the programme's pinned pair job, use `scripts/test-peers/install-neo4j.sh`
and put that distribution's bin directory first on PATH; no extra CLI download.

No pcap oracle: Wireshark 4.6.8 has no Bolt dissector. The fuzz target is
`fuzz/fuzz_targets/packstream_message.rs`.
