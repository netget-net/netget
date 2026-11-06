# Cap'n Proto RPC client

Uses the server's `layout`, `schema` and `rpc` modules. `connect` loads the schema (same
`schema`/`interface` parameters), bootstraps within 10 s, and keeps the bootstrap capability
by finishing that question with `releaseResultCaps = false` — the default (true) releases it,
which NetGet's own server ignored and both real servers honoured (`unknown export ID`).

`capnp_call {method, params}` encodes the params by the schema (a method the interface lacks,
an unknown field or an out-of-range number is refused locally) and sends a Call on the bootstrap
import; calls are pipelined, at most 64 awaiting answers, matched by question id. Each Return
becomes `capnp_result {method, results, exception}` and is finished. `capnp_connected` lists
every method with its params and results fields. The client exports nothing: a Call or
Bootstrap from the server is answered `unimplemented`. A handler chain stops after 8 follow-ups.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/capnp_rpc/`:

1. the peer is pycapnp (the C++ runtime) and go-capnp v3 — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: each server echoes back, as it decoded it, the `store` the connect handler sent. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
