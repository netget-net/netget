# Vault tests

## Strategy

**HashiCorp's `vault` CLI is the peer.** It asks the KV preflight which version a mount runs,
rewrites paths for KV v2, and decodes our envelope into its own `api.Secret`, so a
`vault kv get -field=password` that prints the right word proves the preflight, the path
rewrite, the envelope and the `data`/`metadata` split at once.

The child runs with a **cleared environment** (`vault()` in `real_client_test.rs`): `PATH`, a
temp `HOME` so no `~/.vault-token` or token helper is read, `VAULT_ADDR` at NetGet and the test's
own `VAULT_TOKEN`. No real Vault is involved.

`require_tool("vault")` searches `PATH` first, including the workflow's pinned
owned peer directory, then the shared Homebrew/Linux installation fallbacks.
It **hard-fails** when the CLI is absent.

## Files

| File | LLM calls | What it proves |
|---|---|---|
| `real_client_test.rs` | 0 | against Python script handlers with fixed data and a configured token: `vault status` (six fields), `kv put` (the CLI's `{"data": …}` reaches the event intact; version and time printed), `kv get` as a table, `-field=password` (exact stdout) and `-format=json` (parsed), `kv list` (keys, sorted by the CLI), `kv metadata get`, a missing secret answered with `send_vault_not_found` as the CLI's "No value found" with exit 2, a wrong token refused 403 by the handler on the event's booleans, `kv delete` 405; and the shipped script-mode example serving `get -field`, `list` and `put` |
| `e2e_test.rs` | 6 | a mocked model that stores what `kv put` sent and returns it on `kv get` (the model is the storage), `kv list`, a wrong token refused by the model, `kv metadata get`; every event it saw has `token_configured: true` and **no event contains either token string**; `decision=model_answer` and `model_reject` in the log |
| `llm_failure_test.rs` | 1 | a backend failure is `Code: 500` with the fixed category in the CLI's output — never "No value found" — no leaked error text, `decision=fail_closed_llm_error` |
| `api_test.rs` | 0 | the routing table (sys endpoints, preflight, data/metadata, LIST and `?list=true`, the mount root, longest-mount match, `secretive` not matching `secret`), the envelope and defaults, and ten refusals |
| `connection_bounds_test.rs` | 2 | the shared hyper-family checks in `tests/helpers/http_bounds.rs` (cap; silent peer at 30 s, stalled peer at 120 s, parked peer kept) and the 1 MiB body cap (at the cap: 405; one byte over: 413) |

**Total: 9 LLM calls**, all mocked.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features vault --test server -- \
    vault:: --test-threads=100
```

`connection_bounds_test.rs` takes about two minutes (it sits out the 120 s idle bound).

## Not covered from the wire

The overload branch (503 + `Retry-After`): the mock backend cannot be made to saturate the rate
limiter on demand.
