# Prometheus exporter tests

## Strategy

**The Prometheus project's own tools are the peers.** `promtool check metrics` parses and lints
a body NetGet served; a real `prometheus` binary scrapes NetGet on a one-second interval and is
queried through its own PromQL API. Neither is linked, and neither was written by us — which is
the bar the root `AGENTS.md` sets for an HTTP-layered protocol (a generic HTTP client proves only
that HTTP works).

Both binaries **hard-fail** when absent (`require_binary` in `real_client_test.rs`). A skip would
be a silent pass on any machine without them.

The real-client tests answer scrapes with a **static handler** in an in-process server, so no
model is involved and the bodies are deterministic. `e2e_test.rs` carries a mocked model's
answer through `promtool` as well.

## Files

| File | LLM calls | What it proves |
|---|---|---|
| `real_client_test.rs` | 0 | `promtool check metrics` exits 0 with no findings on a served body carrying every type, an escaped label, unsorted buckets and a counter without `_total`; a body with one unterminated label value is rejected (negative control); a real `prometheus` scrapes in text 0.0.4 and OpenMetrics 1.0.0 (pinned with `scrape_protocols`, and a direct scrape with Prometheus' captured `Accept` asserts which format NetGet chose), `up == 1`, and the escaped label, counter values, synthesised `+Inf` bucket and a summary quantile read back exactly through PromQL; the protocol's own script-mode startup example, run as shipped through the real script executor, serves a lint-clean exposition |
| `e2e_test.rs` | 6 | a model-answered scrape renders with `_total` and `+Inf` and passes promtool; a model refusal is its own 503 and text with `decision=model_reject`; an invalid family is a 500 with `decision=fail_closed_invalid_exposition`; `/`, `HEAD`, `POST` and an unknown path never reach the model (the scrape rule is `expect_calls(3)`); OpenMetrics negotiation, the event's `format` field and second-resolution timestamps |
| `llm_failure_test.rs` | 1 | a backend failure is a 500 with the fixed category text, not an exposition content type, no leaked error text, and `decision=fail_closed_llm_error` |
| `exposition_test.rs` | 0 | the renderer byte for byte: `_total` in both formats, escaping, bucket ordering and `+Inf`/`_count` synthesis per label set, an `le` sample without a suffix read as a bucket, summaries, NaN, timestamps, 18 distinct refusals each with its reason, the sample cap, and negotiation against Prometheus' captured default header |
| `connection_bounds_test.rs` | 2 | the shared hyper-family checks in `tests/helpers/http_bounds.rs` (cap refusal and slot return; silent peer closed at 30 s, stalled peer at 120 s, parked peer kept) and the 64 KiB body cap (at the cap: 405; one byte over: 413) |

**Total: 9 LLM calls**, all mocked.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features prometheus --test server -- \
    prometheus:: --test-threads=100
```

`connection_bounds_test.rs` takes about three minutes (it sits out the 120 s idle bound); add
`--skip connection_bounds` for a quick run.

## Not covered from the wire

The overload branch (503 + `Retry-After`) — the mock backend cannot be made to saturate the
rate limiter on demand. The code path is the same `WireFailure::classify` split as `kubernetes`.
