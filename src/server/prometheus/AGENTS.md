# Prometheus exporter

NetGet serves `GET /metrics` like any Prometheus exporter; the model decides what the metrics
are. A real Prometheus server, `promtool`, or anything else that reads the exposition format can
scrape it.

**State**: Beta. **Privilege**: `None` (9100 is node_exporter's port and unprivileged).
**Feature**: `prometheus`. **Group**: AI & API. **Keywords**: `prometheus`, `exporter`,
`node_exporter`, `/metrics`, `openmetrics`.

## Library choice

hyper HTTP/1.1, the same shape as `kubernetes` and the registry family. No Prometheus crate:
the exposition format is small, and the part that matters — refusing what a scraper would
reject — is ours to decide, not a client library's. `exposition.rs` is pure and public so it is
tested directly (`tests/server/prometheus/exposition_test.rs`) and through `promtool`.

## What NetGet decides vs what the model decides

| Served deterministically, no model call | Decided by the model, one event per scrape |
|---|---|
| `GET /` — a static HTML page linking to `/metrics` | which families exist, their type and help |
| `HEAD /metrics` — headers only | labels and values of every sample |
| `POST`/`PUT`/… on `/` or `/metrics` — 405 with `Allow: GET, HEAD` | whether to refuse the scrape (`send_scrape_error`) |
| any other path — 404 | |
| format negotiation from `Accept` | |
| every byte of the exposition text | |

## Event and actions

- `prometheus_scrape` — `{path, accept, user_agent, format: "text"|"openmetrics",
  scrape_timeout_seconds?}`. `format` is what NetGet negotiated; `scrape_timeout_seconds` comes
  from Prometheus' `X-Prometheus-Scrape-Timeout-Seconds` header when present. Declared with
  `.with_actions(...)`, raised in `mod.rs::handle_request`.
- `send_metrics {metrics: [{name, type, help?, samples: [{labels?, value, suffix?,
  timestamp_ms?}]}]}` — validated in `execute_action` by `MetricFamilies::parse`, rendered by
  `MetricFamilies::render`.
- `send_scrape_error {status: 4xx|5xx, message}` — the model refusing on purpose; the message is
  written as one line of `text/plain` (control characters become spaces).

## The exposition renderer (`exposition.rs`)

Everything a scraper would reject is refused at parse time, with a reason naming the metric:
invalid metric or label names, `__`-prefixed labels, a suffix the type does not have, `le` or
`quantile` outside a histogram bucket or summary quantile, negative or NaN counts, duplicate
series, duplicate families, two families whose sample names collide, a non-cumulative
histogram, a `_count` that disagrees with the `+Inf` bucket, a quantile outside 0..1, more than
`MAX_SAMPLES` (50 000) samples.

What it completes rather than refuses: a counter named without `_total` gets it (text format
puts it on the `# TYPE` line, OpenMetrics does not); a histogram sample with an `le` label and
no `suffix` is a bucket, since only a bucket carries `le` (llama3.1:8b leaves the suffix off in
about one answer in five); histogram buckets are sorted by `le`; a
missing `+Inf` bucket is synthesised from `_count` (or from the largest bucket when there is no
`_count`), and a missing `_count` from the `+Inf` bucket. Integral bounds render as `1.0`.

Escaping: label values escape `\`, `"` and LF; help escapes `\` and LF, plus `"` in
OpenMetrics.

Negotiation: OpenMetrics 1.0.0 is served only when the `Accept` header gives
`application/openmetrics-text` a strictly higher q than text/plain and `*/*`. Prometheus 3.15's
default header does (captured: `application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;
q=0.7,…,text/plain;version=0.0.4;q=0.4,*/*;q=0.3`); `curl` and `promtool`-via-curl get text.

## Failure behaviour

| Condition | Wire | Log |
|---|---|---|
| model answered `send_metrics` | 200 + exposition | `decision=model_answer` |
| model answered `send_scrape_error` | its 4xx/5xx + its message | `decision=model_reject` |
| model's families refused by the executor | 500 `netget: the handler returned no usable metrics` | `decision=fail_closed_invalid_exposition (<reason>)` |
| model answered no exporter action | same 500 | `decision=fail_closed_no_action` |
| backend saturated | 503 + `Retry-After: 5`, `netget: backend at capacity, retry later` | `decision=fail_closed_llm_error category=Overloaded` |
| backend failed | 500 `netget: request could not be processed` | `decision=fail_closed_llm_error category=Unavailable` |
| request body over the cap | 413 | `decision=fail_closed_body_rejected` |

Never an empty 200: that would read as "this target has no series" with `up == 1`. The executor's
refusal reason reaches the log and the access log (`list_access_logs`); on the network path the
model is not re-prompted with it, because protocol-action executor errors are not fed back into
the retry loop (`src/llm/conversation.rs` only re-prompts for unknown and malformed *common*
actions).

## Bounds

| Bound | Value | Why |
|---|---|---|
| `MAX_REQUEST_BODY_BYTES` | 64 KiB | a scrape has no body; read and discarded before routing so it holds on every path |
| `FIRST_BYTE_READ_TIMEOUT` | 30 s | `TcpStream::peek` before hyper; HTTP is client-speaks-first |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 120 s | Prometheus reuses one connection per target at a 60 s default interval; `ConnectionActivity` keeps a parked request alive |
| `MAX_CONNECTIONS` | 256 (`accept_bounded` default) | refusal is a plaintext 503 + `Retry-After` |
| `MAX_SAMPLES` | 50 000 per answer | render bound |

No peer handle: hyper owns the socket for the life of the connection
(`tests/peer_handle_coverage_ratchet_test.rs`, `HyperOwnsSocket`).
It is also request-only; `metadata()` declares `.request_only(…)`: "Prometheus scraping is HTTP
request/response; a server cannot send a peer anything unprompted". The dashboard's
`[ send message ]` on a peer is disabled and shows that reason, and MCP `send_to_peer` refuses
with it.

## Not implemented

Protobuf exposition, native histograms, exemplars, `_created` series, `# UNIT`, gzip (the
`Accept-Encoding: gzip` Prometheus sends is ignored and the body is served identity), UTF-8
metric names (legacy names only; Prometheus' `escaping=allow-utf-8` is irrelevant because
nothing non-legacy is ever emitted), federation's `match[]`, TLS, authentication.

## Maturity

Beta. The bar is "works against real clients", and the evidence is
`tests/server/prometheus/real_client_test.rs`: `promtool check metrics` (parse and lint, with a
negative control proving it rejects) and a real `prometheus` scraping NetGet in both negotiated
formats and answering PromQL with the served values. Both binaries **hard-fail** when absent; if
that gate is ever softened to a skip, demote this in the same commit. Promoted after the suite
passed three consecutive runs at `--test-threads=100`.

Not Stable: `promtool` and `prometheus` are one project and share one parser, so this is one
independent implementation rather than the two condition 1 asks for; there is no fuzz target
(the inbound side is a request line, and the renderer's input is JSON) and no pcap-oracle test
(Wireshark has no Prometheus dissector, only `http`).
