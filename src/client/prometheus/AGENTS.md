# Prometheus exporter scrape client

Feature `prometheus`, canonical client `Prometheus`, exporter default port 9100.
Experimental. This is roadmap 57: negotiate and ingest exporter exposition. The
existing programmable exporter server is preserved. PromQL query APIs and remote
write are separate scopes.

Open an HTTP(S) origin (`127.0.0.1:9100` or `https://host:port`), without credentials,
path, query or fragment. The startup `metrics_path` defaults to `/metrics` and
`scrape_timeout_secs` to 15, range 1..30. The connection is logical: an explicit
`scrape_metrics {path?, format?: "auto"|"text"|"openmetrics"}` performs one GET.
Actions cannot change the origin. There is no scheduler, target discovery,
authentication, redirect following or protocol-specific metrics database.

`auto` prefers OpenMetrics 1.0.0 and offers classic text 0.0.4 fallback; the other
values offer only the selected format. Requests declare `escaping=underscores`,
`Accept-Encoding: identity`, `X-Prometheus-Scrape-Timeout-Seconds` and a NetGet user
agent. A non-200 response, missing/unsupported Content-Type, unexpected negotiated
format, compression, malformed/partial body or exceeded bound raises
`prometheus_scrape_error {request,path,error}` with no partial metrics. The client
remains available for another request. Native HTTPS uses ordinary certificate
verification; custom roots/client certificates are not exposed. The browser uses
plain HTTP and drives hyper's socket future directly, without a detached driver.

`prometheus_connected {origin,metrics_path}` requests the first decision.
`prometheus_metrics {request,path,format,content_type,sample_count,metrics}` reports
complete parsed families:

```json
{
  "name": "requests_seconds",
  "type": "counter",
  "help": "Requests served",
  "unit": "seconds",
  "samples": [{
    "name": "requests_seconds_total",
    "suffix": "_total",
    "labels": {"path": "/"},
    "value": 3.0,
    "timestamp_seconds": 1605281325.125,
    "exemplar": {"labels": {"trace_id": "abc"}, "value": 2.5,
      "timestamp_seconds": 1605281325.5}
  }]
}
```

Classic text counter family names include `_total` and their main sample's suffix
is empty; OpenMetrics families omit `_total`. Samples retain their actual wire
names and labels. Finite float64 values are JSON numbers; `NaN`, `+Inf`, `-Inf` are
strings. Classic sample timestamps are signed integer `timestamp_ms`; OpenMetrics
sample/exemplar timestamps are `timestamp_seconds`. These units are never
silently conflated. Missing help/unit are null. The event contains structured
samples, without raw exposition or arbitrary encodings.

The parser supports classic counter/gauge/histogram/summary/untyped, and OpenMetrics
counter/gauge/histogram/summary/unknown/gaugehistogram/info/stateset, UNIT metadata,
created samples and counter/bucket exemplars. It validates escaping, legacy names,
unique labels/series/metadata, declared type components, quantiles, counter/count
values, histogram bucket order/cumulative counts/+Inf/count agreement, format
timestamps, and mandatory OpenMetrics EOF. It accepts no partial exposition.
There is no protobuf/native-histogram support or OpenMetrics 2.0 claim. This is a
bounded ingestion implementation; it does not claim a complete OpenMetrics
conformance suite or retain metrics across scrapes.

Bounds: 4 MiB body checked before extending accumulated chunks, 20,000 samples,
4,096 families, 64 labels per sample, 256-byte names, 16 KiB decoded label/help
text, 128 characters across exemplar labels, 4,096-byte origin paths. One active
scrape; a whole connect/head/body deadline from startup; eight queued events and
eight handler actions; four handler followup scrapes per chain. New injected
requests start a new chain. A full event queue fails the client closed.

The command channel is registered before the connected event. Two registered,
owned tasks separate event decisions from HTTP exchanges. Manual decisions do not
block injection; a second active scrape is rejected busy; disconnect/removal
cancels the current request and dispatcher. Common memory updates use AppState's
shared client memory and reach followup model events. Static/script/model handlers
use the same typed action vocabulary. No protocol-specific persistence exists.

Primary specifications inspected:
https://prometheus.io/docs/instrumenting/exposition_formats/,
https://prometheus.io/docs/instrumenting/content_negotiation/,
https://github.com/prometheus/OpenMetrics/blob/v1.0.0/specification/OpenMetrics.md.
Independent exporter evidence and exact environment are in
`tests/client/prometheus/AGENTS.md`. No pcap or fuzz evidence is claimed.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/prometheus/`:

1. the peer is a real Prometheus 3 server's own `/metrics` and the official Python exporter — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: Prometheus's own `promhttp_metric_handler_requests_total` counts exactly the one scrape the mocked model chose. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
