# InfluxDB client checks

Mandatory decoder-backed independent receiver, with all five field kinds, escaping, four
timestamp precisions and gzip. Validate HTTP v2 route/query/auth/content-type/content-encoding
and require the peer's typed observations and status response. Fail if the pinned peer is
absent; never return early or mark ignored.

Exercise native pair handlers, explicit partial/error responses, atomic rejection before
socket creation, command injection during parked handlers, in-flight disconnect/removal,
response-body/time limits, event/action/follow-up bounds and shared-memory refresh. Cleartext
HTTP only. Mandatory official InfluxDB 2.9.1 service fixture on Linux/macOS (no missing-peer
skip), isolated data/telemetry disabled, all five kinds/four precisions/gzip writes followed
by official Python readback and actual401/404 errors. Daemon bootstrap contract and exact
environment are documented in tests/server/influxdb/CLAUDE.md. Windows has native and
decoder-backed evidence only. Service bootstrap fails explicitly on unsupported platforms.

`query_test.rs` starts its own official 2.9.1 daemon (org `netget`, bucket `telegraf`), writes
three points through NetGet's write action and reads them back through NetGet's own queries:
Flux into seven typed tables (doubles, longs, booleans, a CSV-quoted string, group-key flags,
RFC 3339 times) and a two-statement InfluxQL query through the bucket's virtual DBRP mapping
with `epoch=s`. It also asserts the daemon's own refusals as events — a Flux 400 `invalid`, an
InfluxQL parse error (InfluxDB 2 answers `{"code":"invalid","message":"failed to parse query…"}`,
not v1's `{"error"}`), an unknown org (400, not 404) and a wrong token (401). A second test
drives connect → write → write response → query → answer through static handlers alone.
Turning off the typed conversion fails both the daemon test and the reader test.
`reported_rows_stop_at_the_bound` points the client at NetGet's own server for a 1001-row
answer in each dialect — a bound test, not interoperability evidence.

`flux_bounds_test.rs` needs no peer. It reads hostile Flux answers directly with `read_flux`
and serves them from a fake HTTP server on 127.0.0.1 to `query()`: 9 000 rows each in a table
of its own under a near-limit header (64 tables kept, 9 000 counted, prompt), a 1.5 MiB header
(refused as `unreadable_answer`), annotation and header rows at and past `MAX_HEADER_BYTES`, a
4 MiB record of commas (refused at the comma past `MAX_COLUMNS + 1`), and error text — v2 and
v1 bodies, an in-band Flux error, an unparsable cell, an InfluxQL statement error — each
reaching the event within `MAX_ERROR_TEXT_BYTES` plus the `...` marker.
