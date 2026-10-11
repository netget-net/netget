# InfluxDB v2 write collector and query endpoint

Implemented Experimental scope: POST /api/v2/write surface, typed native line protocol,
ns/us/ms/s timestamps, identity/gzip bodies, Token/Bearer authentication when a token
is configured, model-controlled acceptance/rejection/partial decisions. Standard bounded
access logs and shared memory only; no private time-series/schema storage. Queries are
answered by the handler (see Queries below), never from anything NetGet kept.

Primary references: https://docs.influxdata.com/influxdb/v2/api/write/ and
https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/.
Independent receiver uses unmodified MIT InfluxData line-protocol v2.2.1 decoder behind a
test-only v2 HTTP contract; it is a decoder-backed receiver, not an official InfluxDB daemon.
Official Python InfluxDB2 client 1.50.0 is the independent emitter. Official InfluxDB 2.9.1
is the service receiver, with official Python readback. Daemon evidence is mandatory on
Linux/macOS; macOS uses existing amd64 execution support. Do not claim Beta/Stable, complete InfluxDB, schema
conflict tracking, durable delivery, auth roles/org ACLs, TLS listener or retries.

Bounds:256 KiB compressed/decompressed body, 16 KiB line, 256 points, 1024 source lines,
64 tags/fields, 1024 byte names/org/bucket/token, 256 connections, 32 KiB/64 headers,
30s absolute header/body deadlines, 10s response-write deadline. No read/write timer wraps
the event handler; manual handlers keep their ordinary intercept timeout. Every listener
and peer task is owned by AppState. One request per TCP connection; stop releases sockets.
The quoted string subset excludes CR/LF/NUL; names exclude ASCII controls and trailing
backslashes. Single field/timestamp separators only; reserved underscore namespace/time
tag and field keys are rejected. Timestamps normalize with checked ns/us/ms/s arithmetic.

`influx_write` contains org, bucket, precision, typed points with source line/timestamp_ns,
syntax errors and authentication facts. No raw payload or token reaches event handlers.
Accept valid lines by default; syntax errors return400 with line and explicit counts.
Successful configured handlers without a protocol decision accept valid lines. Mixed
failed actions, dispatch failure, multiple decisions or invalid subsets fail closed503.
Configured actions can accept all, accept a valid subset or reject with bounded JSON
code/message and optional numeric Retry-After. No acceptance means persistent storage.

Peer licenses are MIT. Decoder archive SHA256 and every Python dependency version are
pinned in install_peers.py; official daemon platform hashes come from the v2.9.1 release
manifest (the install guide has obsolete example hashes):
https://github.com/influxdata/influxdb/releases/tag/v2.9.1.

## Queries (`query.rs`)

`POST /api/v2/query` takes Flux (a JSON `{"query", "type"}` body as every official client sends
it, or `application/vnd.flux`) and answers in **annotated CSV**: `#datatype`, `#group`,
`#default`, a header `,result,table,…`, then rows. Each table the handler supplies is its own
annotated block, separated by an empty line, with its index in the `table` column; a table's
`measurement` becomes `_measurement` and its tags become string columns, all in the group key.
Errors are v2 JSON `{code, message}`. `GET|POST /query` takes InfluxQL — `q`, `db`, `rp`,
`epoch` from the query string or a form body (the v1 Python client uses the first, a form POST
the second) — split on `;` outside quotes, and answers v1 JSON: one result per statement with
`series` (`name`, `tags`, `columns`, `values`) or a per-statement `error`. `epoch` turns times
into integers in that unit; **an empty `epoch=` means RFC 3339**, because node-influx sends one
whenever no precision was asked. `chunked=true` is refused rather than answered unchunked.
`GET|HEAD /ping` is 204.

The token is also accepted for InfluxQL the two v1 ways InfluxDB 2's compatibility API accepts:
the `p` parameter (node-influx) and the password of HTTP Basic (the v1 Python client). The user
name is not checked, as InfluxDB 2 does not check it. On the Flux endpoint `p` is not a
credential.

`influx_query` carries the dialect, the query, the split statements and org/db/rp/epoch — never
the credential. Answers: `send_influx_query_result` (`tables`, or for InfluxQL `statements` with
one entry per statement) and `send_influx_query_error`. Every cell is checked against its
column's declared type in `execute_action`, so a `long` column holding `0.5` is an action
failure the model hears about, not a rounded number on the wire. A table for a multi-statement
query, or `statements` for Flux, does not say what it answers and fails closed.

**With no `influx_query` handler and `llm_fallback` off, a query is 503, not an empty result.**
An empty result asserts there is no data, and nobody made that assertion. Every other way of
not having an answer — the handler errored, an action failed, no answer action, two of them,
an answer that does not render — is the same 503 with its own `decision=fail_closed_*` tag.

Query bounds: 16 KiB query, 16 statements, 64 tables, 64 columns and 64 tags per table, 10 000
rows, 64 KiB per cell, tag or name, 4 MiB rendered answer. Flux repeats a table's measurement
and tags on every row, so `render_flux` measures each line before appending it and refuses the
answer at the line that would pass 4 MiB; it never builds a larger answer to measure it.
