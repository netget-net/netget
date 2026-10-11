# InfluxDB v2 write emitter and query client

HTTP-only logical session, one fresh HTTP/1.1 TCP exchange per typed write. Use ordinary
client event handlers, memory and command injection. Poll the HTTP connection driver inside
the owned session future; never detach it. Disconnect/remove-client must cancel a parked
handler and an in-flight exchange. Validate the whole batch before opening a socket.

The token is a startup credential only, never an action field/event/access-log value. Emit
`Authorization: Token ...`, `/api/v2/write?org=...&bucket=...&precision=...`, text/plain UTF-8,
and identity/gzip. Require empty 204 success or bounded typed JSON error; expose HTTP status,
partial-write counts/line and numeric Retry-After without retries. No TLS, redirects,
durable queue, HTTP-date retry advice or server persistence claims.

Independent receiver uses unmodified InfluxData line-protocol v2.2.1 decoder inside a small
test HTTP adapter which validates route/query/auth/encoding/response semantics. It is a
decoder-backed receiver, not an official InfluxDB daemon. The additional mandatory Linux/
macOS official 2.9.1 service test closes the service gap, with independent Python readback
for all five kinds and four timestamp precisions plus real401/404 responses. Windows has
no daemon fixture. No new Cargo dependencies; flate2 is already present.

Bounds:256 KiB encoded/compressed body, 16 KiB line, 256 points, 64 tags/fields, 1024 byte names/
org/bucket/token; 64 KiB response, 32 KiB/64 response headers, 128 byte code/1024 byte message;
10s whole exchange, one in-flight write, 32 queued response events/handler actions, 8 follow-up
depth. Commands remain independent of parked handlers and active IO; another write while
busy is rejected atomically. The logical local address is0.0.0.0:0, because TCP opens only
for a write. Standard shared memory refreshes per event; HTTP failures raise typed events
and keep the logical session open. Malformed/oversized responses or transport errors close
the session without retries. Disconnect/removal drops the live HTTP driver/socket future.

## Queries (`query.rs`)

`query_influx_flux` (`org`, `query`) posts to `/api/v2/query` asking for the three annotations,
and `query_influxql` (`query`, `db`, `rp`, `epoch`) issues `GET /query` — on InfluxDB 2 the
database is a bucket's DBRP mapping, and every bucket has a virtual one. The answer is one
`influx_query_response` event, and **the model never sees CSV**: `read_flux` splits RFC 4180
records (quoted commas, doubled quotes, line breaks), reads each block's `#datatype`, `#group`
and `#default`, converts each cell by its datatype (`long` → integer, `boolean` → boolean, an
empty cell → the column default or `null`) and groups rows into tables by `result`/`table`.
InfluxQL's v1 JSON is passed through series by series. A non-2xx answer is `{code, message}`
from either error shape. A 2xx answer that cannot be read — wrong type, malformed CSV, or a
Flux failure reported in-band as an `error` table after the status line — is an error event,
not a closed session.

An event carries at most 1000 rows and 64 tables, with `row_count`, `reported_rows` and
`truncated` saying what was left out. The answer body is capped at 4 MiB and the exchange at
30 s. Query and write share the one-request-in-flight rule and the follow-up depth bound.

The 4 MiB body cap does not by itself bound what reading it costs, so the Flux reader holds
only what an event can carry. `CsvRecords` yields one record at a time and refuses a record
past `MAX_COLUMNS + 1` fields at the comma that passes it. A header's column descriptors are
built once and shared by every row and table under it; a header's names and each annotation
row are capped at `MAX_HEADER_BYTES` (16 KiB), since descriptors and `#default` values are
copied into the event. Only the first 64 tables and the first 1000 rows are stored — every
later row is still checked against its datatype, then counted (`read_flux` returns
`FluxAnswer { tables, table_count, row_count }`). Server-supplied error text — a v2/v1 error
body's `code` and `message`, an in-band Flux `error`, an InfluxQL statement's `error`, and why
a 2xx answer could not be read — reaches the model cut to `MAX_ERROR_TEXT_BYTES` (1024) on a
char boundary.
