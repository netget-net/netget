# OTLP HTTP and gRPC receiver

Feature `otlp` exposes one receiver on the configured TCP port. The existing HTTP/1.1
paths/encodings remain supported. Hyper's auto connection builder also admits HTTP/2,
including generated tonic unary Export services for traces, metrics and logs on that
same port. 4318 remains the default port; use 4317 explicitly for a conventional gRPC
endpoint. Receiver TLS is outside this subset; the exporter supports authenticated TLS.

`mod.rs` owns bounded accept/connection tasks, HTTP handling and the shared verdict path.
`grpc.rs` routes generated services, admits RPCs before decoding, bounds unary bodies,
and owns Hyper HTTP/2 child tasks. `codec.rs` provides bounded protobuf/JSON summary walks
and all response encoders. `actions.rs` declares the semantic export event and verdicts.

The OpenTelemetry project's opentelemetry-proto 0.29 generated messages/services preserve
the repository's tonic 0.12/prost 0.13 family. gRPC framing, codec/compression, status and
trailers remain library-owned. the `netget-tonic` fork, github.com/netget-net/tonic (NETGET.md) documents its minimal
receive-limit patch: 4 MiB is enforced before and after decompression in either direction.

## Requests and semantic decisions

HTTP POST /v1/traces, /v1/metrics and /v1/logs accepts protobuf or OTLP JSON, with optional
gzip. Content-Type parameters are ignored. Unknown JSON fields are ignored; lowerCamelCase
and snake_case, integer numbers/strings and status names/numbers are supported. JSON is walked
as Value because the generated serde layer is narrower than exporter interoperability.

gRPC paths are the standard opentelemetry.proto.collector.{trace,metrics,logs}.v1
{Trace,Metrics,Logs}Service/Export methods. Requests/responses use generated protobuf and
none/gzip compression. One framed Export message is required. The guard bounds the total
wire body at 4 MiB+5, validates the declared message length before further accumulation, and
rejects extra or incomplete frames before tonic decoding. It prevents tonic's unary trailer
drain from consuming arbitrary additional messages. `compressed` comes from the validated
message prefix: `grpc-encoding: gzip` also permits a message with flag 0. Tonic validates
the compression flag and encoding before dispatch. Request trailer metadata is ignored.

Both transports raise `otlp_export` with a bounded summary, never raw telemetry or IDs:
transport, signal, encoding, compressed, body_bytes, resource_count, service name(s), up to 20
first-resource scalar attributes (values cut 200 bytes), span/error counts and first 10 names,
metric/data-point counts and first 10 names, or log/error counts and first 5 bodies cut 200 bytes.
Arrays/maps/bytes are described by size rather than expanded. The event carries answer_with.

The first semantic verdict is sent:

| Action | HTTP | gRPC |
|---|---|---|
| accept_otlp |200 empty Export response|OK empty generated response|
| accept_otlp_partially |200 partial_success|OK partial_success|
| reject_otlp |declared allowed status + google.rpc.Status|mapped gRPC status, optional RetryInfo|

Partial counts are clamped to the export's item count. Allowed refusal statuses are
400/401/403/413/429/500/502/503/504, mapped to the codec's corresponding gRPC code. HTTP
Retry-After is sent only for 429/502/503/504. gRPC supplies google.rpc.RetryInfo when that
delay is present; RESOURCE_EXHAUSTED without RetryInfo is permanently nonretryable.
Backend overload fails closed 503/UNAVAILABLE, other backend failures 500/INTERNAL, each
with a fixed category message. No usable verdict fails closed 500/INTERNAL. No backend
error text is sent. Responses update connection statistics; gRPC request statistics count
decoded protobuf bytes and requests. There is no receiver storage/forwarding/domain state.

## Ownership and bounds

The accept loop and each connection belong to AppState. A connection owns an executor
guard which aborts every Hyper HTTP/2 child task on exit/removal, including a parked manual
handler. Finished handles are pruned. This explicit guard works even when executor clones
remain inside a child task. Operation permits drop on completion, cancellation or deadline.

| Bound | Value |
|---|---|
| TCP connections |256; overflow HTTP 503 + Retry-After 5 then close|
| First byte |30s|
| Idle between requests |120s; an active request is not idle|
| HTTP body before/after gzip |4MiB|
| gRPC message before/after gzip |4MiB; overflow RESOURCE_EXHAUSTED without RetryInfo|
| gRPC unary raw body |4MiB+5; one message|
| HTTP/2 concurrent streams/connection |16|
| HTTP/2 initial stream/connection window |64KiB /1MiB|
| HTTP/2 header list/frame |32KiB /16KiB|
| Global active gRPC exports |64, acquired before reading/decoding; overflow UNAVAILABLE|
| Whole gRPC request |30s, including body and model; smaller valid grpc-timeout honored; duplicates invalid|
| Nesting |prost 100 / serde_json 128; NetGet summaries do not recurse into attributes|

HTTP routing failures retain 404/405+Allow/415/400/413 behavior. A gRPC prefix/body bound
fails closed before asking the model. Client cancellation and receiver removal drop parked
handlers. This remains request-only: no unprompted receiver message action exists.

Expanded surface is Experimental. The previous HTTP subset had Beta evidence from independent
otel-cli and telemetrygen; both now also exercise gRPC. No pcap oracle or fuzz target exists.
No profiles, receiver TLS/mTLS, persistent ingestion, forwarding or third-party JSON sender
evidence is claimed. See tests/server/otlp/AGENTS.md and tests/client/otlp/AGENTS.md.
