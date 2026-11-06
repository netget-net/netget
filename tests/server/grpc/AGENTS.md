# Generic gRPC Server Verification

Experimental expanded unary/streaming/reflection scope. No checks skip missing peers.

`streaming_test.rs` uses mandatory independently generated grpcio 1.75.1 (C++ transport) and
grpcurl 1.9.4 (grpc-go) for all three stream forms/gzip and reflection list/describe/invoke
without a supplied proto. grpcurl drives each streaming shape through reflection alone:
server-streaming `Watch`, client-streaming `Collect` (three messages, one reply after
half-close counting them) and bidirectional `Chat` (two messages, one derived reply each), in
`independent_grpcurl_client_streaming_and_bidi`; the handler must see every message, and
dropping the per-message event fails it. grpcurl does not negotiate gzip, so compression
rests on grpcio alone. grpcio checks v1alpha; generated tonic v1 checks query and wire
bounds. Native requests verify exact 4 MiB/+1 before/after gzip,128/+1 reflection queries,
64 KiB/+1 reflection messages, opt-out, parked-handler cancellation/server removal, whole
RPC deadlines including unclosed input,64 global admission and released-slot recovery.

`schema_bounds_test.rs` checks exact 4 MiB/+1 startup descriptors,128/+1 files, built-in
reflection totals, reserved descriptors, depth 32/+1, expanded-name/node preflight and typed
stream schema exclusions (nested bytes and 128/+1 fields). No raw descriptor reaches a model.

Pinned peer environment: install `tests/helpers/grpcio-peer-requirements.txt` into an owned
venv and set NETGET_GRPCIO_PYTHON to its Python. grpcio/tools/reflection1.75.1,protobuf 6.32.1,
setuptools 80.9.0,typing_extensions 4.15.0. protoc 36.1 and grpcurl 1.9.4 are mandatory. Peer
servers bind port0 directly and report readiness; Rust owns/kills each fixture child.
TLS fixture needs openssl. Test commands use the programme shared run_cargo.py guard.

Legacy checks remain: five mocked unary schema/routing checks; two mandatory grpcurl
unary success/error checks; failure/status classification and connection bounds. Raw HTTP/2
reqwest/prost probes are useful for framing but cannot inspect trailers and are not an
independent gRPC implementation. The expanded scope is Experimental; the pcap oracle covers the two grpcurl unary calls and `fuzz/fuzz_targets/grpc_message.rs` the unary decode path (see the end of this file).

## Unary trailers regression evidence

That gap hid a defect that broke **every successful RPC** against a real client. Until
September 2026 the server wrote `grpc-status` into the initial HEADERS and emitted no trailers;
a success has a non-empty body, so the stream ended after DATA with nothing, and grpcurl
answered `Internal: server closed the stream without sending trailers` to every call. Errors
were unaffected — an empty body makes them Trailers-Only by accident — so **only the success
path was broken and the failure paths were the ones being asserted on**. `test_grpc_unary_rpc_basic`
asserted `grpc-status: 0` *on the initial headers*, which is precisely the assertion that kept
the bug satisfied; it now asserts that header is absent and checks the reply frame instead.

The success test in `real_client_test.rs` was written `#[ignore]`d against the broken server,
describing correct behaviour rather than the behaviour of the day. It is now un-ignored and is
the regression test.


The 30s preface deadline and 900s idle watchdog retain their prior wire tests. A silent peer
closes; a peer that sent the preface gets a SETTINGS ACK 38s later. Removing the peek timeout
makes the silent-peer test fail at its 70s window. The watchdog is idle-only; new stream
body guards and deadlines cover parked model work and response flow control independently.

## Current execution

Final server suite: 24 passed, 0 failed/ignored at 100 threads, 38.52s (includes12 retained
unary/status/connection checks). Log: programme logs/item68-grpc-server-full.log.
Earlier fixture compile errors, incorrect status/header expectations and the missing
second tonic readiness poll remain in the preparatory logs; none is claimed as a pass.

## Stable conditions 2 and 3: the pcap oracle and the fuzz target

The rating is Experimental, so these are evidence for the surface rather than a step toward
Stable; condition 1 is the expanded scope's to settle first.

**Condition 2.** Both grpcurl tests in `real_client_test.rs` run through a recording relay and
the pcap oracle reads each connection with Wireshark's `http2` and `grpc` dissectors: the
success shape (HEADERS, a DATA frame with the message, trailing HEADERS) and the Trailers-Only
error shape. Streaming, gzip and reflection traffic (the grpcio peer tests) are not captured.

**Condition 3.** `fuzz/fuzz_targets/grpc_message.rs` drives `grpc::decode_grpc_frame`,
`DynamicMessage::decode` against a deliberately recursive schema, `value_codec`'s bounded JSON
conversion and `stream_codec::to_json`. Its corpus carries three 20 000-level bombs (nested
`child`, nested map values, nested unknown groups) for prost's recursion limit and a 90-level
message for `MAX_VALUE_DEPTH` (32). run 120 s clean on 1 November 2026 (unoptimised, `-s none`, macOS): 18 666 executions, no crash.
