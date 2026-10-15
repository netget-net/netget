//! What a gRPC client gets when the LLM backend fails: a non-zero status, and which one.
//!
//! This server already answered on this path — it never went silent — so what is under test is
//! the *choice of code*. Every handler failure was reported as `13 INTERNAL`, including the ones
//! caused by the LLM rate limiter refusing a request because the backend was saturated.
//! `INTERNAL` is explicitly **not** in gRPC's retryable set and is not a code any
//! `grpc-service-config` `retryableStatusCodes` list names, so a backlog that would clear in
//! seconds reached every caller as a permanent application error and no retry policy could act
//! on it.
//!
//! Two things are asserted, and they need different techniques:
//!
//! * **On the wire**, that a plain backend failure produces HTTP 200 with `grpc-status: 13` and
//!   an empty body — read from the response headers rather than through a client that could
//!   synthesise a status of its own.
//! * **In the classifier**, that an overload maps to `14 UNAVAILABLE` while everything else
//!   stays `13 INTERNAL`. This half cannot be driven end-to-end: the only errors
//!   `crate::llm::is_overload_error` recognises come from the rate limiter, whose bounds are set
//!   by `--llm-queue-timeout` / `--llm-max-queued`, and `tests/helpers/netget.rs` passes neither
//!   (only `--llm-max-concurrent`, at 1000). Reaching `QueueFull` through the harness would need
//!   129 requests in flight against a mock that answers instantly. So the classification is
//!   exercised directly rather than faked with an assertion that proves nothing.
//!
//! A third case is covered by `test_grpc_answers_internal_when_handler_returns_no_usable_action`:
//! the handler *succeeds* but returns an action that is neither `grpc_unary_response` nor
//! `grpc_error`. `handle_unary` used to fall back to encoding an empty `DynamicMessage` and ship it
//! as `grpc-status: 0` — indistinguishable from a deliberate empty response — which is the
//! fail-open this sweep exists to close. It now answers `13 INTERNAL` with an empty body, so the
//! only reply carrying `grpc-status: 0` is one the handler actually produced.
//!
//! The empty-body assertion matters as much as the code: a gRPC failure carries no message frame,
//! so `grpc-status: 0` plus a five-byte frame and `grpc-status: 13` plus nothing are what
//! distinguish "the model answered" from "the model said nothing usable" or "the model could not
//! be reached".

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

const PROTO_SCHEMA: &str = r#"
syntax = "proto3";

package failtest;

service EchoService {
  rpc Echo(EchoRequest) returns (EchoReply);
}

message EchoRequest {
  string text = 1;
}

message EchoReply {
  string text = 1;
}
"#;

/// An `EchoRequest { text: "hello" }`, encoded by hand.
///
/// Field 1 is a `string`, so the wire form is tag `0x0A` (field 1, length-delimited), the length,
/// then the UTF-8 octets. Built here rather than with `prost-reflect` so the test shares no
/// encoder with the server.
fn echo_request_frame(text: &str) -> Vec<u8> {
    let mut message = vec![0x0A, text.len() as u8];
    message.extend_from_slice(text.as_bytes());

    let mut frame = vec![0u8]; // compression flag: none
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

#[tokio::test]
async fn test_grpc_answers_internal_when_llm_fails() -> E2EResult<()> {
    if std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .is_err()
    {
        panic!(
            "protoc not found in PATH. Install it with `brew install protobuf` (macOS) or \
             `apt-get install protobuf-compiler` (Linux)."
        );
    }

    let prompt = format!(
        "Start a gRPC server on port {{AVAILABLE_PORT}} with this schema:\n{PROTO_SCHEMA}\n\
         Echo back whatever text you are sent."
    );

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("gRPC server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gRPC",
                    "instruction": "Echo back whatever text you are sent",
                    "startup_params": { "proto_schema": PROTO_SCHEMA }
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for `grpc_unary_request`: the mock answers HTTP 500, which is
        // what drives the server down its LLM-failure path.
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .http2_prior_knowledge()
        .build()?;
    let url = format!("http://127.0.0.1:{}/failtest.EchoService/Echo", server.port);

    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(&url)
            .header("content-type", "application/grpc")
            .body(echo_request_frame("hello"))
            .send(),
    )
    .await
    .map_err(|_| {
        "No gRPC response within 25s - the server went silent on LLM failure, which would be a \
         regression of the defect this whole sweep exists to prevent"
    })??;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a gRPC status must travel over HTTP 200; a non-200 makes a conformant client discard \
         the code and synthesise one of its own"
    );

    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing")
        .to_string();
    let grpc_message = response
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    assert_ne!(
        grpc_status, "0",
        "an LLM failure must never be reported as OK - the empty-message fallback in \
         handle_unary would otherwise be indistinguishable from a backend outage"
    );
    assert_eq!(
        grpc_status, "13",
        "a plain (non-overload) backend failure is INTERNAL; got {grpc_status} \
         (grpc-message: {grpc_message:?})"
    );
    assert!(
        grpc_message.contains("netget"),
        "the status message should name the source of the failure: {grpc_message:?}"
    );

    let body = response.bytes().await?;
    assert!(
        body.is_empty(),
        "a gRPC failure carries no message frame, got {} bytes",
        body.len()
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The handler *ran and answered*, but produced no usable action — the fail-open trap.
///
/// This is a different path from `test_grpc_answers_internal_when_llm_fails`: there the backend
/// was unreachable and `call_llm` returned `Err`. Here `call_llm` **succeeds** — the mock answers
/// HTTP 200 with a perfectly valid action — but the action is neither `grpc_unary_response` nor
/// `grpc_error`, so `handle_unary` matches nothing. The old code fell through to encoding an empty
/// `DynamicMessage` and shipping it as `grpc-status: 0`, which is byte-for-byte what a handler that
/// *deliberately* returned an empty `grpc_unary_response { }` produces. A model that never gave a
/// usable answer was therefore indistinguishable, on the wire, from one that succeeded with an
/// empty reply — exactly the fail-open the root CLAUDE.md warns against (OAuth2's "no answer became
/// approval"). The fix reports `13 INTERNAL` here so the two are structurally distinct: a real
/// empty response still travels through `grpc_unary_response` and reaches the wire as `grpc-status: 0`.
#[tokio::test]
async fn test_grpc_answers_internal_when_handler_returns_no_usable_action() -> E2EResult<()> {
    if std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .is_err()
    {
        panic!(
            "protoc not found in PATH. Install it with `brew install protobuf` (macOS) or \
             `apt-get install protobuf-compiler` (Linux)."
        );
    }

    let prompt = format!(
        "Start a gRPC server on port {{AVAILABLE_PORT}} with this schema:\n{PROTO_SCHEMA}\n\
         Echo back whatever text you are sent."
    );

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("gRPC server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gRPC",
                    "instruction": "Echo back whatever text you are sent",
                    "startup_params": { "proto_schema": PROTO_SCHEMA }
                }
            ]))
            .expect_calls(1)
            .and()
            // The handler answers successfully, but with an action that is NOT a gRPC response:
            // `show_message` executes cleanly and leaves `handle_unary` with nothing to send. This
            // is the "model returned nothing usable" case, distinct from the backend being down.
            .on_event("grpc_unary_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "show_message",
                    "message": "I looked at the request but produced no gRPC response for it"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .http2_prior_knowledge()
        .build()?;
    let url = format!("http://127.0.0.1:{}/failtest.EchoService/Echo", server.port);

    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(&url)
            .header("content-type", "application/grpc")
            .body(echo_request_frame("hello"))
            .send(),
    )
    .await
    .map_err(|_| {
        "No gRPC response within 25s - the server went silent when the handler produced no usable \
         action, which would itself be a regression"
    })??;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a gRPC status must travel over HTTP 200; a non-200 makes a conformant client discard \
         the code and synthesise one of its own"
    );

    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing")
        .to_string();
    let grpc_message = response
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    assert_ne!(
        grpc_status, "0",
        "a handler that produced no usable action must NOT be reported as OK - an empty-OK reply \
         is indistinguishable from a deliberate empty response, which is the fail-open defect"
    );
    assert_eq!(
        grpc_status, "13",
        "a handler that ran but produced no usable response is a genuine (non-retryable) INTERNAL \
         error, not a transient UNAVAILABLE; got {grpc_status} (grpc-message: {grpc_message:?})"
    );
    assert!(
        grpc_message.contains("no usable response"),
        "the status message should say the handler produced no usable response, distinguishing it \
         from a backend outage: {grpc_message:?}"
    );

    let body = response.bytes().await?;
    assert!(
        body.is_empty(),
        "a gRPC failure carries no message frame, got {} bytes",
        body.len()
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// An overloaded backend is `UNAVAILABLE`; everything else stays `INTERNAL`.
///
/// Both halves are asserted, including the context-wrapped form: `call_llm` reports rate-limiter
/// refusals underneath an `anyhow::Context` layer, and a classifier that only inspected the
/// outermost error would silently fall back to `INTERNAL` for every real overload.
#[test]
fn overload_is_unavailable_and_everything_else_is_internal() {
    use netget::llm::RateLimitError;
    use netget::server::grpc::{grpc_status_for_llm_failure, GrpcStatus};

    for refusal in [
        RateLimitError::QueueFull { max_queued: 128 },
        RateLimitError::QueueTimeout { waited_secs: 120 },
        RateLimitError::TokenLimit {
            limit: 10_000,
            window_secs: 60,
        },
    ] {
        assert_eq!(
            grpc_status_for_llm_failure(&anyhow::Error::new(refusal)) as i32,
            GrpcStatus::Unavailable as i32,
            "a rate-limiter refusal is transient and must be reported as retryable: {refusal:?}"
        );
        assert_eq!(
            grpc_status_for_llm_failure(&anyhow::Error::new(refusal).context("LLM call failed"))
                as i32,
            GrpcStatus::Unavailable as i32,
            "the same refusal underneath a context layer, which is how call_llm reports it"
        );
    }

    assert_eq!(
        grpc_status_for_llm_failure(&anyhow::anyhow!("model returned unparseable JSON")) as i32,
        GrpcStatus::Internal as i32,
        "a genuine handler fault is not retryable and must stay INTERNAL"
    );
    assert_eq!(
        grpc_status_for_llm_failure(&anyhow::anyhow!("connection refused").context("Ollama"))
            as i32,
        GrpcStatus::Internal as i32,
        "a backend that is down, rather than saturated, is still INTERNAL here"
    );

    // The numbers themselves, since they are what a client's retry policy is configured with.
    assert_eq!(GrpcStatus::Unavailable as i32, 14);
    assert_eq!(GrpcStatus::Internal as i32, 13);
}
