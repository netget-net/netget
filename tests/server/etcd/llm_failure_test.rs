//! What an etcd client gets when the LLM backend fails: a non-zero gRPC status, and which one.
//!
//! etcd already answered on this path — it never went silent — so what is under test here is the
//! *choice of code*. Every handler failure was reported as `13 INTERNAL`, including the ones
//! caused by the LLM rate limiter refusing a request because the backend was saturated.
//! `INTERNAL` is explicitly **not** in gRPC's retryable set and is not a code any
//! `grpc-service-config` `retryableStatusCodes` list names, so a backlog that would clear in
//! seconds was handed to every caller as a permanent application error. For etcd that is worse
//! than it sounds: a `Txn`-based distributed lock reports a hard failure rather than a retryable
//! one, and the client gives up.
//!
//! Two things are asserted, and they need different techniques:
//!
//! * **On the wire**, that a plain backend failure really produces `grpc-status: 13` with an
//!   empty body, decoded from the HTTP/2 response headers rather than through a client library
//!   that might synthesise a status of its own. The request is a hand-built protobuf
//!   `RangeRequest` so nothing in this file shares code with the server's own encoder.
//! * **In the classifier**, that an overload maps to `14 UNAVAILABLE` while anything else stays
//!   `13 INTERNAL`. This half cannot be driven end-to-end: the only errors
//!   `crate::llm::is_overload_error` recognises come from the rate limiter, whose bounds are set
//!   by `--llm-queue-timeout` / `--llm-max-queued`, and `tests/helpers/netget.rs` passes neither
//!   (it passes only `--llm-max-concurrent`, at 1000). Reaching `QueueFull` through the harness
//!   would need 129 requests in flight against a mock that answers instantly. So the
//!   classification is exercised directly instead of being faked with an assertion that proves
//!   nothing.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// A `RangeRequest` for key `/config/database`, encoded by hand.
///
/// Field 1 (`key`) is `bytes`, so the wire form is tag `0x0A` (field 1, length-delimited), the
/// length, then the octets. Building it here rather than with `prost` keeps the test independent
/// of the server's own encoder.
fn range_request_frame(key: &str) -> Vec<u8> {
    let mut message = vec![0x0A, key.len() as u8];
    message.extend_from_slice(key.as_bytes());

    let mut frame = vec![0u8]; // compression flag: none
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

#[tokio::test]
async fn test_etcd_answers_internal_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via etcd. Serve the /config/ key space";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via etcd")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ETCD",
                    "instruction": "Serve the /config/ key space"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for `etcd_range_request`: the mock answers HTTP 500, which is
        // what drives the server down its LLM-failure path.
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .http2_prior_knowledge()
        .build()?;
    let url = format!("http://127.0.0.1:{}/etcdserverpb.KV/Range", server.port);

    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(&url)
            .header("content-type", "application/grpc+proto")
            .body(range_request_frame("/config/database"))
            .send(),
    )
    .await
    .map_err(|_| {
        "No gRPC response within 25s - the server went silent on LLM failure, which would be a \
         regression of the defect this whole sweep exists to prevent"
    })??;

    // gRPC carries application failures in `grpc-status`, not in the HTTP status line. A
    // non-200 would make a conformant client discard the code entirely and synthesise one.
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a gRPC status must travel over HTTP 200"
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
        "an LLM failure must never be reported as OK - `grpc-status: 0` with an empty body is a \
         Range that matched nothing, which is a claim about the key space that nothing here is \
         in a position to make"
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

    // No response body: a failure must not be accompanied by anything a client could decode as
    // a RangeResponse.
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

/// An overloaded backend is `14 UNAVAILABLE`; everything else stays `13 INTERNAL`.
///
/// `13` and `14` are the two halves of the same decision, so both are asserted here, including
/// the context-wrapped form — `call_llm` reports rate-limiter refusals underneath an
/// `anyhow::Context` layer, and a classifier that only inspected the outermost error would
/// silently fall back to `INTERNAL` for every real overload.
#[test]
fn overload_is_unavailable_and_everything_else_is_internal() {
    use netget::llm::RateLimitError;
    use netget::server::etcd::grpc_status_for_llm_failure;

    const INTERNAL: i32 = 13;
    const UNAVAILABLE: i32 = 14;

    for refusal in [
        RateLimitError::QueueFull { max_queued: 128 },
        RateLimitError::QueueTimeout { waited_secs: 120 },
        RateLimitError::TokenLimit {
            limit: 10_000,
            window_secs: 60,
        },
    ] {
        assert_eq!(
            grpc_status_for_llm_failure(&anyhow::Error::new(refusal)),
            UNAVAILABLE,
            "a rate-limiter refusal is transient and must be reported as retryable: {refusal:?}"
        );
        assert_eq!(
            grpc_status_for_llm_failure(
                &anyhow::Error::new(refusal).context("LLM call failed for Range")
            ),
            UNAVAILABLE,
            "the same refusal underneath a context layer, which is how call_llm reports it"
        );
    }

    assert_eq!(
        grpc_status_for_llm_failure(&anyhow::anyhow!("model returned unparseable JSON")),
        INTERNAL,
        "a genuine handler fault is not retryable and must stay INTERNAL"
    );
    assert_eq!(
        grpc_status_for_llm_failure(&anyhow::anyhow!("connection refused").context("Ollama")),
        INTERNAL,
        "a backend that is down, rather than saturated, is still INTERNAL here"
    );
}
