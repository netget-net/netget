//! What an OTLP exporter gets when the model cannot, or will not, decide.
//!
//! * A backend failure refuses the export — 503 with `Retry-After` when the backend is
//!   saturated, 500 otherwise — with a fixed `google.rpc.Status` message in the request's own
//!   encoding. Never an invented 200: accepting tells the exporter to discard its copy.
//! * A model that answers with no verdict is refused 500 and logged `model_silent`, told apart
//!   from an outage.
//! * A partial success never claims more rejected items than the export carried.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- otlp::llm_failure --test-threads=100


use super::common::{self, post, static_handler, traces_json, traces_protobuf, JSON, PROTOBUF};
use netget::server::otlp::codec::RpcStatus;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse;
use prost::Message;

const LEAKS: &[&str] = &[
    "http://",
    "127.0.0.1:1",
    "ollama",
    "Ollama",
    "retries",
    ".rs:",
    "error sending request",
    "Connection refused",
];

#[tokio::test]
async fn a_backend_failure_refuses_the_export_with_a_fixed_status_in_its_own_encoding() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start_with(&state, "Accept everything", Vec::new()).await;

    for (header, body) in [
        (PROTOBUF, traces_protobuf("s", &["a"])),
        (JSON, traces_json("s", &["a"])),
    ] {
        let reply = post(port, "/v1/traces", &[header], &body).await;
        assert!(
            reply.status == 500
                || (reply.status == 503 && reply.header("retry-after") == Some("5")),
            "{} {:?}",
            reply.status,
            reply.headers
        );
        assert_eq!(reply.header("content-type"), Some(header.1));
        let message = if header == JSON {
            reply.json()["message"].as_str().unwrap().to_string()
        } else {
            RpcStatus::decode(&*reply.body).unwrap().message
        };
        assert!(
            message == "netget: request could not be processed"
                || message == "netget: backend at capacity, retry later",
            "{message:?}"
        );
        let text = String::from_utf8_lossy(&reply.body);
        for leak in LEAKS {
            assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
        }
    }
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 60).await;
}

#[tokio::test]
async fn a_handler_with_no_verdict_is_refused_not_accepted() {
    let state = common::new_state().await;
    let (_id, port, mut rx) =
        common::start(&state, vec![static_handler(serde_json::json!([]))]).await;
    let reply = post(port, "/v1/traces", &[JSON], &traces_json("s", &["a"])).await;
    assert_eq!(reply.status, 500);
    assert_eq!(
        reply.json()["message"],
        "netget: the receiver reached no decision on this export"
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn a_partial_success_never_rejects_more_than_was_sent() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![static_handler(serde_json::json!([
            {"type": "accept_otlp_partially", "rejected": 50, "error_message": "all of it"}
        ]))],
    )
    .await;
    let reply = post(
        port,
        "/v1/traces",
        &[PROTOBUF],
        &traces_protobuf("s", &["a", "b"]),
    )
    .await;
    assert_eq!(reply.status, 200);
    let partial = ExportTraceServiceResponse::decode(&*reply.body)
        .unwrap()
        .partial_success
        .unwrap();
    assert_eq!(partial.rejected_spans, 2, "clamped to the two spans sent");
    common::wait_for_log(&mut rx, "rejected=2 of 2", 10).await;
}

#[tokio::test]
async fn a_model_refusal_is_sent_and_logged_as_model_reject() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![static_handler(serde_json::json!([
            {"type": "reject_otlp", "code": 403, "message": "unknown sender",
             "retry_after_secs": 9}
        ]))],
    )
    .await;
    let reply = post(port, "/v1/traces", &[JSON], &traces_json("s", &["a"])).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.header("retry-after"), None, "403 is not retryable");
    assert_eq!(
        reply.json(),
        serde_json::json!({"code": 7, "message": "unknown sender"})
    );
    common::wait_for_log(&mut rx, "decision=model_reject status=403", 10).await;
}
