//! A handler that produces no response action must not answer the client anyway.
//!
//! `handle_put` already refused this case. `handle_range` and `handle_delete_range` did not, and
//! what they returned instead was not a vague or empty reply — it was a **definite, successful
//! answer**:
//!
//! * A `RangeResponse` with `kvs: []` and `count: 0` means "that key does not exist". A client
//!   cannot tell it apart from a real lookup that found nothing, so a model that declined to
//!   answer, a static handler with an empty action list, or a reply whose actions were all
//!   unrecognised silently asserted the absence of a key.
//! * A `DeleteRangeResponse` with `deleted: 0` under a freshly *incremented* revision means the
//!   delete ran and committed, matching nothing.
//!
//! Both are the fail-open shape the root CLAUDE.md names as the most dangerous pattern in this
//! codebase, wearing the clothes of a normal result. The responses are decoded from the HTTP/2
//! headers by hand so nothing here shares code with the server's encoder, and the requests are
//! hand-built protobuf for the same reason.


use crate::helpers::server::NetGetServer;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// A `RangeRequest` or `DeleteRangeRequest` for `key`, encoded by hand.
///
/// Both messages put `key` in field 1 as `bytes`, so the wire form is identical: tag `0x0A`
/// (field 1, length-delimited), the length, then the octets.
fn key_request_frame(key: &str) -> Vec<u8> {
    let mut message = vec![0x0A, key.len() as u8];
    message.extend_from_slice(key.as_bytes());

    let mut frame = vec![0u8]; // compression flag: none
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

/// Start an etcd server whose handler answers the given event with **zero actions**.
///
/// A zero-action static handler is the cleanest way to express "the handler ran and produced
/// nothing", and it is a shape that really occurs: it is what the dashboard installs for a
/// client's connect events, and `tests/empty_static_handler_test.rs` establishes that it
/// suppresses the LLM call entirely. So the server reaches its response-building code having
/// been given nothing, with no backend error to blame — which is exactly the case that used to
/// produce a confident answer.
async fn server_answering_with_nothing(event: &'static str) -> E2EResult<NetGetServer> {
    let prompt = "listen on port {AVAILABLE_PORT} via etcd. Serve the /config/ key space";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(move |mock| {
        mock.on_instruction_containing("via etcd")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ETCD",
                    "instruction": "Serve the /config/ key space",
                    "event_handlers": [{
                        "event_pattern": event,
                        "handler": { "type": "static", "actions": [] }
                    }]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    start_netget_server(config).await
}

/// Post one hand-built gRPC frame and return `(grpc-status, body length)`.
async fn call(port: u16, method: &str, frame: Vec<u8>) -> E2EResult<(String, usize)> {
    let client = reqwest::Client::builder().http2_prior_knowledge().build()?;
    let url = format!("http://127.0.0.1:{port}/etcdserverpb.KV/{method}");

    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(&url)
            .header("content-type", "application/grpc+proto")
            .body(frame)
            .send(),
    )
    .await
    .map_err(|_| format!("no gRPC response to {method} within 25s"))??;

    // gRPC carries application failures in `grpc-status`, not in the HTTP status line.
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
    let body_len = response.bytes().await?.len();
    Ok((grpc_status, body_len))
}

#[tokio::test]
async fn test_etcd_range_refuses_rather_than_claiming_the_key_is_absent() -> E2EResult<()> {
    let server = server_answering_with_nothing("etcd_range_request").await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let (grpc_status, body_len) =
        call(server.port, "Range", key_request_frame("/config/database")).await?;

    assert_ne!(
        grpc_status, "0",
        "an unanswered Range came back OK - `grpc-status: 0` with an empty RangeResponse is the \
         claim that /config/database does not exist, and nothing here is in a position to make \
         it"
    );
    assert_eq!(
        grpc_status, "13",
        "an unanswered Range is INTERNAL (nothing is saturated, so a retry would not help); \
         got {grpc_status}"
    );
    assert_eq!(
        body_len, 0,
        "a gRPC failure carries no message frame, got {body_len} bytes"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_etcd_delete_refuses_rather_than_reporting_a_commit() -> E2EResult<()> {
    let server = server_answering_with_nothing("etcd_delete_request").await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let (grpc_status, body_len) = call(
        server.port,
        "DeleteRange",
        key_request_frame("/config/database"),
    )
    .await?;

    assert_ne!(
        grpc_status, "0",
        "an unanswered DeleteRange came back OK - a DeleteRangeResponse under a bumped revision \
         tells the client the delete ran and committed"
    );
    assert_eq!(
        grpc_status, "13",
        "an unanswered DeleteRange is INTERNAL; got {grpc_status}"
    );
    assert_eq!(
        body_len, 0,
        "a gRPC failure carries no message frame, got {body_len} bytes"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
