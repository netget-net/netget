//! What the Elasticsearch server must refuse rather than answer affirmatively.
//!
//! **An oversized request body.** `Incoming` has no default limit, so the handler buffered
//! whatever an unauthenticated peer chose to send — a single `POST /_bulk` was enough — and
//! the body is then embedded whole in an LLM prompt, so there is no legitimate large one
//! either. The refusal has to land *before* the model call, which is why this test counts
//! model calls as well as checking the status.
//!
//! **Responses that assert more than the handler did.** Three fields were declared
//! `required: true` and silently defaulted, and every default was the affirmative answer:
//! `send_index_response`'s `result` defaulted to `"created"`, which is what makes the reply a
//! 201; `send_cluster_health`'s `status` defaulted to `"green"`, so a handler that said
//! nothing reported a fully-allocated cluster; `send_get_response`'s `found` defaulted to
//! `false`, so a mistyped `"true"` (a string, not a JSON boolean) became "no such document".
//!
//! **`errors` in a bulk response.** Clients check it before deciding whether to walk `items`
//! at all, so defaulting it to `false` hid per-item failures the handler had itself reported.
//! It is now derived from the items when omitted — observable rather than assumed.


use crate::server::helpers::*;
use ::netget::llm::actions::protocol_trait::{ActionResult, Server};
use ::netget::server::ElasticsearchProtocol;
use serde_json::json;

#[tokio::test]
async fn an_oversized_body_is_refused_with_413_before_any_llm_call() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Start Elasticsearch on port {AVAILABLE_PORT}").with_mock(|mock| {
            mock.on_instruction_containing("Elasticsearch")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Elasticsearch",
                    "instruction": "Elasticsearch server"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately no rule for `elasticsearch_request`: if the oversized body reached
            // the model, the request would fall through to a real LLM call and the server
            // would answer 500, not 413.
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;

    // Wait for the bind before sending. Without this the POST races the listener: under a
    // 100-thread run it is refused at connect, which surfaces as a transport error rather
    // than an assertion, so the failure reads as "the body limit is broken" when the server
    // had simply not finished starting.
    //
    // This is the same defect the September hygiene sweep removed from 74 sites; these two
    // test files were written after it, in different waves, and reintroduced it
    // independently — which is why the helper is the thing to reach for rather than a sleep.
    crate::helpers::common::wait_for_server_listening(
        &test_state,
        std::time::Duration::from_secs(30),
    )
    .await?;

    let oversized = "x".repeat(9 * 1024 * 1024);
    let body = format!("{{\"index\":{{\"_index\":\"big\"}}}}\n{{\"blob\":\"{oversized}\"}}\n");

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/_bulk"))
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await?;

    assert_eq!(
        resp.status(),
        413,
        "an oversized body must be refused with 413; a 500 would mean it reached the model, \
         and a 2xx would mean it was silently truncated to nothing and answered as an empty \
         bulk request"
    );
    let json: serde_json::Value = resp.json().await?;
    assert_eq!(json["error"]["type"], "circuit_breaking_exception");
    assert_eq!(
        json["status"], 413,
        "the `status` inside the envelope must agree with the HTTP status or clients report \
         the wrong thing"
    );

    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[test]
fn affirmative_fields_are_not_defaulted() {
    let p = ElasticsearchProtocol::new();

    for action in [
        // `result` decides 201 Created.
        json!({"type": "send_index_response", "index": "products", "id": "abc"}),
        // `status` is the entire content of a health check.
        json!({"type": "send_cluster_health", "cluster_name": "c"}),
        // `found` decides 200-with-a-document versus 404.
        json!({"type": "send_get_response", "index": "products", "id": "abc"}),
        // A string is not a JSON boolean, and used to collapse to 404.
        json!({"type": "send_get_response", "index": "p", "id": "a", "found": "true"}),
    ] {
        p.execute_action(action.clone())
            .expect_err(&format!("{action} must be refused, not defaulted"));
    }

    // An out-of-set health status was already refused; keep it that way.
    p.execute_action(json!({"type": "send_cluster_health", "status": "chartreuse"}))
        .expect_err("only green/yellow/red are defined");

    for action in [
        json!({"type": "send_index_response", "index": "p", "id": "a", "result": "created"}),
        json!({"type": "send_cluster_health", "status": "yellow"}),
        json!({"type": "send_get_response", "index": "p", "id": "a", "found": false}),
    ] {
        p.execute_action(action.clone())
            .unwrap_or_else(|e| panic!("{action} should still be accepted: {e}"));
    }
}

/// An omitted `errors` is derived from the items rather than assumed to be `false`.
#[test]
fn bulk_errors_flag_agrees_with_the_items_beneath_it() {
    let p = ElasticsearchProtocol::new();

    let body_of = |action: serde_json::Value| -> serde_json::Value {
        match p.execute_action(action).expect("bulk response accepted") {
            ActionResult::Custom { data, .. } => {
                serde_json::from_str(data["body"].as_str().expect("body is a string"))
                    .expect("body parses as JSON")
            }
            other => panic!("expected a custom result, got {other:?}"),
        }
    };

    let clean = body_of(json!({
        "type": "send_bulk_response",
        "items": [{"index": {"_index": "p", "_id": "1", "status": 201}}]
    }));
    assert_eq!(clean["errors"], false, "no item failed");

    let failed_status = body_of(json!({
        "type": "send_bulk_response",
        "items": [
            {"index": {"_index": "p", "_id": "1", "status": 201}},
            {"index": {"_index": "p", "_id": "2", "status": 409}}
        ]
    }));
    assert_eq!(
        failed_status["errors"], true,
        "a 4xx item status means errors occurred; reporting false makes a client skip `items` \
         entirely and never see the failure"
    );

    let failed_error_object = body_of(json!({
        "type": "send_bulk_response",
        "items": [{"index": {"_index": "p", "_id": "1", "error": {"type": "mapper_parsing"}}}]
    }));
    assert_eq!(failed_error_object["errors"], true);

    // An explicit flag still wins: the handler may know something the items do not show.
    let explicit = body_of(json!({
        "type": "send_bulk_response",
        "errors": true,
        "items": [{"index": {"_index": "p", "_id": "1", "status": 201}}]
    }));
    assert_eq!(explicit["errors"], true);
}
