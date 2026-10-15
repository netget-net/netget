//! What an Elasticsearch client gets when the LLM backend fails: the ES error envelope, 5xx.
//!
//! ES already answered 500 here. What this pins down is the part that is easy to get wrong in
//! a search API: the failure must not be a 200 with an empty `hits` array. That is a valid,
//! meaningful search result - "nothing in the index matches" - and a client has no way to tell
//! it from a backend that never ran the query.
//!
//! `status` inside the body must agree with the HTTP status, because that is the field most
//! clients report. 503 with `unavailable_shards_exception` is ES's own "come back later" and
//! is used when the backend is merely saturated.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_elasticsearch_answers_error_envelope_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open elasticsearch on port {AVAILABLE_PORT}. Serve a products index.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open elasticsearch")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Elasticsearch",
                    "instruction": "Serve a products index"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for the request event.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .post(format!("http://127.0.0.1:{}/products/_search", server.port))
            .header("content-type", "application/json")
            .body(r#"{"query":{"match_all":{}}}"#)
            .send(),
    )
    .await
    .map_err(|_| {
        "No Elasticsearch response within 25s - the server went silent on LLM failure, which \
         is the exact defect this test exists to catch"
    })??;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("Elasticsearch -> {status} {text}");

    assert!(
        (500..600).contains(&status),
        "expected a server-side status rather than a 200 with an empty hits array, which is a \
         valid search result meaning nothing matched: {status}"
    );

    let body: Value = serde_json::from_str(&text)?;
    assert!(
        body["hits"].is_null(),
        "a failure must not carry a hits object of any kind: {text}"
    );
    assert_eq!(
        body["status"].as_u64(),
        Some(status as u64),
        "the `status` field in the envelope is what most clients report, so it must agree \
         with the HTTP status: {text}"
    );
    let kind = body["error"]["type"].as_str().unwrap_or_default();
    assert!(
        kind == "server_error" || kind == "unavailable_shards_exception",
        "expected a server-side error type, got {kind:?}"
    );
    assert!(
        body["error"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("netget"),
        "the reason should name the source of the failure: {text}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
