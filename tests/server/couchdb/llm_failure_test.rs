//! What a CouchDB client gets when the LLM backend fails: `{"error":…,"reason":…}` with a 5xx.
//!
//! The shape was already right; what this pins down is that the status is never a 2xx. CouchDB
//! makes the trap unusually easy to fall into because its success bodies are so small: a 200
//! with `{"rows":[]}` says the view returned nothing, and a 201 with `{"ok":true}` says the
//! document was written. Both are statements about the database, and a failed request is in no
//! position to make either.
//!
//! 503 `unavailable` when the backend is merely saturated, 500 `internal_server_error`
//! otherwise.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_couchdb_answers_error_body_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open couchdb on port {AVAILABLE_PORT}. Serve a notes database.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open couchdb")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "CouchDB",
                    "instruction": "Serve a notes database"
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
            .put(format!("http://127.0.0.1:{}/notes/doc1", server.port))
            .header("content-type", "application/json")
            .body(r#"{"title":"hello"}"#)
            .send(),
    )
    .await
    .map_err(|_| {
        "No CouchDB response within 25s - the server went silent on LLM failure, which is the \
         exact defect this test exists to catch"
    })??;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("CouchDB -> {status} {text}");

    assert!(
        (500..600).contains(&status),
        "expected a server-side status. A 201 with {{\"ok\":true}} would tell the client the \
         document was written: {status}"
    );

    let body: Value = serde_json::from_str(&text)?;
    assert_ne!(
        body["ok"].as_bool(),
        Some(true),
        "a failure must never report ok:true: {text}"
    );
    let kind = body["error"].as_str().unwrap_or_default();
    assert!(
        kind == "internal_server_error" || kind == "unavailable",
        "expected a server-side error name, got {kind:?}"
    );
    assert!(
        body["reason"]
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
