//! The OpenAPI server must fail closed, and must never put netget's internals on the wire.
//!
//! Two regressions are pinned here:
//!
//! 1. A model that answers a matched request with **no response action** used to be answered
//!    with HTTP 200 and a body reading "OpenAPI server received request but LLM did not
//!    generate a response" — a silent model was indistinguishable from a successful one, and
//!    the body named netget's own LLM machinery to a stranger. It is now a 500 carrying only
//!    a category.
//! 2. Whatever the failure, the response body may not contain the error text, the backend
//!    URL, the model name or any other internal detail.


use crate::helpers::*;
use serde_json::Value;
use std::time::Duration;

/// Words that must never appear in a peer-visible body. Same spirit as
/// `tests/wire_failure_test.rs::FORBIDDEN_TOKENS`.
const FORBIDDEN_IN_BODY: &[&str] = &[
    "LLM", "llm", "Ollama", "ollama", "http://", "11434", "retries", "✗", "/Users/",
];

#[tokio::test]
async fn test_openapi_no_action_fails_closed() -> E2EResult<()> {
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    let server_config =
        NetGetConfig::new("Start OpenAPI server with todo list spec on port {AVAILABLE_PORT}")
            .with_mock(|mock| {
                mock.on_instruction_containing("Start OpenAPI server")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "openapi",
                            "instruction": "OpenAPI server for TODO API",
                            "startup_params": { "spec": spec_content }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // The model is consulted and answers with nothing usable.
                    .on_event("openapi_request")
                    .and_event_data_contains("path", "/todos")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
            });

    let mut server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(20),
        client
            .get(format!("http://127.0.0.1:{}/todos", server.port))
            .send(),
    )
    .await
    .map_err(|_| "Request timeout")??;

    let status = response.status();
    let body = response.text().await?;

    assert_eq!(
        status, 500,
        "a model that produced no response action must fail closed, got {} with body {}",
        status, body
    );

    for token in FORBIDDEN_IN_BODY {
        assert!(
            !body.contains(token),
            "peer-visible body leaks internal detail `{}`: {}",
            token,
            body
        );
    }

    // Still valid JSON carrying a category, not a diagnosis.
    let json: Value = serde_json::from_str(&body)?;
    assert_eq!(json["error"], "Internal Server Error");
    assert_eq!(json["message"], "request could not be processed");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}
