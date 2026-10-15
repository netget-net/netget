//! Every terminal outcome of an NPM registry request is grep-able as `decision=<token>`.
//!
//! The npm CLI *acts* on a 200: it takes the body as a packument or a tarball and unpacks it.
//! So the outcome that matters most here is the one that must never happen — a backend
//! failure or a silent model producing a 200 with a synthesised or empty body. The first test
//! asserts both halves of that: 500 on the wire, `decision=fail_closed_llm_error` in the log.
//!
//! NPM decides its own terminal outcomes in `src/server/npm/mod.rs`; nothing here is delegated
//! to `src/server/http_common/`, so the tokens and the status codes are set in one place.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

fn open_npm_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "NPM",
            "instruction": "NPM registry - serve package metadata"
        }
    ])
}

async fn get(url: &str) -> E2EResult<(u16, String)> {
    let client = reqwest::Client::new();
    let response = tokio::time::timeout(Duration::from_secs(20), client.get(url).send())
        .await
        .map_err(|_| "NPM did not answer within 20s")??;
    let status = response.status().as_u16();
    let body = response.text().await?;
    Ok((status, body))
}

/// The backend fails: HTTP 500 carrying only a category, and a `fail_closed` token in the log.
/// A 200 here would hand npm a packument nobody authored.
#[tokio::test]
async fn test_npm_llm_failure_is_tagged_fail_closed_and_never_200() -> E2EResult<()> {
    let prompt = "Open NPM registry on port {AVAILABLE_PORT} serving package metadata";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open NPM registry")
            .respond_with_actions(open_npm_server())
            .expect_calls(1)
            .and()
            // Not an action: the repair loop exhausts and `call_llm` returns Err.
            .on_event("NPM_PACKAGE_REQUEST")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;
    let (status, body) = get(&format!("http://127.0.0.1:{}/express", server.port)).await?;
    println!("NPM answered {} with {}", status, body);

    assert_eq!(
        status, 500,
        "a backend failure must be a server error, never a 200 npm would act on. Body: {body}"
    );
    assert!(
        !body.contains("LLM") && !body.contains("Ollama") && !body.contains("retries"),
        "the peer gets a category, never netget's own error text: {body}"
    );
    assert!(
        !body.contains("\"versions\"") && !body.contains("\"dist-tags\""),
        "a failure must not synthesise anything packument-shaped: {body}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure and a model that answered with nothing both end in a 500, so the \
         log must say which. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model answers with a packument, and the answer reaches the client: `decision=model_answer`.
/// The control for the test above — a token emitted unconditionally would pass that one too.
#[tokio::test]
async fn test_npm_successful_answer_is_tagged_model_answer() -> E2EResult<()> {
    let prompt = "Open NPM registry on port {AVAILABLE_PORT} serving package metadata";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open NPM registry")
            .respond_with_actions(open_npm_server())
            .expect_calls(1)
            .and()
            .on_event("NPM_PACKAGE_REQUEST")
            .and_event_data_contains("path", "/express")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "npm_package_metadata",
                    "metadata": {
                        "name": "express",
                        "version": "4.18.2",
                        "description": "Fast, unopinionated, minimalist web framework"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;
    let (status, body) = get(&format!("http://127.0.0.1:{}/express", server.port)).await?;
    assert_eq!(status, 200, "expected the mocked packument, got: {body}");
    assert!(
        body.contains("4.18.2"),
        "expected the mocked metadata, got: {body}"
    );

    server.wait_for_any(&["decision=model_answer"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_answer")),
        "an applied answer must be tagged model_answer. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "a successful request must not log any fail_closed token. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
