//! What a scraper gets when the model cannot answer: a 500 with a fixed category, never an
//! empty 200 and never netget's own error text.
//!
//! An empty `200 OK` would be the worst outcome here: Prometheus would record a successful
//! scrape of a target with no series, `up` would read 1, and every alert keyed on a missing
//! series would fire for the wrong reason. A 500 makes `up` 0 and puts the status line in the
//! target's error column, which is the truth.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_prometheus_answers_500_with_a_category_when_the_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via prometheus. Expose queue metrics",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("via prometheus")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "prometheus",
                "instruction": "Expose queue metrics"
            }]))
            .expect_calls(1)
            .and()
        // No rule for prometheus_scrape: the mock answers HTTP 500 and call_llm returns Err.
    });
    let server = start_netget_server(config).await?;

    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .build()?
        .get(format!("http://127.0.0.1:{}/metrics", server.port))
        .send()
        .await
        .map_err(|e| format!("the exporter neither answered nor closed on LLM failure: {e}"))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = response.text().await?;
    println!("status {status}, body {body:?}");

    assert_eq!(
        status, 500,
        "a backend failure must fail the scrape: {body}"
    );
    assert!(
        !content_type.contains("version=0.0.4") && !content_type.contains("openmetrics"),
        "a failure must not be labelled as an exposition: {content_type}"
    );
    assert_eq!(body.trim(), "netget: request could not be processed");
    for leak in ["LLM", "Ollama", "http://", "127.0.0.1", "retries", "model"] {
        assert!(
            !body.contains(leak),
            "the scraper gets a category, never the error text ({leak}): {body}"
        );
    }

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure must be greppable as decision=fail_closed_llm_error. Output:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
