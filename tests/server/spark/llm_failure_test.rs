//! What a Spark client gets when the LLM backend fails: a JSON error object with a 5xx.
//!
//! Spark's success responses are bare JSON arrays, so the dangerous failure is answering
//! `200 []` — a valid "no applications/jobs" result a client cannot distinguish from a backend
//! that never ran. This pins the LLM-failure path to a 5xx JSON *object* with an `error` field,
//! structurally distinct from any success array.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_spark_answers_error_when_llm_fails() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("Open an Apache Spark REST API on port {AVAILABLE_PORT}")
            .with_mock(|mock| {
                mock.on_instruction_containing("Apache Spark REST API")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server", "port": 0, "base_stack": "spark",
                        "instruction": "Spark monitoring API"
                    }]))
                    .expect_calls(1)
                    .and()
                // No rule for the spark_request event -> the mock 500s -> call_llm errors.
            });

    let server = start_netget_server(config).await?;

    // Wait for the socket, not for a duration: `start_netget_server` returns when startup is
    // parsed, not when the listener is bound, so the fixed 500ms this used to sleep was a
    // guess that gets worse the more tests run alongside. A 5xx is a *successful* HTTP
    // exchange, so only a transport failure retries — and the client's own 25s timeout is
    // what catches the other half of the defect, a server that answers nothing at all.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()?;
    let url = format!("http://127.0.0.1:{}/api/v1/applications", server.port);
    let response = crate::helpers::retry(|| async { client.get(&url).send().await })
        .await
        .map_err(|e| {
            format!(
                "no Spark response: the server went silent on LLM failure, which is the exact \
                 defect this test exists to catch ({e})"
            )
        })?;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("Spark -> {status} {text}");

    assert!(
        (500..600).contains(&status),
        "expected a 5xx rather than a success-shaped empty array: {status}"
    );
    let body: Value = serde_json::from_str(&text)?;
    assert!(
        !body.is_array(),
        "a failure must be a JSON error object, never a (possibly-empty) success array: {text}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("netget"),
        "the error should name the source of the failure: {text}"
    );

    // A 5xx is also a status the *model* may choose with `spark_response`, so the status code
    // alone does not say whether anything was asked. The `decision=` tag does, and
    // `grep decision=fail_closed` is the diagnostic this repo teaches.
    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| { l.contains("/api/v1/applications") && l.contains("decision=fail_closed_") }),
        "the LLM-failure path must carry a fail_closed decision tag naming the request; \
         without it a backend outage reads exactly like a model that chose to answer 500. \
         Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_")),
        "nothing the model decided happened here — it was never reached. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
