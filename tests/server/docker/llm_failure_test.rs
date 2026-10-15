//! What a Docker client gets when the model cannot answer: Docker's error shape with a fixed
//! category, printed by the real CLI, and `decision=fail_closed_llm_error` in the log.
//!
//! The failure that matters here is an empty list. `[]` from `/containers/json` is a perfectly
//! ordinary answer — "no containers" — so a server that fell back to it on an outage would tell
//! a monitoring script that every container had vanished.


use super::real_client_test::{docker, require_tool};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_docker_answers_500_with_a_category_when_the_llm_fails() -> E2EResult<()> {
    let bin = require_tool("docker");
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via docker. A small host")
            .with_mock(|mock| {
                mock.on_instruction_containing("via docker")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "docker",
                        "instruction": "A small host"
                    }]))
                    .expect_calls(1)
                    .and()
                // No rule for docker_api_request: the mock answers HTTP 500 and call_llm returns Err.
            });
    let server = start_netget_server(config).await?;
    let dir = tempfile::TempDir::new()?;

    let ps = docker(&bin, dir.path(), server.port, &["ps"]).await;
    assert!(
        !ps.success,
        "a backend failure must fail the command, not list nothing"
    );
    assert!(
        ps.stderr
            .contains("Error response from daemon: netget: request could not be processed"),
        "{}",
        ps.stderr
    );
    for leak in ["LLM", "Ollama", "http://", "retries", "model"] {
        assert!(!ps.stderr.contains(leak), "leaked {leak}: {}", ps.stderr);
    }

    let raw = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(format!(
            "http://127.0.0.1:{}/v1.47/containers/json",
            server.port
        ))
        .send()
        .await?;
    assert_eq!(raw.status(), 500);
    assert_eq!(
        raw.json::<serde_json::Value>().await?,
        serde_json::json!({"message": "netget: request could not be processed"})
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
