//! What a Vault client gets when the model cannot answer: Vault's `{"errors": [...]}` with a
//! fixed category, printed by the real CLI, and `decision=fail_closed_llm_error` in the log.
//!
//! The dangerous outcomes are a 404 ("no value found" — a monitoring job would conclude the
//! secret was deleted) and an empty secret. Neither may come out of an outage.


use super::real_client_test::{require_tool, vault};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_vault_answers_500_with_a_category_when_the_llm_fails() -> E2EResult<()> {
    let bin = require_tool("vault");
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via vault. Team secrets")
            .with_mock(|mock| {
                mock.on_instruction_containing("via vault")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "vault",
                        "instruction": "Team secrets"
                    }]))
                    .expect_calls(1)
                    .and()
                // No rule for vault_read: the mock answers HTTP 500 and call_llm returns Err.
            });
    let server = start_netget_server(config).await?;
    let home = tempfile::TempDir::new()?;

    let get = vault(
        &bin,
        home.path(),
        server.port,
        "any",
        &["kv", "get", "secret/app/db"],
    )
    .await;
    assert_ne!(get.code, 0);
    let all = format!("{}{}", get.stdout, get.stderr);
    assert!(
        !all.contains("No value found"),
        "an outage must not read as a missing secret: {all}"
    );
    assert!(
        get.stderr.contains("Code: 500")
            && get
                .stderr
                .contains("netget: request could not be processed"),
        "{}",
        get.stderr
    );
    for leak in ["LLM", "Ollama", "retries", "model"] {
        assert!(!get.stderr.contains(leak), "leaked {leak}: {}", get.stderr);
    }

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    assert!(
        server
            .output_contains("decision=fail_closed_llm_error")
            .await,
        "{}",
        server.get_output().await.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
