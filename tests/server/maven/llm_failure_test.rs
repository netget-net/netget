//! What a Maven client gets when the LLM backend fails.
//!
//! Silence would leave `mvn` blocked on the socket until its own timeout, and a 200 with an
//! empty body would be cached as a successfully downloaded zero-byte artifact. The server
//! answers with an HTTP status and a literal body carrying only a category — never the
//! backend error, its URL, the model name or an `anyhow` chain.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};

/// Nothing internal may appear in the response the peer reads.
fn assert_no_leak(body: &str) {
    for leaked in [
        "LLM", "ollama", "Ollama", "http://", "retries", "anyhow", "src/",
    ] {
        assert!(
            !body.contains(leaked),
            "response body leaked {leaked:?}: {body:?}"
        );
    }
}

#[tokio::test]
async fn test_maven_answers_500_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via maven.
Serve a library com.example:hello-world:1.0.0";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("maven")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Maven",
                    "instruction": "Serve a library com.example:hello-world:1.0.0"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `maven_artifact_request`: the backend call fails.
    });

    let server = helpers::start_netget_server(config).await?;
    assert_eq!(server.stack, "Maven");

    let url = format!(
        "http://127.0.0.1:{}/com/example/hello-world/1.0.0/hello-world-1.0.0.pom",
        server.port
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        reqwest::Client::new().get(&url).send(),
    )
    .await
    .map_err(|_| {
        "Maven neither answered nor failed within 25s - the server went silent on LLM failure, \
         which is the exact defect this test exists to catch"
    })??;

    let status = response.status().as_u16();
    assert!(
        status == 500 || status == 503,
        "expected 500 (unavailable) or 503 (overloaded), got {status}"
    );
    if status == 503 {
        assert!(
            response
                .headers()
                .contains_key(reqwest::header::RETRY_AFTER),
            "a 503 must carry Retry-After so the client backs off"
        );
    }
    let body = response.text().await?;
    assert_no_leak(&body);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model answering with nothing usable is a distinct case: the default 404 stands, and it
/// must not become a 200 with an empty body.
#[tokio::test]
async fn test_maven_no_action_yields_404_not_empty_success() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via maven.
Serve a library com.example:hello-world:1.0.0";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("maven")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Maven",
                    "instruction": "Serve a library com.example:hello-world:1.0.0"
                }
            ]))
            .expect_calls(1)
            .and()
            // The call succeeds and the model answers with nothing.
            .on_event("maven_artifact_request")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let url = format!(
        "http://127.0.0.1:{}/com/example/hello-world/1.0.0/hello-world-1.0.0.pom",
        server.port
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        reqwest::Client::new().get(&url).send(),
    )
    .await
    .map_err(|_| "Maven went silent after the model answered with no actions")??;

    assert_eq!(
        response.status().as_u16(),
        404,
        "an unanswered artifact request is a miss, never a successful empty download"
    );
    let body = response.text().await?;
    assert_no_leak(&body);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
