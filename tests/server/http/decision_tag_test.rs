//! Every HTTP request ends in exactly one `decision=` line, and the three ways a request
//! can end badly are told apart there.
//!
//! HTTP is the protocol whose failure handling root `CLAUDE.md` tells everything else to
//! copy, so its own log has to carry the distinction it teaches. Before these tests:
//!
//! - a model that answered `send_http_response`,
//! - a model that answered with nothing at all, and
//! - a model whose action the executor refused
//!
//! all produced the same single line (`→ HTTP GET / → 200 (0 bytes)`) and, in the last two
//! cases, the same affirmative `200` on the wire. Only a backend *failure* was tagged, and
//! that tag is emitted from `src/server/http_common/handler.rs`, which is shared with
//! ipp/openapi/… — so the success/silence split had to be added at HTTP's own call site.
//!
//! **The second test pins a fail-open.** A model that says nothing still answers the peer
//! `200 OK`. That is not repaired here — repairing it would change HTTP's wire behaviour for
//! every existing prompt and handler — but it is now stated in the log, in the words
//! `decision=model_silent fallback=blank_200`, so an operator can find every request that
//! was "answered" by nobody.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

fn open_http_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "HTTP",
            "instruction": "HTTP server"
        }
    ])
}

/// A backend failure is `decision=fail_closed_llm_error`, and it says so in the log as well
/// as on the wire.
///
/// The wire already carries a 500 (`failure_semantics_test.rs` pins that). What this adds is
/// that the log line naming the request is greppable with the one diagnostic this repo
/// teaches, `grep decision=fail_closed`.
#[tokio::test]
async fn test_http_backend_failure_is_tagged_fail_closed() -> E2EResult<()> {
    // No rule matches `http_request`, so the mock answers HTTP 500 and `call_llm` returns
    // Err after its retries — the backend-failure path.
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via http stack").with_mock(|mock| {
            mock.on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(open_http_server())
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .get(format!("http://127.0.0.1:{}/", server.port))
        .send()
        .await
        .map_err(|e| format!("the HTTP server neither answered nor closed within 20s: {e}"))?;
    assert_eq!(
        response.status().as_u16(),
        500,
        "a backend error must answer 500"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;

    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure must be logged with decision=fail_closed_llm_error so it is \
         distinguishable from a model that answered nothing. Output was:\n{}",
        lines.join("\n")
    );
    // ...and it must not be mistaken for the model having chosen to say nothing.
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_silent")),
        "a backend failure was reported as model silence. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// **Fail-open.** A model that answers with no `send_http_response` still gets the peer a
/// `200 OK` with an empty body, because that is `build_response`'s fallback when the server
/// has no `default_response` configured.
///
/// This test asserts the wire behaviour as it actually is — so that changing it is a
/// deliberate act with a failing test attached — and asserts that the log now says which of
/// the two 200s this was.
#[tokio::test]
async fn test_http_model_silence_answers_200_and_is_tagged_as_a_fail_open() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via http stack").with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("via http")
                .respond_with_actions(open_http_server())
                .expect_calls(1)
                .and()
                // The model is reached, answers, and its answer contains no action at all.
                // Distinct from the test above, where the backend never answered usefully.
                .on_event("http_request")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .get(format!("http://127.0.0.1:{}/", server.port))
        .send()
        .await
        .map_err(|e| format!("the HTTP server did not answer within 20s: {e}"))?;

    let status = response.status().as_u16();
    let body = response.text().await?;
    assert_eq!(
        status, 200,
        "current (fail-open) behaviour: a model that said nothing answers 200. If this now \
         fails because the server answers 5xx instead, the fail-open was fixed — update this \
         test and `src/server/http/CLAUDE.md` together."
    );
    assert!(
        body.is_empty(),
        "the fail-open 200 carries an empty body, got {body:?}"
    );

    server
        .wait_for_any(&["decision=model_silent fallback=blank_200"], 30)
        .await;

    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=model_silent fallback=blank_200")),
        "a model that produced no send_http_response must be logged as model_silent, naming \
         the fallback that answered the peer in its place — otherwise an affirmative 200 that \
         nobody authored is indistinguishable from one the model wrote. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_answer")),
        "the model answered nothing; it must not be logged as having answered. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
