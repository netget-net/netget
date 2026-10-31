//! Every HTTP request ends in exactly one `decision=` line, and the ways a request can end
//! badly are told apart there as well as on the wire:
//!
//! - a backend that failed: `500`, `decision=fail_closed_llm_error`;
//! - a model that answered with nothing: `500`, `decision=fail_closed_no_action`;
//! - a model whose action the executor refused: `500`, `decision=fail_closed_bad_action`;
//! - a silent model on a server with a `default_response`: that response,
//!   `decision=model_silent fallback=default_response`.
//!
//! A model that says nothing must not reach the peer as `200 OK`: a client cannot tell an
//! empty success nobody authored from one the model wrote, so it would record an unanswered
//! request as a completed one. The `default_response` startup parameter is the operator's
//! deliberate answer for that case and is the only thing that may stand in for the model.

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
/// teaches, `grep decision=fail_closed`, and is not confused with a silent model.
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
        !lines
            .iter()
            .any(|l| l.contains("decision=model_silent")
                || l.contains("decision=fail_closed_no_action")),
        "a backend failure was reported as model silence. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A model that answers with no `send_http_response`, on a server with no
/// `default_response`: the request is refused with a `500` carrying only the failure
/// category, and the log says `decision=fail_closed_no_action`.
///
/// The regression test for the empty `200` this used to be.
#[tokio::test]
async fn test_http_model_silence_fails_closed_with_500() -> E2EResult<()> {
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
        .post(format!("http://127.0.0.1:{}/todos", server.port))
        .header("Content-Type", "application/json")
        .body(r#"{"title":"write the test"}"#)
        .send()
        .await
        .map_err(|e| format!("the HTTP server did not answer within 20s: {e}"))?;

    let status = response.status().as_u16();
    let body = response.text().await?;
    assert_eq!(
        status, 500,
        "a model that said nothing must not be answered as a success; got {status} {body:?}"
    );
    assert_eq!(
        body, "netget: request could not be processed",
        "the refusal carries the failure category and nothing else"
    );

    server
        .wait_for_any(&["decision=fail_closed_no_action"], 30)
        .await;

    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_no_action")),
        "a model that produced no send_http_response must be logged as \
         decision=fail_closed_no_action. Output was:\n{}",
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

/// A model whose only action the executor refuses (a `send_http_response` with no `status`)
/// produced no response either: `500` and `decision=fail_closed_bad_action`.
#[tokio::test]
async fn test_http_refused_action_fails_closed_with_500() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via http stack").with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("via http")
                .respond_with_actions(open_http_server())
                .expect_calls(1)
                .and()
                .on_event("http_request")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_http_response", "body": "no status here"}
                ]))
                // At least one: the LLM layer may retry an answer that names a field wrong.
                .expect_at_least(1)
                .expect_at_most(5)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let response = client
        .get(format!("http://127.0.0.1:{}/", server.port))
        .send()
        .await
        .map_err(|e| format!("the HTTP server did not answer within 30s: {e}"))?;
    let status = response.status().as_u16();
    let body = response.text().await?;
    assert_eq!(
        status, 500,
        "a refused action is not an answer; got {status} {body:?}"
    );
    assert!(
        !body.contains("no status here"),
        "the refused action's body must not reach the peer, got {body:?}"
    );

    server
        .wait_for_any(&["decision=fail_closed_bad_action"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_bad_action")),
        "a refused action must be logged as decision=fail_closed_bad_action. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// With a `default_response` configured, a silent model is answered with it: the operator
/// wrote that answer for exactly this case.
#[tokio::test]
async fn test_http_model_silence_uses_the_configured_default_response() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via http stack").with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("via http")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server",
                    "startup_params": {
                        "default_response": {
                            "status": 404,
                            "headers": {"Content-Type": "text/plain"},
                            "body": "nothing here"
                        }
                    }
                }]))
                .expect_calls(1)
                .and()
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
        .get(format!("http://127.0.0.1:{}/missing", server.port))
        .send()
        .await
        .map_err(|e| format!("the HTTP server did not answer within 20s: {e}"))?;
    assert_eq!(response.status().as_u16(), 404);
    assert_eq!(response.text().await?, "nothing here");

    server
        .wait_for_any(&["decision=model_silent fallback=default_response"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=model_silent fallback=default_response")),
        "a silent model answered by the configured default must say so. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
