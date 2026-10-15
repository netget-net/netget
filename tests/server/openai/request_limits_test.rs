//! What the OpenAI server refuses to read, and what it refuses to say.
//!
//! `/v1/chat/completions` takes an unauthenticated POST whose body is buffered whole and then
//! handed to the model as prompt text. `hyper`'s `Incoming` has no default limit, so
//! `req.collect()` read whatever the peer chose to send.
//!
//! The second test is about the other direction: when the backend fails, the peer must get a
//! category and the log must get the error. "LLM did not return valid response" and a raw
//! `anyhow` chain are both netget's own internals on a stranger's terminal.


use crate::server::helpers::{self, E2EResult, NetGetConfig};

/// An oversized body is refused with 413 before the model ever sees it.
///
/// Deliberately no mock for `openai_request`: the cap has to be applied before the request can
/// provoke an LLM call, so an unmocked one would fail the run.
#[tokio::test]
async fn an_oversized_request_body_is_refused_without_reaching_the_model() -> E2EResult<()> {
    let config = NetGetConfig::new("Open an OpenAI API server on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenAI")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openai",
                        "instruction": "Answer OpenAI API requests",
                        "event_handlers": [{
                            "event_pattern": "openai_request",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "openai_chat_response",
                                    "content": "ok",
                                    "model": "gpt-4"
                                }]
                            }
                        }]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;

    // Wait for the bind before sending. Without this the request races the listener: under a
    // 100-thread run it is refused at connect, which surfaces as a transport error rather
    // than an assertion, so the failure reads as "the body limit is broken" when the server
    // had simply not finished starting.
    //
    // Same defect the September hygiene sweep removed from 74 sites; this file and
    // elasticsearch's refusal_test were written after it, in different waves, and
    // reintroduced it independently.
    crate::helpers::common::wait_for_server_listening(&server, std::time::Duration::from_secs(30))
        .await?;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", server.port);

    // 9 MiB of message content, one megabyte past the 8 MiB cap.
    let oversized = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "A".repeat(9 * 1024 * 1024)}],
    });
    let refused = reqwest::Client::new()
        .post(&url)
        .json(&oversized)
        .send()
        .await?;
    assert_eq!(
        refused.status(),
        413,
        "a body past the cap must be refused with 413, not buffered and prompted with"
    );
    let body: serde_json::Value = refused.json().await?;
    assert_eq!(
        body["error"]["type"], "invalid_request_error",
        "the refusal must keep OpenAI's error envelope so a client can parse it: {body}"
    );

    // An ordinary request on the same endpoint still works — a guard that refused everything
    // would satisfy the assertion above and be useless.
    let accepted = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await?;
    assert_eq!(
        accepted.status(),
        200,
        "an ordinary request must not be caught by the body cap"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// A backend failure reaches the peer as a category, never as netget's own error text.
#[tokio::test]
async fn a_backend_failure_tells_the_peer_nothing_about_netget() -> E2EResult<()> {
    // The server starts, and then every `openai_request` goes unmocked — which is how the
    // harness simulates a backend that cannot answer.
    let config = NetGetConfig::new("Open an OpenAI API server on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenAI")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openai",
                        "instruction": "Answer OpenAI API requests"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;

    // Wait for the bind before sending. Without this the request races the listener: under a
    // 100-thread run it is refused at connect, which surfaces as a transport error rather
    // than an assertion, so the failure reads as "the body limit is broken" when the server
    // had simply not finished starting.
    //
    // Same defect the September hygiene sweep removed from 74 sites; this file and
    // elasticsearch's refusal_test were written after it, in different waves, and
    // reintroduced it independently.
    crate::helpers::common::wait_for_server_listening(&server, std::time::Duration::from_secs(30))
        .await?;

    let response = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            server.port
        ))
        .json(&serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await?;

    assert!(
        response.status().is_server_error(),
        "a backend failure must not read as a success, got {}",
        response.status()
    );
    let body: serde_json::Value = response.json().await?;
    let message = body["error"]["message"].as_str().unwrap_or_default();

    // The categories `WireFailure` returns are `&'static str` precisely so nothing can be
    // interpolated into them. These are the idioms that leaked before.
    for leak in [
        "LLM",
        "Ollama",
        "ollama",
        "http://",
        "retries",
        "mock",
        "src/",
        "did not return valid response",
    ] {
        assert!(
            !message.contains(leak),
            "the peer was told {leak:?} about netget's internals: {message:?}"
        );
    }
    assert!(
        !message.is_empty(),
        "the peer still needs to be told something: {body}"
    );

    // The startup rule is the one expectation this test sets, and it must have fired:
    // without it the server would never have started and the 5xx above would be a
    // connection refusal wearing the same shape.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
