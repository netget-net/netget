//! The Ollama server driven by a real, third-party Ollama client.
//!
//! The rest of this suite speaks to the server with `reqwest`, which proves an HTTP server
//! answers but not that the protocol on top of it is right — `CLAUDE.md` names that as
//! non-evidence, and `metadata().e2e_testing` used to claim an "ollama Python library" that
//! never existed anywhere in the tree.
//!
//! `ollama-rs` is the crate NetGet itself uses to talk to a real Ollama backend
//! (`src/llm/ollama_client.rs`). Here it is pointed the other way, at NetGet's own Ollama
//! server, so it decides for itself whether our `/api/tags`, `/api/generate` and `/api/chat`
//! envelopes are the ones an Ollama client expects. It is an unconditional dependency, so
//! this evidence compiles and runs wherever `--features ollama` does — not behind an
//! `optional = true` or a skip-when-missing gate.
//!
//! Also covered here, because both need a live server: `/api/embeddings` as a *decision*
//! rather than a fabrication, and the request-body cap.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use ollama_rs::generation::chat::request::ChatMessageRequest;
use ollama_rs::generation::chat::ChatMessage;
use ollama_rs::generation::completion::request::GenerationRequest;
use ollama_rs::Ollama;

/// One NetGet Ollama server whose three main endpoints are answered from static routing, so
/// the whole exchange costs a single LLM call (the one that opens the server).
fn ollama_server_config() -> NetGetConfig {
    NetGetConfig::new(
        "Open Ollama on port {AVAILABLE_PORT}. Serve the model 'netget-test:1b' only.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Serve the model 'netget-test:1b' only.",
                    "event_handlers": [
                        {
                            "event_pattern": "ollama_models_request",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "ollama_models_response",
                                    "models": ["netget-test:1b"]
                                }]
                            }
                        },
                        {
                            "event_pattern": "ollama_generate_request",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "ollama_generate_response",
                                    "response_text": "Paris is the capital of France."
                                }]
                            }
                        },
                        {
                            "event_pattern": "ollama_chat_request",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "ollama_chat_response",
                                    "message_content": "Hello from the NetGet Ollama server."
                                }]
                            }
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    })
}

/// `ollama-rs` completes list, generate and chat against NetGet's server.
///
/// Each assertion is on a field `ollama-rs` deserialised for itself: a malformed envelope
/// would surface as a decode error from the crate, not as a missing key we looked up by hand.
#[tokio::test]
async fn ollama_rs_completes_list_generate_and_chat() -> E2EResult<()> {
    let server = helpers::start_netget_server(ollama_server_config()).await?;

    let client = Ollama::new("http://127.0.0.1".to_string(), server.port);

    // /api/tags
    let models = client
        .list_local_models()
        .await
        .expect("ollama-rs must be able to list models from NetGet's /api/tags");
    assert!(
        models.iter().any(|m| m.name == "netget-test:1b"),
        "ollama-rs decoded the model list but not the model we served: {:?}",
        models.iter().map(|m| &m.name).collect::<Vec<_>>()
    );

    // /api/generate
    let generated = client
        .generate(GenerationRequest::new(
            "netget-test:1b".to_string(),
            "What is the capital of France?".to_string(),
        ))
        .await
        .expect("ollama-rs must be able to complete a generate request");
    assert_eq!(
        generated.response, "Paris is the capital of France.",
        "the text the handler produced must reach ollama-rs unchanged"
    );

    // /api/chat
    let chat = client
        .send_chat_messages(ChatMessageRequest::new(
            "netget-test:1b".to_string(),
            vec![ChatMessage::user("Hello!".to_string())],
        ))
        .await
        .expect("ollama-rs must be able to complete a chat request");
    assert_eq!(
        chat.message.content, "Hello from the NetGet Ollama server.",
        "the chat content the handler produced must reach ollama-rs unchanged"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// `/api/embeddings` answers what the model said, and refuses when it says nothing.
///
/// It used to return a hardcoded 768-element ramp for every request with no event and no LLM
/// call anywhere in the path, so no instruction could reach it — the server's own routing
/// table could not change the answer. These two cases differ only in the routing table, which
/// is the whole point: if the endpoint still fabricated, both would return a vector.
#[tokio::test]
async fn embeddings_is_a_decision_not_a_fabrication() -> E2EResult<()> {
    let config = NetGetConfig::new("Open Ollama on port {AVAILABLE_PORT} for embeddings.")
        .with_mock(|mock| {
            mock.on_instruction_containing("Open Ollama")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Ollama",
                        "instruction": "Embed only for 'netget-test:1b'."
                    }
                ]))
                .expect_calls(1)
                .and()
                // ONE rule that branches on the event. Two rules on the same event with no
                // way to tell them apart is the documented first-match-wins trap: the first
                // would answer both requests and the second report zero calls.
                .on_event("ollama_embeddings_request")
                .respond_with_actions_from_event(|event| {
                    if event["model"] == "netget-test:1b" {
                        serde_json::json!([
                            {"type": "ollama_embeddings_response", "dimensions": 8}
                        ])
                    } else {
                        serde_json::json!([{
                            "type": "ollama_error_response",
                            "error_message": "model not served here",
                            "status_code": 404
                        }])
                    }
                })
                .expect_calls(2)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/embeddings", server.port);

    let served = http
        .post(&url)
        .json(&serde_json::json!({"model": "netget-test:1b", "prompt": "hello"}))
        .send()
        .await?;
    assert_eq!(served.status(), 200, "the served model must be embedded");
    let body: serde_json::Value = served.json().await?;
    let vector = body["embedding"]
        .as_array()
        .expect("the reply carries an embedding array");
    assert_eq!(
        vector.len(),
        8,
        "the width the handler asked for must be the width returned, not the 768 the \
         endpoint used to hardcode"
    );

    let refused = http
        .post(&url)
        .json(&serde_json::json!({"model": "gpt-4", "prompt": "hello"}))
        .send()
        .await?;
    assert_eq!(
        refused.status(),
        404,
        "a model the server does not serve must be refused; it used to be embedded anyway"
    );
    let body: serde_json::Value = refused.json().await?;
    assert_eq!(body["error"], "model not served here");
    assert!(
        body.get("embedding").is_none(),
        "a refusal must not carry a vector: {body}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// An oversized body is refused with 413 before it is buffered or shown to the model.
///
/// Every endpoint on this server is reachable without authentication and `Incoming` has no
/// default limit, so `req.collect()` buffered whatever the peer chose to send. The assertion
/// that matters is the *status*: a truncated body handed to the model would look like a
/// complete one, and the model would answer a request it never saw.
#[tokio::test]
async fn an_oversized_request_body_is_refused_without_reaching_the_model() -> E2EResult<()> {
    // Deliberately no mock for any ollama_* event: the cap must be applied before the
    // request can provoke one, so an unmocked call would fail the run.
    let config = NetGetConfig::new("Open Ollama on port {AVAILABLE_PORT}.").with_mock(|mock| {
        mock.on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Handle Ollama API requests"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    // 9 MiB of prompt, one megabyte past the 8 MiB cap.
    let oversized = serde_json::json!({
        "model": "netget-test:1b",
        "prompt": "A".repeat(9 * 1024 * 1024),
    });

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/generate", server.port))
        .json(&oversized)
        .send()
        .await?;

    assert_eq!(
        response.status(),
        413,
        "a body past the cap must be refused with 413, not buffered"
    );

    // A body inside the cap on the same endpoint still reaches the model — a guard that
    // refused everything would satisfy the assertion above and be useless.
    let accepted = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/generate", server.port))
        .json(&serde_json::json!({"model": "netget-test:1b", "prompt": "hi"}))
        .send()
        .await?;
    assert_ne!(
        accepted.status(),
        413,
        "an ordinary request must not be caught by the body cap"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
