//! Where the OpenAI client sends its traffic, and what it refuses to send.
//!
//! This client holds an API key and its vendor SDK has a production default, which is the
//! exact combination `CLAUDE.md` records for the DynamoDB client: it dropped `remote_addr`,
//! the AWS SDK resolved its own default, and a client the operator pointed at localhost
//! issued real reads and writes against real AWS.
//!
//! `async-openai` behaves the same way. Its config's default `api_base` is
//! `https://api.openai.com/v1`, and the client used to leave it alone unless `remote_addr`
//! was non-empty *and* not literally that string — so an empty or unrecorded address meant
//! the key was presented to real OpenAI. Talking to real OpenAI is a legitimate thing to ask
//! this client for; arriving there because nobody said otherwise is not.
//!
//! The second half covers the narrowing casts: two of them sat between the model's
//! `max_tokens` and the wire (`as u32`, then `as u16`), so 70000 was sent as 4464 — a budget
//! silently replaced by a smaller one, which reads on the wire as a deliberate choice.


use netget::client::openai::actions::OpenAiClientProtocol;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;

/// The `openai_chat_completion` payload the executor built, or `None` if it refused.
fn chat(action: serde_json::Value) -> Option<serde_json::Value> {
    match OpenAiClientProtocol::new().execute_action(action) {
        Ok(ClientActionResult::Custom { name, data }) => {
            assert_eq!(name, "openai_chat_completion");
            Some(data)
        }
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

fn with_max_tokens(value: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "send_chat_completion",
        "messages": [{"role": "user", "content": "hello"}],
        "model": "gpt-4",
        "max_tokens": value,
    })
}

#[test]
fn a_wrapping_max_tokens_is_refused_rather_than_silently_shrunk() {
    // The value the `as u16` actually corrupted. 70000 is a real budget on a long-context
    // model, and it used to arrive as 4464 — so the assertion is that it passes through,
    // not that it is rejected. Refusing it would be a different bug with the same symptom.
    let data = chat(with_max_tokens(json!(70000u64))).expect("70000 is a legitimate budget");
    assert_eq!(
        data["max_tokens"].as_u64(),
        Some(70000),
        "70000 narrowed to 4464 under `as u16`; it must now reach the wire intact, got {data}"
    );

    // Past `u32`, the old `as u32` produced 0 — "no budget" from a request that named one.
    for bad in [json!(4_294_967_296u64), json!(u64::MAX)] {
        assert!(
            chat(with_max_tokens(bad.clone())).is_none(),
            "max_tokens {bad} is out of range and must be refused, not narrowed to 0"
        );
    }
    assert!(
        chat(with_max_tokens(json!(0))).is_none(),
        "max_tokens 0 is not a budget and must be refused"
    );
    assert!(
        chat(with_max_tokens(json!(-1))).is_none(),
        "a negative max_tokens must be refused, not reinterpreted"
    );
    assert!(
        chat(with_max_tokens(json!("4096"))).is_none(),
        "a string max_tokens must be refused rather than dropped to None, which would send \
         the model's budget as no budget at all"
    );
}

#[test]
fn ordinary_budgets_pass_through_unchanged() {
    // A guard that refused everything would satisfy the test above and be useless.
    for good in [1u64, 256, 4096, 128_000, 1_000_000] {
        let data = chat(with_max_tokens(json!(good)))
            .unwrap_or_else(|| panic!("{good} is a legitimate max_tokens"));
        assert_eq!(
            data["max_tokens"].as_u64(),
            Some(good),
            "{good} must reach the request builder unchanged, got {data}"
        );
    }
    // Omitting it stays "no explicit budget", not zero.
    let data = chat(json!({
        "type": "send_chat_completion",
        "messages": [{"role": "user", "content": "hello"}],
    }))
    .expect("max_tokens is optional");
    assert!(data["max_tokens"].is_null(), "got {data}");
}

#[test]
fn an_unusable_temperature_is_refused() {
    let with = |t: serde_json::Value| {
        json!({
            "type": "send_chat_completion",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": t,
        })
    };
    // `as f32` of a value outside OpenAI's 0.0-2.0 produces a number the API rejects with a
    // message the model never sees; a non-finite one cannot even be serialised.
    for bad in [json!(-0.5), json!(2.5), json!(1e39), json!("0.7")] {
        assert!(
            chat(with(bad.clone())).is_none(),
            "temperature {bad} must be refused"
        );
    }
    for good in [json!(0.0), json!(0.7), json!(2.0)] {
        assert!(
            chat(with(good.clone())).is_some(),
            "temperature {good} is in range and must be accepted"
        );
    }
}

/// `remote_addr` decides the API base, and an absent one refuses rather than defaulting.
///
/// Driven through the real client creation path, so what is asserted is the endpoint the
/// client recorded for itself — not a helper's return value.
mod api_base {
    use netget::cli::management::ClientForm;
    use netget::state::app_state::AppState;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn no_llm_handlers() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]
    }

    async fn endpoint_for(remote_addr: &str) -> Result<String, String> {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
        state
            .set_llm_client(netget::llm::OllamaClient::new(
                "http://127.0.0.1:1".to_string(),
            ))
            .await;
        let (tx, _rx) = mpsc::unbounded_channel();

        let id = ClientForm {
            protocol: "openai".to_string(),
            remote_addr: Some(remote_addr.to_string()),
            instruction: Some("test client".to_string()),
            event_handlers: Some(no_llm_handlers()),
            startup_params: Some(serde_json::json!({"api_key": "sk-netget-test-dummy"})),
            ..Default::default()
        }
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx,
        )
        .await
        .map_err(|e| e.to_string())?;

        for _ in 0..300 {
            let recorded = state
                .with_client_mut(id, |c| {
                    c.get_protocol_field("api_endpoint")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .await
                .flatten();
            if let Some(endpoint) = recorded {
                return Ok(endpoint);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err("the client never recorded an api_endpoint".to_string())
    }

    #[tokio::test]
    async fn a_scheme_qualified_address_is_used_exactly_as_given() {
        assert_eq!(
            endpoint_for("http://127.0.0.1:8080/v1").await.unwrap(),
            "http://127.0.0.1:8080/v1"
        );
        assert_eq!(
            endpoint_for("https://api.example.test/v1").await.unwrap(),
            "https://api.example.test/v1"
        );
    }

    #[tokio::test]
    async fn a_bare_address_gets_a_scheme_rather_than_failing_as_a_relative_url() {
        // Loopback can only mean http; anything else is assumed to be a real API over TLS.
        assert_eq!(
            endpoint_for("127.0.0.1:8080/v1").await.unwrap(),
            "http://127.0.0.1:8080/v1"
        );
        assert_eq!(
            endpoint_for("localhost:8080/v1").await.unwrap(),
            "http://localhost:8080/v1"
        );
        assert_eq!(
            endpoint_for("api.example.test/v1").await.unwrap(),
            "https://api.example.test/v1"
        );
    }

    #[tokio::test]
    async fn a_local_target_never_becomes_the_vendor_default() {
        let endpoint = endpoint_for("127.0.0.1:8080/v1").await.unwrap();
        assert!(
            !endpoint.contains("api.openai.com"),
            "a client pointed at loopback recorded {endpoint}; async-openai's default base \
             is https://api.openai.com/v1 and must never be reached by omission"
        );
    }

    #[tokio::test]
    async fn an_empty_address_refuses_instead_of_defaulting() {
        let error = endpoint_for("   ")
            .await
            .expect_err("an empty endpoint must refuse, not fall back to api.openai.com");
        assert!(
            error.contains("remote_addr"),
            "the refusal must say what is missing, got {error}"
        );
    }
}
