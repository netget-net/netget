//! Where the NPM client sends its traffic, and what it refuses to send.
//!
//! `resolve_registry_url` used to end in `return "https://registry.npmjs.org".to_string()` for
//! an empty `remote_addr`, logging an INFO as it went. That is the class the root `CLAUDE.md`
//! records as "a client that loses its target must fail, never fall back to the real service":
//! an address that merely failed to arrive is indistinguishable, further down, from one the
//! caller deliberately omitted, so the fallback turns "I forgot to say where" into "talk to the
//! public registry" with nothing an operator would read as a problem. It is milder than the
//! DynamoDB case — nothing here is signed with anybody's credentials — and it is the same
//! shape. `openai::api_base_for` faced the identical choice and refuses; so does this now.
//!
//! Driven through the real client creation path, so what is asserted is the registry the client
//! recorded for itself, not a helper's return value.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features npm \
//!       --test client -- npm::registry_target --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::sync::mpsc;

/// A `*` rule answering with nothing, so `npm_connected` never reaches a model.
///
/// The LLM endpoint is a closed port anyway; this keeps the test from depending on how a
/// failed connect-event call is handled, which is a different question from this one.
fn no_llm_handlers() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": [] }
    })]
}

/// Create an NPM client for `remote_addr` and report the `registry_url` it recorded.
async fn registry_for(remote_addr: &str) -> Result<String, String> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let id = ClientForm {
        protocol: "npm".to_string(),
        remote_addr: Some(remote_addr.to_string()),
        instruction: Some("test client".to_string()),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut out = Err("the client never recorded a registry_url".to_string());
    for _ in 0..300 {
        let recorded = state
            .with_client_mut(id, |c| {
                c.get_protocol_field("registry_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten();
        if let Some(url) = recorded {
            out = Ok(url);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Stop the client before returning. Nothing here puts a byte on the wire — no request is
    // made at connect, and the `*` rule answers the connected event with no actions — but a
    // case that names a real public host has no business leaving a live client behind.
    let _ = state.remove_client(id).await;
    out
}

#[tokio::test]
async fn a_scheme_qualified_address_is_used_exactly_as_given() {
    assert_eq!(
        registry_for("http://127.0.0.1:4873").await.unwrap(),
        "http://127.0.0.1:4873"
    );
    assert_eq!(
        registry_for("https://registry.example.test/")
            .await
            .unwrap(),
        "https://registry.example.test"
    );
}

#[tokio::test]
async fn a_bare_host_gets_a_scheme_rather_than_being_discarded() {
    assert_eq!(
        registry_for("registry.example.test").await.unwrap(),
        "https://registry.example.test"
    );
}

/// The public registry is still reachable — by asking for it, which is the distinction the
/// whole rule turns on. A guard that refused everything would satisfy the refusal test below
/// while breaking the protocol's own startup example.
#[tokio::test]
async fn naming_the_public_registry_is_honoured() {
    assert_eq!(
        registry_for("registry.npmjs.org").await.unwrap(),
        "https://registry.npmjs.org"
    );
}

/// The fix. Before it, this returned `https://registry.npmjs.org`.
#[tokio::test]
async fn an_empty_address_refuses_instead_of_defaulting() {
    let error = registry_for("   ")
        .await
        .expect_err("an empty address must refuse, not fall back to the public registry");
    assert!(
        error.contains("remote_addr"),
        "the refusal must say what is missing, got {error}"
    );
    assert!(
        !error.contains("registry_url\": \"https://registry.npmjs.org"),
        "the refusal must not be a recorded vendor target, got {error}"
    );
}

/// The protocol's own name is not an address. It reaches the resolver when a caller fills
/// `remote_addr` with the thing it is starting rather than the thing it is talking to, and
/// under the old code that too became the public registry.
#[tokio::test]
async fn the_protocol_name_as_an_address_refuses() {
    registry_for("npm")
        .await
        .expect_err("\"npm\" is the protocol, not a registry, and must not resolve to one");
}
