//! What happens when the configured provider is not there.
//!
//! # This file used to hold five tests that ran nowhere and named production
//!
//! Each was `#[ignore]`d with the reason written into the attribute: "No `.with_mock()`
//! configured: hits real accounts.google.com / example.com and requires `--use-ollama`." So
//! they proved nothing on any runner, and the one way to make them run was to send live
//! traffic to Google. That is the client-side shape of the defect this repo already knows
//! from the DynamoDB client — *a client that loses its target must fail, never fall back to
//! the real service* — except here it was the test, not the code, pointing at production.
//!
//! They are gone. What they claimed to cover (discovery against a provider, a real token
//! exchange, the tokens that come back) is covered for real by `command_channel_test.rs`,
//! which serves a discovery document, a JWKS and a token endpoint in-process and asserts
//! that only the provider's own token is stored.
//!
//! What is left here is the case that suite cannot show, because it always has a provider:
//! with **no** provider reachable, nothing may be invented. The `openidconnect` crate is an
//! SDK, and an SDK that cannot reach its configured endpoint is exactly where a fallback
//! would hide.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connect-time calls
//! fail and the loop tolerates it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openidconnect \
//!       --test client -- openidconnect --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "OIDC client #{} never registered a command handle",
        id.as_u32()
    );
}

/// A closed port is a provider that is not there. Every flow must fail loudly and store
/// nothing — no token, from anywhere.
#[tokio::test]
async fn oidc_client_with_an_unreachable_provider_invents_nothing() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Port 1 on loopback: nothing listens, and nothing in the test contacts the network.
    let client_id = ClientForm {
        protocol: "OpenIDConnect".to_string(),
        remote_addr: Some("http://127.0.0.1:1".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "client_id": "marker-client",
            "client_secret": "marker-secret",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create openidconnect client");

    wait_for_client_handle(&state, client_id).await;

    for action in [
        serde_json::json!({"type": "exchange_client_credentials", "scopes": "marker.scope"}),
        serde_json::json!({"type": "discover_configuration"}),
        serde_json::json!({"type": "fetch_userinfo"}),
    ] {
        let name = action["type"].as_str().unwrap_or_default().to_string();
        let outcome = state
            .send_to_client(client_id, action, Duration::from_secs(15))
            .await;
        match outcome {
            // An error, or a Rejected, is the correct answer.
            Err(_) | Ok(ClientSendOutcome::Rejected { .. }) => {}
            Ok(other) => panic!(
                "{name} against a dead provider must fail rather than report success: {other:?}"
            ),
        }
    }

    // The load-bearing assertion: no credential exists. A fallback to a provider's default
    // endpoint, or a fabricated token on the failure path, would both show up here.
    let client = state.get_client(client_id).await.expect("client");
    for field in ["access_token", "id_token", "refresh_token"] {
        assert!(
            client.protocol_data.get(field).is_none(),
            "no provider answered, so {field} must not exist: {:?}",
            client.protocol_data.get(field)
        );
    }
}
