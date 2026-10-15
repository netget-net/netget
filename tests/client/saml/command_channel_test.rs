//! The dashboard's `[ initiate_sso ]` / `[ validate_assertion ]` path on a SAML client:
//! `AppState::send_to_client` injects an action from outside the client's own tasks.
//!
//! There is no NetGet SAML *server* to answer, and SAML puts nothing on a socket NetGet
//! owns - an AuthnRequest is carried by the user's browser - so this asserts the honest
//! outcomes instead: what the action actually produced, and that an action that cannot run
//! says so rather than reporting a success. Zero LLM calls: the client's LLM points at an
//! unreachable URL, so its connected-event call fails and the loop tolerates it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features saml --test client -- saml::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
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
        "SAML client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// A minimal signed-nothing SAML Response, base64-encoded as an IdP would post it.
fn saml_response_b64(status: &str) -> String {
    use base64::engine::Engine;
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
  <saml:Assertion><saml:Subject><saml:NameID>injected-marker@example.com</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>"#
    );
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

#[tokio::test]
async fn injected_saml_actions_report_what_they_actually_did() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "SAML".to_string(),
        remote_addr: Some("http://127.0.0.1:1/saml/sso".to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create saml client");

    // Registered before (not after) the connected-event LLM call, which this client awaits
    // inline: the regression guard for "[ send ] reads 'no command channel' during a park".
    wait_for_client_handle(&state, client_id).await;

    // initiate_sso builds and stores the AuthnRequest URL; nothing leaves NetGet, so the
    // outcome is Executed with the URL, never Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "initiate_sso",
                "relay_state": "/injected-marker",
                "force_authn": true
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client initiate_sso");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("saml_initiate_sso") && detail.contains("SAMLRequest="),
            "detail should carry the built SSO URL, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let sso_url = state
        .get_client(client_id)
        .await
        .and_then(|c| {
            c.protocol_data
                .get("sso_url")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
        .expect("initiate_sso must store the SSO URL it reported");
    assert!(
        sso_url.contains("RelayState=%2Finjected-marker"),
        "the injected relay_state must be the one in the URL, got {sso_url}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // validate_assertion parses a real IdP response and reports the status it found.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "validate_assertion",
                "saml_response": saml_response_b64("urn:oasis:names:tc:SAML:2.0:status:Success")
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client validate_assertion");
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("saml_validate_assertion")),
        "expected Executed naming the action, got {outcome:?}"
    );

    // A malformed response is a failure, not a silent success: nothing here may report an
    // authenticated session it did not get.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "validate_assertion", "saml_response": "!!not base64!!"}),
            Duration::from_secs(10),
        )
        .await;
    assert!(
        err.is_err(),
        "an undecodable SAML response must surface as an error, got {err:?}"
    );

    // An action the protocol does not know is Rejected - never silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}
