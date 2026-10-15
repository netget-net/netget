//! `success` is the field the model reads to decide whether the subject is signed in, and it
//! is derived from a `StatusCode` chosen by whoever sent the response — an unauthenticated
//! peer, since nothing in this client verifies a signature.
//!
//! It used to be computed as `status_code.contains("Success")`. That is satisfied by
//! `…:status:NotSuccess`, by `Success-denied`, by any string with those seven characters
//! anywhere in it: an affirmative default on the one field that matters, keyed on attacker
//! input. SAML 2.0 Core 3.2.2.2 defines exactly one success value and the check is now an
//! exact match against it.
//!
//! The same parser matched the raw qualified element names `saml:NameID` and
//! `samlp:StatusCode`, so a conforming document using any other prefix — `saml2:`, which is
//! what ADFS and Shibboleth emit — parsed as having no subject and an `Unknown` status. Both
//! are covered here.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event call
//! fails and the loop tolerates it. Actions are injected through `AppState::send_to_client`,
//! the same path the dashboard uses.

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{ClientId, ClientStatus};
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

/// A Response with a caller-chosen StatusCode value and namespace prefix.
fn response_xml(status: &str, saml: &str, samlp: &str) -> String {
    format!(
        r#"<{samlp}:Response xmlns:{samlp}="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:{saml}="urn:oasis:names:tc:SAML:2.0:assertion">
  <{samlp}:Status><{samlp}:StatusCode Value="{status}"/></{samlp}:Status>
  <{saml}:Assertion><{saml}:Subject><{saml}:NameID>victim@example.com</{saml}:NameID></{saml}:Subject></{saml}:Assertion>
</{samlp}:Response>"#
    )
}

/// Inject `parse_assertion` and return the `Executed` detail, which reports `success=`.
async fn parse(state: &AppState, client_id: ClientId, xml: String) -> String {
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "parse_assertion", "response_xml": xml}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client parse_assertion");
    match outcome {
        ClientSendOutcome::Executed { detail } => detail,
        other => panic!("expected Executed, got {other:?}"),
    }
}

#[tokio::test]
async fn saml_status_code_success_is_exact_not_a_substring() {
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
    wait_for_client_handle(&state, client_id).await;

    // The control. Without it, the failures below are indistinguishable from a parser that
    // never reports success at all.
    let detail = parse(
        &state,
        client_id,
        response_xml(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "saml",
            "samlp",
        ),
    )
    .await;
    assert!(
        detail.contains("success=true"),
        "the one real success value must be recognised, got {detail:?}"
    );

    // Every one of these contains the substring "Success" and none of them is an
    // authentication. `Requester`/`Responder` are the real SAML failure codes; the others are
    // what a hostile IdP would send to exploit a `contains` check.
    for hostile in [
        "urn:oasis:names:tc:SAML:2.0:status:NotSuccess",
        "urn:oasis:names:tc:SAML:2.0:status:Success-denied",
        "Success is not what this means",
        "urn:oasis:names:tc:SAML:2.0:status:Requester",
        "urn:oasis:names:tc:SAML:2.0:status:Responder",
    ] {
        let detail = parse(&state, client_id, response_xml(hostile, "saml", "samlp")).await;
        assert!(
            detail.contains("success=false"),
            "StatusCode {hostile:?} is not an authentication, but the client reported \
             {detail:?}"
        );
    }

    // A conforming document with a different namespace prefix must parse identically.
    // Matching the raw qualified name recognised only `saml:`/`samlp:`, so this came back as
    // `Unknown` — which failed closed, but meant the client could not read ADFS or
    // Shibboleth output at all.
    let detail = parse(
        &state,
        client_id,
        response_xml(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "saml2",
            "saml2p",
        ),
    )
    .await;
    assert!(
        detail.contains("success=true"),
        "a saml2:-prefixed Response is just as conforming; got {detail:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(matches!(outcome, ClientSendOutcome::Disconnected));

    for _ in 0..1_000 {
        if matches!(
            state.get_client(client_id).await.map(|c| c.status),
            Some(ClientStatus::Disconnected)
        ) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client never reached Disconnected");
}
