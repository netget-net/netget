//! The declared `entity_id` / `acs_url` / `binding` startup parameters must actually reach
//! the AuthnRequest.
//!
//! `connect` dropped `ctx.startup_params` and wrote **hardcoded** placeholders into
//! `protocol_data` instead — `urn:netget:sp` and `http://localhost:8080/saml/acs` — under a
//! comment reading "Default entity ID (can be overridden by startup params)". Nothing could
//! override them, because nothing read them. `build_sso_request` then read those placeholders
//! back, so every AuthnRequest NetGet produced claimed to be NetGet's own placeholder SP and
//! asked the IdP to post the assertion to `localhost:8080` — whoever the caller actually was
//! and wherever their ACS really lives. A real IdP answers an unknown `Issuer` with an error,
//! and this is the SP identity and the assertion destination, so nothing subtler than
//! "SSO cannot work" was on the line.
//!
//! `binding` had a third failure mode: `build_sso_request` treats anything that is not exactly
//! `"redirect"` as HTTP-POST, so once the parameter is honoured a typo silently changes the
//! binding. It is now validated at connect and an unrecognised value is refused.
//!
//! The assertion here is on the produced request, not on stored state: `initiate_sso` builds
//! the AuthnRequest, encodes it and stores the finished `sso_url`, with no network I/O at all
//! (`post` binding is plain base64, which is why the test picks it). The test decodes that URL
//! and reads the XML.
//!
//! **Zero LLM calls**: the client's model endpoint is 127.0.0.1:1 and the events this raises
//! are free to fail.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features saml --test client -- saml::startup_params --test-threads=100


use std::time::Duration;

use base64::Engine as _;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

const SP_ENTITY_ID: &str = "https://sp.netget.test/saml/metadata";
const SP_ACS_URL: &str = "https://sp.netget.test/saml/acs";

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

/// The AuthnRequest XML out of the `sso_url` the client stored, decoded.
async fn authn_request_xml(state: &AppState, id: ClientId) -> String {
    for _ in 0..1_000 {
        let sso_url = state
            .get_client(id)
            .await
            .and_then(|c| c.get_protocol_field("sso_url").cloned())
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        if let Some(sso_url) = sso_url {
            let encoded = sso_url
                .split_once("SAMLRequest=")
                .map(|(_, rest)| rest.split('&').next().unwrap_or_default().to_string())
                .expect("sso_url must carry a SAMLRequest");
            // `post` binding, so the payload is plain base64 with no deflate step.
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .expect("SAMLRequest must be base64");
            return String::from_utf8(bytes).expect("AuthnRequest must be UTF-8");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("SAML client #{} never produced an sso_url", id.as_u32());
}

#[tokio::test]
async fn the_authn_request_carries_the_declared_sp_configuration() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "saml".to_string(),
        remote_addr: Some("https://idp.netget.test/sso".to_string()),
        instruction: Some("startup parameter probe".to_string()),
        startup_params: Some(serde_json::json!({
            "entity_id": SP_ENTITY_ID,
            "acs_url": SP_ACS_URL,
            "binding": "post",
        })),
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

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "initiate_sso"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client initiate_sso");
    assert!(
        matches!(
            outcome,
            netget::state::client_handles::ClientSendOutcome::Executed { .. }
        ),
        "initiate_sso should have produced an SSO URL, got {outcome:?}"
    );

    // Asserted before decoding, so a `binding` that never arrived fails by name rather than
    // as an opaque base64 error: the redirect encoding is deflate + URL-escaped base64.
    assert_eq!(
        state
            .get_client(client_id)
            .await
            .expect("client")
            .get_protocol_field("binding")
            .and_then(|v| v.as_str()),
        Some("post"),
        "the declared `binding` must be honoured; before the fix it was always \"redirect\""
    );

    let xml = authn_request_xml(&state, client_id).await;

    assert!(
        xml.contains(SP_ENTITY_ID),
        "the AuthnRequest must identify the SP the caller declared; before the fix it said \
         urn:netget:sp. Request was:\n{xml}"
    );
    assert!(
        xml.contains(SP_ACS_URL),
        "the AuthnRequest must send the assertion to the caller's ACS URL; before the fix it \
         said http://localhost:8080/saml/acs. Request was:\n{xml}"
    );
    assert!(
        !xml.contains("urn:netget:sp") && !xml.contains("localhost:8080"),
        "NetGet's placeholder SP configuration must not survive into the request:\n{xml}"
    );
}

/// `binding` decides between HTTP-Redirect (deflate + base64) and HTTP-POST (base64), and
/// anything not exactly `"redirect"` was treated as POST. Now that the parameter is honoured
/// that makes a typo a silent behaviour change, so an unrecognised value is refused at connect.
#[tokio::test]
async fn an_unrecognised_binding_is_refused_rather_than_reinterpreted() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let err = ClientForm {
        protocol: "saml".to_string(),
        remote_addr: Some("https://idp.netget.test/sso".to_string()),
        instruction: Some("startup parameter probe".to_string()),
        startup_params: Some(serde_json::json!({ "binding": "artifact" })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect_err("an unrecognised binding must be refused, not silently read as HTTP-POST");

    let message = format!("{err:#}");
    assert!(
        message.contains("binding"),
        "the refusal must name the parameter, got {message:?}"
    );
}

/// A caller who names nothing still gets NetGet's placeholders — the parameters are optional,
/// and honouring them must not turn an omission into a failure.
#[tokio::test]
async fn omitting_the_parameters_keeps_the_previous_defaults() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "saml".to_string(),
        remote_addr: Some("https://idp.netget.test/sso".to_string()),
        instruction: Some("startup parameter probe".to_string()),
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

    let client = state.get_client(client_id).await.expect("client");
    assert_eq!(
        client
            .get_protocol_field("entity_id")
            .and_then(|v| v.as_str()),
        Some("urn:netget:sp")
    );
    assert_eq!(
        client
            .get_protocol_field("acs_url")
            .and_then(|v| v.as_str()),
        Some("http://localhost:8080/saml/acs")
    );
    assert_eq!(
        client
            .get_protocol_field("binding")
            .and_then(|v| v.as_str()),
        Some("redirect")
    );
}
