//! The dashboard's `[ exchange_client_credentials ]` path on an OpenID Connect client:
//! `AppState::send_to_client` injects an action from outside the client's own tasks, the
//! token request really goes on the wire to a provider of our own (discovery document,
//! JWKS and token endpoint served in-process), and the reported outcome is built from what
//! the provider actually returned.
//!
//! The security property this pins is the client-side mirror of the OAuth2 *server*
//! fail-open bug: an injected action that cannot complete must surface as `Rejected` or an
//! error, and must never fabricate a token. The second half of the test asserts that.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the discovery event
//! call and the deferred `oidc_token_received` event both fail, and the loop tolerates it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openidconnect --test client -- openidconnect::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

/// A minimal OpenID provider: discovery document, an empty JWKS, and a token endpoint that
/// answers every POST with the same token document. Hand-rolled HTTP/1.1 so the test needs
/// no extra feature (the repo's axum mock lives behind `mcp`).
async fn start_provider() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();

    let issuer_for_task = issuer.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let issuer = issuer_for_task.clone();
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = seen_tx.send(request.clone());

                let body = if request.contains("/.well-known/openid-configuration") {
                    serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": format!("{issuer}/token"),
                        "userinfo_endpoint": format!("{issuer}/userinfo"),
                        "jwks_uri": format!("{issuer}/jwks"),
                        "scopes_supported": ["openid", "marker.scope"],
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "client_credentials"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "claims_supported": ["sub"],
                    })
                    .to_string()
                } else if request.contains("/jwks") {
                    serde_json::json!({ "keys": [] }).to_string()
                } else {
                    serde_json::json!({
                        "access_token": "injected-marker-token",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "scope": "marker.scope",
                    })
                    .to_string()
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    (issuer, seen_rx)
}

#[tokio::test]
async fn injected_oidc_exchange_reaches_the_provider_and_never_invents_a_token() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (issuer, mut seen) = start_provider().await;

    let client_id = ClientForm {
        protocol: "OpenIDConnect".to_string(),
        remote_addr: Some(issuer.clone()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "client_id": "injected-marker-client",
            "client_secret": "injected-marker-secret",
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

    // Registered before (not after) the discovery + connected-event LLM call, which this
    // client awaits inline: the regression guard for "[ send ] reads 'no command channel'
    // during a park".
    wait_for_client_handle(&state, client_id).await;

    // A real token exchange, injected from outside the client. OIDC rides on HTTPS through
    // the `openidconnect` crate, so no byte count can honestly be reported; the outcome
    // states whether a token was actually stored.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "exchange_client_credentials", "scopes": "marker.scope"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client exchange_client_credentials");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("oidc_client_credentials")
                && detail.contains("an access token is stored"),
            "the provider issued a token, so the detail must say so: {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let mut saw_token_request = false;
    while let Ok(request) = seen.try_recv() {
        if request.contains("grant_type=client_credentials") {
            saw_token_request = true;
        }
    }
    assert!(
        saw_token_request,
        "the injected action must produce a real client-credentials request"
    );

    let token = state
        .get_client(client_id)
        .await
        .and_then(|c| {
            c.protocol_data
                .get("access_token")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
        .expect("the provider's token must be stored");
    assert_eq!(
        token, "injected-marker-token",
        "only the provider's own token may be stored"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An action the protocol does not know is Rejected - never silently swallowed, and
    // never answered with a token.
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

    // An injected disconnect ends the command loop and drops the handle. Unlike the model's
    // own disconnect it does not remove the client from under its own command loop.
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
