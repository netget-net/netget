//! The dashboard's `[ exchange_client_credentials ]` path on an OAuth2 client:
//! `AppState::send_to_client` injects an action from outside the client's own tasks, the
//! token request really goes on the wire to a token endpoint of our own, and the reported
//! outcome is built from what the provider actually returned.
//!
//! The security property this pins is the client-side mirror of the OAuth2 *server*
//! fail-open bug: an injected action that cannot complete must say so - `Rejected`, an
//! error, or an `Executed` that states no token was stored - and must never fabricate a
//! code or a token. The second half of the test asserts exactly that.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event
//! call and the deferred `oauth2_token_obtained` event both fail, and the loop tolerates it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features oauth2 --test client -- oauth2::command_channel --test-threads=100

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
        "OAuth2 client #{} never registered a command handle",
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

/// A one-endpoint OAuth2 token server: answers every POST with the same token document and
/// records the request bodies it saw. Hand-rolled HTTP/1.1 so the test needs no extra
/// feature (the repo's axum mock lives behind `mcp`).
async fn start_token_endpoint() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = seen_tx.send(request);

                let body = r#"{"access_token":"injected-marker-token","token_type":"bearer","expires_in":3600,"scope":"marker.scope"}"#;
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

    (format!("http://127.0.0.1:{port}/token"), seen_rx)
}

#[tokio::test]
async fn injected_oauth2_exchange_reaches_the_token_endpoint_and_never_invents_a_token() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (token_url, mut seen) = start_token_endpoint().await;

    let client_id = ClientForm {
        protocol: "OAuth2".to_string(),
        remote_addr: Some(token_url.clone()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "client_id": "injected-marker-client",
            "client_secret": "injected-marker-secret",
            "token_url": token_url,
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create oauth2 client");

    // Registered before (not after) the connected-event LLM call, which this client awaits
    // inline: the regression guard for "[ send ] reads 'no command channel' during a park".
    wait_for_client_handle(&state, client_id).await;

    // A real token exchange, injected from outside the client. OAuth2 rides on HTTPS
    // through the `oauth2` crate, so no byte count can honestly be reported; the outcome
    // states whether a token was actually stored.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "exchange_client_credentials", "scopes": "marker.scope"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client exchange_client_credentials");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("oauth2_exchange_client_credentials")
                && detail.contains("an access token is stored"),
            "the provider issued a token, so the detail must say so: {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let request = seen.try_recv().expect("the token endpoint saw a request");
    // The `oauth2` crate puts the configured credentials in an HTTP Basic header (RFC 6749
    // §2.3.1) and the grant in the form body; assert both, so the test proves the injected
    // action used *this client's* configuration and not some default.
    let basic = {
        use base64::engine::Engine;
        base64::engine::general_purpose::STANDARD
            .encode("injected-marker-client:injected-marker-secret")
    };
    assert!(
        request.contains("grant_type=client_credentials")
            && request.contains("scope=marker.scope")
            && request.contains(&basic),
        "the injected action must produce a real client-credentials request, got:\n{request}"
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

    // Fail-closed half: `exchange_code` needs a PKCE verifier that only `generate_auth_url`
    // can produce, so this cannot run. It must surface as an error - not as a success, and
    // not by inventing a code or minting a token.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "exchange_code", "code": "not-a-real-code"}),
            Duration::from_secs(10),
        )
        .await;
    assert!(
        err.is_err(),
        "an exchange with no PKCE verifier must fail loudly, got {err:?}"
    );
    let token_after = state
        .get_client(client_id)
        .await
        .and_then(|c| {
            c.protocol_data
                .get("access_token")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
        .expect("token field");
    assert_eq!(
        token_after, "injected-marker-token",
        "a failed exchange must not replace or fabricate the stored token"
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
