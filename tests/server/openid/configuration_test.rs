//! The `issuer` startup parameter, and the request-body bound.
//!
//! `issuer` and `supported_scopes` were declared, documented, parsed and written into
//! `OpenIdState` — and then read by nothing, because `handle_openid_request` took the state as
//! `_openid_state`. `src/server/openid/CLAUDE.md` said so in as many words ("only
//! informational … Either wire `OpenIdState` into the event data or drop the parameters"). They
//! are wired now, and this is the test that keeps them wired: the mock rule matches on
//! `configured_issuer` in the event, so if the value stops reaching the model the rule stops
//! matching, the request falls through to an unmocked LLM call and the assertion below fails.
//!
//! The second test bounds the request body. Every OIDC endpoint is reachable before any
//! credential is checked and the body is handed to the model as prompt text, so the previous
//! unbounded `collect()` let one anonymous POST grow the process without limit.


use crate::helpers::*;
use serde_json::Value;
use std::time::Duration;

const ISSUER: &str = "https://issuer.example/oidc";

/// A configured issuer must reach the model, or it configures nothing.
#[tokio::test]
async fn test_openid_startup_issuer_reaches_the_model() -> E2EResult<()> {
    let server_config = NetGetConfig::new("Start OpenID Connect server on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenID Connect server")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openid",
                        "instruction": "OpenID Connect provider. Serve discovery.",
                        "startup_params": {
                            "issuer": ISSUER,
                            "supported_scopes": ["openid", "email"]
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // The whole point: this rule can only match if `configured_issuer` is in the
                // event. With the parameter dead it was absent and nothing matched.
                .on_event("openid_request")
                .and_event_data_contains("configured_issuer", ISSUER)
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_discovery_document",
                        "issuer": ISSUER,
                        "authorization_endpoint": "https://issuer.example/oidc/authorize",
                        "token_endpoint": "https://issuer.example/oidc/token",
                        "userinfo_endpoint": "https://issuer.example/oidc/userinfo",
                        "jwks_uri": "https://issuer.example/oidc/jwks.json"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/openid-configuration",
            server.port
        ))
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("discovery -> {status} {text}");

    assert_eq!(
        status, 200,
        "the discovery request should have been answered by the rule keyed on \
         configured_issuer; a 500 means the issuer never reached the model: {text}"
    );
    let body: Value = serde_json::from_str(&text)?;
    assert_eq!(body["issuer"].as_str(), Some(ISSUER));

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// An over-limit body is refused before the model is consulted. The mock declares no
/// `openid_request` rule, so an LLM call here would surface as an unmatched request.
#[tokio::test]
async fn test_openid_refuses_an_oversized_body() -> E2EResult<()> {
    let server_config = NetGetConfig::new("Start OpenID Connect server on port {AVAILABLE_PORT}.")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenID Connect server")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openid",
                        "instruction": "OpenID Connect provider."
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1 MiB of form data. The server's cap is 64 KiB.
    let huge = format!(
        "grant_type=authorization_code&client_id=rp&code={}",
        "A".repeat(1024 * 1024)
    );
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/token", server.port))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(huge)
        .timeout(Duration::from_secs(25))
        .send()
        .await?;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("oversized /token -> {status} {text}");

    assert_eq!(
        status, 413,
        "an over-limit body must be refused, not buffered and prompted with: {text}"
    );
    assert!(
        !text.contains("access_token") && !text.contains("id_token"),
        "no branch of an over-limit request may issue a token: {text}"
    );

    server.verify_mocks().await?;
    Ok(())
}
