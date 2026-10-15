//! E2E tests for OpenID Connect server
//!
//! Tests the full OIDC flow using HTTP requests.
//!
//! These tests drive the **`openid`** protocol. They previously started
//! `"base_stack": "http"` and mocked `http_request`, which exercised the generic
//! HTTP server and never touched `src/server/openid/` at all — and made the suite
//! unbuildable in a `--features openid` build, because that build has no HTTP protocol to
//! start. They now open an `openid` server, answer its `openid_request` event, and assert
//! on the documents the OIDC layer builds from those actions rather than on bodies the
//! mock supplied verbatim.
//!
//! **Nothing here is signed or verified.** NetGet mints no keys: the `id_token` below is a
//! string the handler chose and the JWKS is whatever it returned. The assertions
//! deliberately check structure and round-tripping, never that a signature validates,
//! because no signature is ever produced.


use crate::helpers::*;
use reqwest;
use serde_json::Value;
use std::time::Duration;

/// Test OpenID Connect discovery endpoint and token flow
#[tokio::test]
async fn test_openid_connect_flow() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenID Connect Flow ===");

    let instruction = r#"OpenID Connect provider.

Answer each openid_request according to its endpoint_type:
- discovery: send_discovery_document with all endpoints and scopes openid/profile/email
- authorization: send_authorization_response redirecting with code AUTH_CODE_123, state preserved
- token: send_token_response with access_token, id_token, expires_in 3600
- userinfo: send_userinfo_response with sub, name, email, email_verified
- jwks: send_jwks_response with one RSA key
"#;

    let server_config = NetGetConfig::new(format!(
        "Start OpenID Connect server on port {{AVAILABLE_PORT}}. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup — base_stack `openid`, so the OIDC server is what runs.
            .on_instruction_containing("OpenID Connect server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "openid",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Discovery endpoint. `endpoint_type` is classified by the OIDC server
            // from the path, so matching on it proves the request reached that classifier.
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "discovery")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_discovery_document",
                    "issuer": "http://localhost/oidc",
                    "authorization_endpoint": "http://localhost/oidc/authorize",
                    "token_endpoint": "http://localhost/oidc/token",
                    "userinfo_endpoint": "http://localhost/oidc/userinfo",
                    "jwks_uri": "http://localhost/oidc/jwks.json",
                    "supported_scopes": ["openid", "profile", "email"],
                    "supported_response_types": ["code", "id_token", "token id_token"]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Authorization endpoint
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "authorization")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_authorization_response",
                    "redirect_uri": "http://localhost:9999/callback",
                    "code": "AUTH_CODE_123",
                    "state": "random_state_123"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: Token endpoint
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "token")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_token_response",
                    "access_token": "ACCESS_TOKEN_XYZ",
                    "token_type": "Bearer",
                    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.not-a-real-signature",
                    "expires_in": 3600,
                    "scope": "openid profile email"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 5: UserInfo endpoint
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "userinfo")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_userinfo_response",
                    "sub": "user123",
                    "name": "John Doe",
                    "email": "john@example.com",
                    "email_verified": true
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 6: JWKS endpoint
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "jwks")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_jwks_response",
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "key1",
                            "alg": "RS256",
                            "n": "0vx7agoebGcQve",
                            "e": "AQAB"
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Test 1: Discovery endpoint
    println!("Testing discovery endpoint...");
    let discovery_resp = client
        .get(format!(
            "http://localhost:{}/.well-known/openid-configuration",
            server.port
        ))
        .send()
        .await?;

    assert_eq!(discovery_resp.status(), 200, "Discovery should return 200");
    assert_eq!(
        discovery_resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "discovery document must be served as JSON"
    );
    let discovery: Value = discovery_resp.json().await?;

    assert_eq!(discovery["issuer"], "http://localhost/oidc");
    assert_eq!(
        discovery["authorization_endpoint"],
        "http://localhost/oidc/authorize"
    );
    assert_eq!(discovery["token_endpoint"], "http://localhost/oidc/token");
    assert_eq!(
        discovery["userinfo_endpoint"],
        "http://localhost/oidc/userinfo"
    );
    assert_eq!(discovery["jwks_uri"], "http://localhost/oidc/jwks.json");
    assert_eq!(
        discovery["scopes_supported"],
        serde_json::json!(["openid", "profile", "email"]),
        "the handler's `supported_scopes` is renamed to the spec's `scopes_supported`"
    );
    assert_eq!(
        discovery["response_types_supported"],
        serde_json::json!(["code", "id_token", "token id_token"]),
        "`supported_response_types` is renamed to `response_types_supported`"
    );
    // These two are supplied by the OIDC layer itself, not by the mock, so they prove the
    // document was assembled by `src/server/openid/` and not echoed from the handler.
    assert_eq!(
        discovery["subject_types_supported"],
        serde_json::json!(["public"]),
        "the OIDC layer must add the required subject_types_supported"
    );
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        serde_json::json!(["RS256"]),
        "the layer must default the required signing-alg list rather than emit null"
    );
    println!("✓ Discovery endpoint works");

    // Test 2: Authorization endpoint (redirect flow)
    println!("Testing authorization endpoint...");
    let auth_resp = client
        .get(format!("http://localhost:{}/authorize", server.port))
        .query(&[
            ("response_type", "code"),
            ("client_id", "test_client"),
            ("redirect_uri", "http://localhost:9999/callback"),
            ("scope", "openid profile email"),
            ("state", "random_state_123"),
        ])
        .send()
        .await?;

    assert_eq!(
        auth_resp.status(),
        302,
        "Authorization should return 302 redirect"
    );

    let location = auth_resp
        .headers()
        .get("location")
        .expect("Missing Location header")
        .to_str()?;

    // The redirect URL is built by the OIDC layer from redirect_uri + code + state; the
    // handler supplied the parts, not the assembled string.
    assert_eq!(
        location, "http://localhost:9999/callback?code=AUTH_CODE_123&state=random_state_123",
        "the layer must assemble the redirect from the handler's parts"
    );
    println!("✓ Authorization endpoint works");

    // Test 3: Token endpoint
    println!("Testing token endpoint...");
    let token_resp = client
        .post(format!("http://localhost:{}/token", server.port))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "AUTH_CODE_123"),
            ("redirect_uri", "http://localhost:9999/callback"),
            ("client_id", "test_client"),
        ])
        .send()
        .await?;

    assert_eq!(token_resp.status(), 200, "Token should return 200");
    // RFC 6749 §5.1 requires a token response to be uncacheable.
    assert_eq!(
        token_resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "token responses must be no-store"
    );
    let token: Value = token_resp.json().await?;

    assert_eq!(token["access_token"], "ACCESS_TOKEN_XYZ");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    assert_eq!(token["scope"], "openid profile email");
    // The id_token is checked for shape only. NetGet signs nothing, so asserting anything
    // about its signature would assert a capability that does not exist.
    let id_token = token["id_token"]
        .as_str()
        .expect("id_token must be a string");
    assert_eq!(
        id_token.split('.').count(),
        3,
        "id_token must at least be JWT-shaped"
    );
    println!("✓ Token endpoint works");

    // Test 4: UserInfo endpoint
    println!("Testing userinfo endpoint...");
    let userinfo_resp = client
        .get(format!("http://localhost:{}/userinfo", server.port))
        .header("Authorization", "Bearer ACCESS_TOKEN_XYZ")
        .send()
        .await?;

    assert_eq!(userinfo_resp.status(), 200, "UserInfo should return 200");
    let userinfo: Value = userinfo_resp.json().await?;

    assert_eq!(userinfo["sub"], "user123");
    assert_eq!(userinfo["name"], "John Doe");
    assert_eq!(userinfo["email"], "john@example.com");
    assert_eq!(userinfo["email_verified"], true);
    println!("✓ UserInfo endpoint works");

    // Test 5: JWKS endpoint
    println!("Testing JWKS endpoint...");
    let jwks_resp = client
        .get(format!("http://localhost:{}/jwks.json", server.port))
        .send()
        .await?;

    assert_eq!(jwks_resp.status(), 200, "JWKS should return 200");
    let jwks: Value = jwks_resp.json().await?;

    let keys = jwks["keys"]
        .as_array()
        .expect("JWKS must have a keys array");
    assert_eq!(keys.len(), 1, "the handler's single key must be served");

    let key = &keys[0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], "key1");
    assert_eq!(key["n"], "0vx7agoebGcQve");
    assert_eq!(key["e"], "AQAB");
    println!("✓ JWKS endpoint works");

    println!("\n✅ All OpenID Connect endpoints tested successfully!");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// Test OpenID Connect error handling
#[tokio::test]
async fn test_openid_error_handling() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenID Connect Error Handling ===");

    let instruction = r#"OpenID Connect provider with error handling.

For /authorize with missing client_id or redirect_uri, answer send_error_response with
error invalid_request and status_code 400.
For /token with an unsupported grant_type, answer send_error_response with error
unsupported_grant_type and status_code 400.
"#;

    let server_config = NetGetConfig::new(format!(
        "Start OpenID Connect server on port {{AVAILABLE_PORT}}. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("OpenID Connect server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "openid",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Invalid authorization request
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "authorization")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_error_response",
                    "error": "invalid_request",
                    "error_description": "Missing required parameter",
                    "status_code": 400
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Invalid token request
            .on_event("openid_request")
            .and_event_data_contains("endpoint_type", "token")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_error_response",
                    "error": "unsupported_grant_type",
                    "error_description": "Only authorization_code is supported",
                    "status_code": 400
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // Test invalid authorization request (missing client_id)
    println!("Testing invalid authorization request...");
    let resp = client
        .get(format!("http://localhost:{}/authorize", server.port))
        .query(&[("response_type", "code")])
        .send()
        .await?;

    // The status comes from the handler's `status_code`; the body is assembled by the
    // OIDC layer into the RFC 6749 §5.2 error shape.
    assert_eq!(resp.status(), 400, "Should return 400 for invalid request");
    let error: Value = resp.json().await?;
    assert_eq!(error["error"], "invalid_request");
    assert_eq!(error["error_description"], "Missing required parameter");
    println!("✓ Invalid authorization request handled correctly");

    // Test invalid token request (unsupported grant type)
    println!("Testing invalid token request...");
    let resp = client
        .post(format!("http://localhost:{}/token", server.port))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    assert_eq!(resp.status(), 400, "Should return 400 for invalid grant");
    let error: Value = resp.json().await?;
    assert_eq!(error["error"], "unsupported_grant_type");
    assert_eq!(
        error["error_description"],
        "Only authorization_code is supported"
    );
    println!("✓ Invalid token request handled correctly");

    println!("\n✅ Error handling tests passed!");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// The model answers with nothing renderable — the relying party must be failed closed, and
/// told only a category.
///
/// Two things are guarded here, and they are the two halves of the same defect. A silent or
/// hung request leaves the RP blocked until its own timeout; a reply that interpolates the
/// backend error puts netget's internals (backend URL, model name, retry text) on a
/// stranger's wire. So: a 500 `server_error` with no token in it, whose `error_description`
/// is the `WireFailure` category string and nothing else.
#[tokio::test]
async fn test_openid_no_usable_answer_fails_closed_without_leaking() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenID no-answer fails closed ===");

    let instruction = "OpenID Connect provider that produces no answer.";

    let server_config = NetGetConfig::new(format!(
        "Start OpenID Connect server on port {{AVAILABLE_PORT}}. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("OpenID Connect server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "openid",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
            // The model answers, but with zero actions: nothing the OIDC layer can render.
            .on_event("openid_request")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://localhost:{}/token", server.port))
        .form(&[("grant_type", "authorization_code"), ("code", "abc")])
        .send()
        .await?;

    assert_eq!(
        resp.status(),
        500,
        "a request the model did not answer must fail closed, not hang and not succeed"
    );
    let body = resp.text().await?;
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"], "server_error");
    assert_eq!(
        error["error_description"],
        ::netget::utils::WireFailure::Unavailable.prefixed_text(),
        "the description must be the fixed category string, not a rendered error"
    );

    // Nothing in the body may name netget's internals, and no credential may be issued.
    for forbidden in [
        "LLM",
        "Ollama",
        "ollama",
        "retries",
        "✗",
        "http://127.0.0.1",
        "11434",
        "/Users/",
        "access_token",
        "id_token",
    ] {
        assert!(
            !body.contains(forbidden),
            "fail-closed body leaked {forbidden:?}: {body}"
        );
    }
    println!("✓ failed closed with a category only: {body}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}
