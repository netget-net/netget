//! End-to-end OAuth2 tests for NetGet
//!
//! These tests spawn the actual NetGet binary with OAuth2 prompts
//! and validate OAuth2 flows using HTTP clients.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_oauth2_authorization_code_flow() -> E2EResult<()> {
    println!("\n=== E2E Test: OAuth2 Authorization Code Flow ===");

    // Start OAuth2 server
    let prompt = "Open oauth2 on port {AVAILABLE_PORT}. Accept client 'testapp' with secret 'secret123'. \
        For authorization requests, approve all and return code 'AUTH_xyz123'. \
        For token requests with valid code, return access token 'ACCESS_token_456' with 1-hour expiry and refresh token 'REFRESH_token_789'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Authorization request - MUST BE FIRST (most specific)
            .on_event("oauth2_authorize")
            .and_event_data_contains("client_id", "testapp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "oauth2_authorize_response",
                    "code": "AUTH_xyz123",
                    "state": "random_state_123"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Token request - MUST BE SECOND (most specific)
            .on_event("oauth2_token")
            .and_event_data_contains("grant_type", "authorization_code")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "oauth2_token_response",
                    "access_token": "ACCESS_token_456",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "REFRESH_token_789"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Server startup - MUST BE LAST (less specific)
            .on_instruction_containing("Open oauth2")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OAuth2",
                    "instruction": "Handle OAuth2 authorization code flow"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create client that doesn't follow redirects (so we can inspect the 302 response)
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Step 1: Authorization request
    println!("\n[1/2] Testing authorization endpoint...");
    let auth_response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/authorize", server.port))
            .query(&[
                ("response_type", "code"),
                ("client_id", "testapp"),
                ("redirect_uri", "http://localhost:3000/callback"),
                ("scope", "read write"),
                ("state", "random_state_123"),
            ])
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received authorization response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Authorization request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Authorization request timeout");
            return Err("Authorization request timeout".into());
        }
    };

    // Authorization endpoint should redirect (302)
    assert!(
        auth_response.status().is_redirection() || auth_response.status().as_u16() == 302,
        "Authorization should redirect (302)"
    );

    // Extract code from Location header
    let location = auth_response
        .headers()
        .get("Location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    println!("✓ Redirect location: {}", location);

    // Parse authorization code from redirect
    let code = location
        .split('?')
        .nth(1)
        .and_then(|params| {
            params
                .split('&')
                .find(|p| p.starts_with("code="))
                .and_then(|p| p.split('=').nth(1))
        })
        .unwrap_or("AUTH_xyz123");

    println!("✓ Authorization code: {}", code);

    // Step 2: Token request
    println!("\n[2/2] Testing token endpoint...");
    let token_response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}/token", server.port))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=authorization_code&code={}&redirect_uri=http://localhost:3000/callback&client_id=testapp&client_secret=secret123",
                code
            ))
            .send()
    ).await {
        Ok(Ok(resp)) => {
            println!("✓ Received token response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Token request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Token request timeout");
            return Err("Token request timeout".into());
        }
    };

    assert_eq!(
        token_response.status(),
        200,
        "Token endpoint should return 200 OK"
    );

    // Parse JSON token response
    let json: Value = token_response.json().await?;
    println!("Token response: {}", serde_json::to_string_pretty(&json)?);

    // Validate OAuth2 token response format (RFC 6749 Section 5.1)
    assert!(
        json.get("access_token").and_then(|v| v.as_str()).is_some(),
        "Expected 'access_token' field"
    );

    assert_eq!(
        json.get("token_type").and_then(|v| v.as_str()),
        Some("Bearer"),
        "Expected 'token_type' to be 'Bearer'"
    );

    assert!(
        json.get("expires_in").and_then(|v| v.as_i64()).is_some(),
        "Expected 'expires_in' field"
    );

    let access_token = json["access_token"].as_str().unwrap();
    println!("✓ Access token: {}", access_token);

    if let Some(refresh_token) = json.get("refresh_token").and_then(|v| v.as_str()) {
        println!("✓ Refresh token: {}", refresh_token);
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("\n✓ OAuth2 Authorization Code Flow test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_oauth2_client_credentials_flow() -> E2EResult<()> {
    println!("\n=== E2E Test: OAuth2 Client Credentials Flow ===");

    let prompt = "Open oauth2 on port {AVAILABLE_PORT}. Accept client 'service' with secret 'service_secret'. \
        For token requests with grant_type=client_credentials, return access token 'SERVICE_token_123' with scope 'api:read api:write'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OAuth2 server
            .on_instruction_containing("Open oauth2")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OAuth2",
                    "instruction": "Handle OAuth2 client credentials flow"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Token request (POST /token with client_credentials)
            .on_event("oauth2_token")
            .and_event_data_contains("grant_type", "client_credentials")
            .respond_with_actions(serde_json::json!([
                {
                    // `oauth2_token_response`, not `send_token_response` — the latter is
                    // an *openid* action name and OAuth2's executor rejects it.
                    "type": "oauth2_token_response",
                    "access_token": "SERVICE_token_123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "api:read api:write"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send client credentials token request
    println!("Sending client credentials token request...");

    let client = reqwest::Client::new();
    let token_response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}/token", server.port))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials&client_id=service&client_secret=service_secret&scope=api:read api:write")
            .send()
    ).await {
        Ok(Ok(resp)) => {
            println!("✓ Received token response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Token request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Token request timeout");
            return Err("Token request timeout".into());
        }
    };

    assert_eq!(
        token_response.status(),
        200,
        "Token endpoint should return 200 OK"
    );

    // Parse JSON response
    let json: Value = token_response.json().await?;
    println!("Token response: {}", serde_json::to_string_pretty(&json)?);

    // Assert the *value* the handler chose, not merely that some token came back — a
    // presence check passes on any canned fallback and so cannot detect a rejected action.
    assert_eq!(
        json.get("access_token").and_then(|v| v.as_str()),
        Some("SERVICE_token_123"),
        "the handler's access_token must reach the client"
    );

    assert_eq!(
        json.get("token_type").and_then(|v| v.as_str()),
        Some("Bearer"),
        "Expected 'token_type' to be 'Bearer'"
    );

    assert_eq!(
        json.get("scope").and_then(|v| v.as_str()),
        Some("api:read api:write"),
        "granted scopes must survive the round trip"
    );

    println!("✓ Access token: {}", json["access_token"].as_str().unwrap());

    // Client credentials flow typically doesn't return refresh tokens

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("\n✓ OAuth2 Client Credentials Flow test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_oauth2_token_introspection() -> E2EResult<()> {
    println!("\n=== E2E Test: OAuth2 Token Introspection ===");

    let prompt = "Open oauth2 on port {AVAILABLE_PORT}. For introspection requests, \
        if token starts with 'VALID_', return active=true with scope 'read write' and client_id 'testapp'. \
        Otherwise return active=false.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Valid token introspection - MUST BE FIRST (most specific)
            .on_event("oauth2_introspect")
            .and_event_data_contains("token", "VALID_token_123")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "oauth2_introspect_response",
                    "active": true,
                    "scope": "read write",
                    "client_id": "testapp"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Invalid token introspection - MUST BE SECOND (most specific)
            .on_event("oauth2_introspect")
            .and_event_data_contains("token", "INVALID_token_xyz")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "oauth2_introspect_response",
                    "active": false
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Server startup - MUST BE LAST (less specific)
            .on_instruction_containing("Open oauth2")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OAuth2",
                    "instruction": "Handle OAuth2 token introspection"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // Test 1: Valid token introspection
    println!("\n[1/2] Testing valid token introspection...");
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}/introspect", server.port))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("token=VALID_token_123&token_type_hint=access_token")
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received introspection response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Introspection request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Introspection request timeout");
            return Err("Introspection request timeout".into());
        }
    };

    assert_eq!(
        response.status(),
        200,
        "Introspection endpoint should return 200 OK"
    );

    let json: Value = response.json().await?;
    println!(
        "Introspection response: {}",
        serde_json::to_string_pretty(&json)?
    );

    // Validate active token response (RFC 7662 Section 2.2)
    assert_eq!(
        json.get("active").and_then(|v| v.as_bool()),
        Some(true),
        "Expected 'active' to be true for valid token"
    );

    println!("✓ Token is active");

    // Test 2: Invalid token introspection
    println!("\n[2/2] Testing invalid token introspection...");
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}/introspect", server.port))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("token=INVALID_token_xyz")
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received introspection response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Introspection request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Introspection request timeout");
            return Err("Introspection request timeout".into());
        }
    };

    assert_eq!(
        response.status(),
        200,
        "Introspection endpoint should return 200 OK"
    );

    let json: Value = response.json().await?;
    println!(
        "Introspection response: {}",
        serde_json::to_string_pretty(&json)?
    );

    assert_eq!(
        json.get("active").and_then(|v| v.as_bool()),
        Some(false),
        "Expected 'active' to be false for invalid token"
    );

    println!("✓ Token is inactive");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("\n✓ OAuth2 Token Introspection test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_oauth2_token_revocation() -> E2EResult<()> {
    println!("\n=== E2E Test: OAuth2 Token Revocation ===");

    let prompt = "Open oauth2 on port {AVAILABLE_PORT}. For revocation requests, always succeed and return 200 OK.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OAuth2 server
            .on_instruction_containing("Open oauth2")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OAuth2",
                    "instruction": "Handle OAuth2 token revocation"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Revocation request.
            //
            // `oauth2_revoke` declares `with_no_actions()` on purpose: RFC 7009 §2.2 fixes
            // the reply at 200 with an empty body whether or not the token existed, so no
            // protocol action can change it and `mod.rs` sends it regardless. The only
            // useful thing a handler can do is note the revocation, so the mock answers
            // with the common `append_memory` action — which is also what the event's own
            // example shows. It previously answered `send_revoke_response`, an action no
            // protocol defines at all.
            .on_event("oauth2_revoke")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "append_memory",
                    "value": "revoked token: ACCESS_token_to_revoke"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send revocation request
    println!("Sending token revocation request...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}/revoke", server.port))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("token=ACCESS_token_to_revoke&token_type_hint=access_token")
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received revocation response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Revocation request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Revocation request timeout");
            return Err("Revocation request timeout".into());
        }
    };

    // RFC 7009: The authorization server responds with HTTP status code 200
    assert_eq!(
        response.status(),
        200,
        "Revocation endpoint should return 200 OK"
    );

    println!("✓ Token revoked successfully");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("\n✓ OAuth2 Token Revocation test completed\n");
    Ok(())
}
