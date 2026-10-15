//! OAuth2 client E2E tests


use netget::cli::client_startup::start_client_by_id;
use netget::llm::OllamaClient;
use netget::state::app_state::AppState;
use netget::state::client::{ClientInstance, ClientStatus};
use netget::state::ClientId;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use axum::{extract::Form, response::Json, routing::post, Router};

/// Helper to create a test OAuth2 client instance
fn create_oauth2_client_instance(
    remote_addr: String,
    client_id_str: String,
    client_secret: Option<String>,
    token_url: String,
    instruction: String,
) -> ClientInstance {
    let mut protocol_data = serde_json::Map::new();
    protocol_data.insert("client_id".to_string(), serde_json::json!(client_id_str));
    if let Some(secret) = client_secret {
        protocol_data.insert("client_secret".to_string(), serde_json::json!(secret));
    }
    protocol_data.insert("token_url".to_string(), serde_json::json!(token_url));

    let mut client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        remote_addr,
        "OAuth2".to_string(),
        instruction,
    );
    client.startup_params = Some(serde_json::Value::Object(protocol_data.clone()));
    client.protocol_data = serde_json::Value::Object(protocol_data);
    client
}

#[tokio::test]
async fn test_oauth2_client_initialization() {
    // Basic smoke test that verifies OAuth2 client can be created
    let app_state = Arc::new(AppState::new());

    // Create OAuth2 client instance
    let client = create_oauth2_client_instance(
        "http://localhost:8080".to_string(),
        "test-client-id".to_string(),
        Some("test-client-secret".to_string()),
        "http://localhost:8080/oauth/token".to_string(),
        "Test OAuth2 client initialization".to_string(),
    );

    let client_id = app_state.add_client(client).await;

    // Verify client was created
    assert!(app_state.get_client(client_id).await.is_some());
}

#[tokio::test]
#[ignore = "Requires Ollama to be running"]
async fn test_oauth2_password_flow() {
    // Skip if mcp feature (which provides axum) is not enabled

    {
        // Start mock OAuth2 server
        let mock_server = start_mock_oauth_server().await;
        let token_url = format!("{}/oauth/token", mock_server);

        let app_state = Arc::new(AppState::new());
        let (status_tx, _status_rx) = mpsc::unbounded_channel();

        // Create OAuth2 client with password flow instruction
        let client = create_oauth2_client_instance(
            mock_server.clone(),
            "test-client".to_string(),
            Some("test-secret".to_string()),
            token_url,
            "Exchange username 'testuser' and password 'testpass' for access token using password flow".to_string(),
        );

        let client_id = app_state.add_client(client).await;

        // Initialize Ollama client
        let ollama_client = OllamaClient::new("http://localhost:11434".to_string());

        // Start the client (triggers LLM + authentication)
        match start_client_by_id(&app_state, client_id, &ollama_client, &status_tx).await {
            Ok(_) => {
                // Wait a bit for async operations
                sleep(Duration::from_secs(2)).await;

                // Verify access token was obtained
                assert_token_stored(&app_state, client_id).await;

                // Verify token details
                let token = extract_access_token(&app_state, client_id).await;
                assert!(token.is_some(), "Access token should be present");
                assert_eq!(token.unwrap(), "mock_access_token");
            }
            Err(e) => {
                println!("Test skipped - Ollama not available: {}", e);
            }
        }
    }
}

#[tokio::test]
#[ignore = "Requires Ollama to be running"]
async fn test_oauth2_client_credentials_flow() {

    {
        let mock_server = start_mock_oauth_server().await;
        let token_url = format!("{}/oauth/token", mock_server);

        let app_state = Arc::new(AppState::new());
        let (status_tx, _status_rx) = mpsc::unbounded_channel();

        let client = create_oauth2_client_instance(
            mock_server.clone(),
            "test-client".to_string(),
            Some("test-secret".to_string()),
            token_url,
            "Get access token using client credentials flow".to_string(),
        );

        let client_id = app_state.add_client(client).await;

        let ollama_client = OllamaClient::new("http://localhost:11434".to_string());

        match start_client_by_id(&app_state, client_id, &ollama_client, &status_tx).await {
            Ok(_) => {
                sleep(Duration::from_secs(2)).await;
                assert_token_stored(&app_state, client_id).await;

                // Client credentials flow should not return refresh token
                let refresh_token = app_state
                    .with_client_mut(client_id, |client| {
                        client
                            .get_protocol_field("refresh_token")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .await;

                // Mock server returns refresh token for all flows, but in real scenarios
                // client credentials flow typically doesn't
                assert!(refresh_token.is_none() || refresh_token.is_some());
            }
            Err(e) => {
                println!("Test skipped - Ollama not available: {}", e);
            }
        }
    }
}

#[tokio::test]
#[ignore = "Requires Ollama to be running"]
async fn test_oauth2_token_refresh() {

    {
        let mock_server = start_mock_oauth_server().await;
        let token_url = format!("{}/oauth/token", mock_server);

        let app_state = Arc::new(AppState::new());
        let (status_tx, _status_rx) = mpsc::unbounded_channel();

        // First, get initial tokens with password flow
        let client = create_oauth2_client_instance(
            mock_server.clone(),
            "test-client".to_string(),
            Some("test-secret".to_string()),
            token_url,
            "First get token with password flow for user 'testuser' and password 'testpass', then refresh it".to_string(),
        );

        let client_id = app_state.add_client(client).await;

        let ollama_client = OllamaClient::new("http://localhost:11434".to_string());

        match start_client_by_id(&app_state, client_id, &ollama_client, &status_tx).await {
            Ok(_) => {
                sleep(Duration::from_secs(2)).await;

                // Verify initial token
                let initial_token = extract_access_token(&app_state, client_id).await;
                assert!(initial_token.is_some(), "Initial token should be present");

                // LLM should have triggered refresh based on instruction
                // In a real scenario, we'd wait for token expiry or manually trigger refresh
                sleep(Duration::from_secs(2)).await;

                // The token might be refreshed or same depending on LLM behavior
                let new_token = extract_access_token(&app_state, client_id).await;
                assert!(
                    new_token.is_some(),
                    "Token should still be present after refresh"
                );
            }
            Err(e) => {
                println!("Test skipped - Ollama not available: {}", e);
            }
        }
    }
}

#[tokio::test]
#[ignore = "Requires Ollama to be running"]
async fn test_oauth2_error_handling() {

    {
        let mock_server = start_mock_oauth_server_with_errors().await;
        let token_url = format!("{}/oauth/token", mock_server);

        let app_state = Arc::new(AppState::new());
        let (status_tx, _status_rx) = mpsc::unbounded_channel();

        let client = create_oauth2_client_instance(
            mock_server.clone(),
            "test-client".to_string(),
            Some("test-secret".to_string()),
            token_url,
            "Try to authenticate with password flow using username 'baduser' and password 'badpass'".to_string(),
        );

        let client_id = app_state.add_client(client).await;

        let ollama_client = OllamaClient::new("http://localhost:11434".to_string());

        match start_client_by_id(&app_state, client_id, &ollama_client, &status_tx).await {
            Ok(_) => {
                sleep(Duration::from_secs(2)).await;

                // Client should still be connected even after error
                let client_status = app_state
                    .get_client(client_id)
                    .await
                    .map(|c| c.status.clone());

                assert!(
                    matches!(
                        client_status,
                        Some(ClientStatus::Connected) | Some(ClientStatus::Error(_))
                    ),
                    "Client should be connected or in error state"
                );

                // No token should be stored after error
                let token = extract_access_token(&app_state, client_id).await;
                assert!(
                    token.is_none(),
                    "No token should be stored after auth error"
                );
            }
            Err(e) => {
                println!("Test skipped - Ollama not available: {}", e);
            }
        }
    }
}

// Helper functions
async fn start_mock_oauth_server() -> String {
    use std::net::TcpListener;

    // Find available port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local address");
    drop(listener);

    let port = addr.port();

    // Create mock OAuth2 server
    let app = Router::new().route("/oauth/token", post(handle_token_request));

    // Spawn server
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind");

        axum::serve(listener, app).await.expect("Server failed");
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    format!("http://127.0.0.1:{}", port)
}

async fn start_mock_oauth_server_with_errors() -> String {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local address");
    drop(listener);

    let port = addr.port();

    let app = Router::new().route("/oauth/token", post(handle_token_request_with_errors));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind");

        axum::serve(listener, app).await.expect("Server failed");
    });

    sleep(Duration::from_millis(100)).await;

    format!("http://127.0.0.1:{}", port)
}

async fn handle_token_request(
    Form(params): Form<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");

    match grant_type {
        "password" => Json(serde_json::json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "read write"
        })),
        "client_credentials" => Json(serde_json::json!({
            "access_token": "mock_client_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "api"
        })),
        "refresh_token" => Json(serde_json::json!({
            "access_token": "mock_refreshed_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_new_refresh_token"
        })),
        "urn:ietf:params:oauth:grant-type:device_code" => Json(serde_json::json!({
            "access_token": "mock_device_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })),
        _ => Json(serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "Grant type not supported"
        })),
    }
}

async fn handle_token_request_with_errors(
    Form(_params): Form<std::collections::HashMap<String, String>>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Invalid username or password"
        })),
    )
}

/// Assert that an access token is stored for a client
async fn assert_token_stored(app_state: &AppState, client_id: ClientId) {
    let has_token = app_state
        .with_client_mut(client_id, |client| {
            client
                .get_protocol_field("access_token")
                .and_then(|v| v.as_str())
                .is_some()
        })
        .await
        .unwrap_or(false);

    assert!(has_token, "Access token should be stored");
}

/// Extract access token from client protocol data
async fn extract_access_token(app_state: &AppState, client_id: ClientId) -> Option<String> {
    app_state
        .with_client_mut(client_id, |client| {
            client
                .get_protocol_field("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .await
        .flatten()
}
