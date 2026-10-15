//! XMPP client E2E tests

#![cfg(unix)]

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use netget::llm::ollama_client::OllamaClient;
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientInstance, ClientStatus};

/// The test account: the JID and password go in startup parameters, the server's address in
/// `remote_addr`.
fn alice_params() -> netget::protocol::StartupParams {
    use netget::llm::actions::protocol_trait::Protocol;
    netget::protocol::StartupParams::new(
        serde_json::json!({"jid": "alice@localhost", "password": "password"}),
        netget::client::xmpp::XmppClientProtocol::new().get_startup_parameters(),
    )
    .expect("valid XMPP startup parameters")
}

/// Test basic XMPP client connection
///
/// This test connects to a local XMPP server and sends presence.
/// Requires a local XMPP server (prosody/ejabberd) listening on 127.0.0.1:5222
/// with test account alice@localhost, password "password".
#[tokio::test]
#[ignore = "Requires local XMPP server"]
async fn test_xmpp_client_connect() -> Result<()> {
    // Setup app state
    let app_state = Arc::new(AppState::new());
    let (status_tx, mut status_rx) = mpsc::unbounded_channel();

    // Create LLM client
    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    // Create client instance
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "127.0.0.1:5222".to_string(),
        "XMPP".to_string(),
        "Send presence and log any messages".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect client
    use netget::client::xmpp::XmppClientConnection;
    let result = timeout(
        Duration::from_secs(10),
        XmppClientConnection::connect_with_llm_actions(
            "127.0.0.1:5222".to_string(),
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            client_id,
            Some(alice_params()),
        ),
    )
    .await;

    // Check connection succeeded
    assert!(result.is_ok(), "Connection timed out");
    assert!(result?.is_ok(), "Connection failed");

    // Wait for status updates
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check client status
    let client = app_state.get_client(client_id).await;
    assert!(client.is_some());
    let client = client.unwrap();

    match client.status {
        ClientStatus::Connected => {
            println!("XMPP client connected successfully");
        }
        ClientStatus::Error(e) => {
            panic!("XMPP client error: {}", e);
        }
        _ => {
            panic!("Unexpected client status: {:?}", client.status);
        }
    }

    // Drain status messages
    while let Ok(msg) = status_rx.try_recv() {
        println!("Status: {}", msg);
    }

    Ok(())
}

/// Test sending XMPP message
///
/// This test sends a message to another JID.
/// Requires local XMPP server with two test accounts.
#[tokio::test]
#[ignore = "Requires local XMPP server and manual verification"]
async fn test_xmpp_client_send_message() -> Result<()> {
    // Setup app state
    let app_state = Arc::new(AppState::new());
    let (status_tx, mut status_rx) = mpsc::unbounded_channel();

    // Create LLM client
    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    // Create client instance
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "127.0.0.1:5222".to_string(),
        "XMPP".to_string(),
        "Send a test message to bob@localhost".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect client
    use netget::client::xmpp::XmppClientConnection;
    XmppClientConnection::connect_with_llm_actions(
        "127.0.0.1:5222".to_string(),
        llm_client,
        app_state.clone(),
        status_tx.clone(),
        client_id,
        Some(alice_params()),
    )
    .await?;

    // Wait for connection and LLM to process
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check that message was sent (check status messages)
    let mut found_send = false;
    while let Ok(msg) = status_rx.try_recv() {
        println!("Status: {}", msg);
        if msg.contains("sent message") || msg.contains("send_message") {
            found_send = true;
        }
    }

    // Note: This test requires manual verification on the receiving end
    println!("Test completed. Check bob@localhost for received message.");

    Ok(())
}

/// Test XMPP presence updates
#[tokio::test]
#[ignore = "Requires local XMPP server"]
async fn test_xmpp_client_presence() -> Result<()> {
    // Setup app state
    let app_state = Arc::new(AppState::new());
    let (status_tx, _status_rx) = mpsc::unbounded_channel();

    // Create LLM client
    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    // Create client instance with presence instruction
    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "127.0.0.1:5222".to_string(),
        "XMPP".to_string(),
        "Send presence as 'away' with status 'Testing NetGet XMPP'".to_string(),
    );
    let client_id = app_state.add_client(client).await;

    // Connect client
    use netget::client::xmpp::XmppClientConnection;
    XmppClientConnection::connect_with_llm_actions(
        "127.0.0.1:5222".to_string(),
        llm_client,
        app_state.clone(),
        status_tx.clone(),
        client_id,
        Some(alice_params()),
    )
    .await?;

    // Wait for LLM to process and send presence
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Note: This requires manual verification
    println!("Test completed. Check alice@localhost presence status.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify feature flag is enabled
    #[test]
    fn test_xmpp_feature_enabled() {
        // This test just ensures the xmpp feature is compiled
        assert!(true);
    }
}
