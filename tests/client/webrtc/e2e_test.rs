//! WebRTC client E2E tests
//!
//! NOTE: WebRTC requires two peers for full E2E testing. These tests validate
//! the basic setup and SDP generation. Full peer-to-peer testing requires
//! manual setup or a test peer implementation.

mod tests {
    use netget::llm::ollama_client::OllamaClient;
    use netget::state::app_state::AppState;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::time::Duration;

    /// Test WebRTC client initialization and SDP offer generation
    #[tokio::test]
    #[ignore = "Requires Ollama and manual peer for full testing"]
    async fn test_webrtc_client_offer_generation() {
        // Create app state
        let app_state = Arc::new(AppState::new());
        let (status_tx, mut status_rx) = mpsc::unbounded_channel();

        // Create LLM client
        let llm_client = OllamaClient::new("http://localhost:11434");

        // Test instruction
        let instruction = "Connect to WebRTC peer and send hello message";

        // Create WebRTC client instance
        use netget::state::{ClientId, ClientInstance};
        let client = ClientInstance::new(
            ClientId::new(0), // Temporary ID, add_client will assign real ID
            "peer".to_string(),
            "WebRTC".to_string(),
            instruction.to_string(),
        );

        // Open WebRTC client
        let client_id = app_state.add_client(client).await;

        println!("Created WebRTC client #{}", client_id.as_u32());

        // Start the client
        let state_clone = app_state.clone();
        let llm_clone = llm_client.clone();
        let status_clone = status_tx.clone();

        tokio::spawn(async move {
            let _ = netget::cli::client_startup::start_client_by_id(
                &state_clone,
                client_id,
                &llm_clone,
                &status_clone,
            )
            .await;
        });

        // Collect status messages
        let mut messages = Vec::new();
        let timeout = Duration::from_secs(10);
        let start = tokio::time::Instant::now();

        while start.elapsed() < timeout {
            if let Ok(msg) =
                tokio::time::timeout(Duration::from_millis(100), status_rx.recv()).await
            {
                if let Some(msg) = msg {
                    println!("Status: {}", msg);
                    messages.push(msg.clone());

                    // Check for SDP offer
                    if msg.contains("SDP Offer") {
                        println!("✓ SDP offer generated");
                        break;
                    }
                }
            }
        }

        // Verify client was created
        let client = app_state.get_client(client_id).await;
        assert!(client.is_some(), "Client should exist");

        // Verify SDP offer was generated
        let has_offer = app_state
            .with_client_mut(client_id, |c| c.get_protocol_field("sdp_offer").is_some())
            .await
            .unwrap_or(false);

        assert!(has_offer, "SDP offer should be generated");

        println!("✓ WebRTC client initialized successfully");

        // Note: Full connection test requires a peer to exchange SDP with
        // For manual testing:
        // 1. Copy SDP offer from output
        // 2. Open https://webrtc.github.io/samples/src/content/datachannel/basic/
        // 3. Paste offer in remote peer
        // 4. Copy answer and apply via apply_answer action
    }

    /// Test WebRTC client state management
    #[tokio::test]
    async fn test_webrtc_client_state() {
        use netget::state::{ClientId, ClientInstance};
        let app_state = Arc::new(AppState::new());

        // Create WebRTC client instance
        let client = ClientInstance::new(
            ClientId::new(0), // Temporary ID, add_client will assign real ID
            "test-peer".to_string(),
            "WebRTC".to_string(),
            "Test instruction".to_string(),
        );

        // Add client
        let client_id = app_state.add_client(client).await;

        // Verify client exists
        let client = app_state.get_client(client_id).await;
        assert!(client.is_some());
        assert_eq!(client.unwrap().protocol_name, "WebRTC");
    }

    /// Test that WebRTC client protocol is registered
    #[test]
    fn test_webrtc_protocol_registered() {
        use netget::protocol::CLIENT_REGISTRY;

        // Verify WebRTC is registered
        assert!(
            CLIENT_REGISTRY.has_protocol("WebRTC"),
            "WebRTC protocol should be registered"
        );

        // Get protocol
        let protocol = CLIENT_REGISTRY.get("WebRTC");
        assert!(protocol.is_some(), "Should be able to get WebRTC protocol");

        let protocol = protocol.unwrap();
        assert_eq!(protocol.protocol_name(), "WebRTC");
        assert_eq!(protocol.stack_name(), "ETH>IP>UDP>DTLS>SCTP>DataChannel");

        // Verify keywords
        let keywords = protocol.keywords();
        assert!(keywords.contains(&"webrtc"));
        assert!(keywords.contains(&"data channel"));

        println!("✓ WebRTC protocol registered correctly");
    }
}
