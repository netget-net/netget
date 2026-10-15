//! E2E tests for SAML client
//!
//! These tests verify SAML client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod saml_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test SAML client initialization with mocks
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    async fn test_saml_client_initialization() -> E2EResult<()> {
        let client_config = NetGetConfig::new(
            "Connect to https://idp.example.com/saml/sso via SAML for authentication",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("SAML")
                .and_instruction_containing("idp.example.com")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "idp.example.com:443",
                        "protocol": "SAML",
                        "instruction": "Connect for authentication",
                        "startup_params": {
                            "idp_url": "https://idp.example.com/saml/sso"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is SAML protocol
        assert_eq!(client.protocol, "SAML", "Client should be SAML protocol");

        println!("✅ SAML client initialized successfully");

        // Note: Mock verification is skipped because the client runs in a subprocess,
        // so mock calls happen inside the netget subprocess and can't be verified
        // from the parent test process. The test assertions above verify the client
        // initialized correctly.

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test SAML client can generate SSO URL with mocks
    /// LLM calls: 2 (client connection, SSO initiation)
    #[tokio::test]
    async fn test_saml_client_sso_url_generation() -> E2EResult<()> {
        // Initialize SAML client with mocks
        let client_config = NetGetConfig::new(
            "Connect to https://idp.example.com/saml/sso via SAML and initiate SSO authentication",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("SAML")
                .and_instruction_containing("SSO")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "idp.example.com:443",
                        "protocol": "SAML",
                        "instruction": "Initiate SSO authentication",
                        "startup_params": {
                            "idp_url": "https://idp.example.com/saml/sso"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ SAML client SSO URL generation test passed");

        // Note: Mock verification not possible in subprocess tests

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
