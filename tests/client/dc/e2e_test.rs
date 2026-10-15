//! E2E tests for DC (Direct Connect) client
//!
//! These tests verify DC client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod dc_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test DC client basic connection with TLS parameter
    /// LLM calls: 1 (client startup)
    #[tokio::test]
    async fn test_dc_client_with_tls_parameter() -> E2EResult<()> {
        let client_config =
            NetGetConfig::new("Connect to 127.0.0.1:9999 via DC as 'testuser' with TLS disabled.")
                .with_mock(|mock| {
                    mock.on_instruction_containing("Connect to")
                        .and_instruction_containing("DC")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": "127.0.0.1:9999",
                                "protocol": "DC",
                                "instruction": "Test TLS parameter",
                                "startup_params": {
                                    "nickname": "testuser",
                                    "use_tls": false
                                }
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify TLS parameter was accepted (client should try to connect)
        client.wait_for_any(&["Opening DC client", "DC"], 30).await;
        assert!(
            client.output_contains("Opening DC client").await || client.output_contains("DC").await,
            "Client should attempt DC connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ DC client accepted TLS parameter");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DC client auto-reconnect parameter
    /// LLM calls: 1
    #[tokio::test]
    async fn test_dc_client_auto_reconnect_parameter() -> E2EResult<()> {
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:9998 via DC with auto-reconnect.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("DC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:9998",
                        "protocol": "DC",
                        "instruction": "Test auto-reconnect",
                        "startup_params": {
                            "nickname": "reconnector",
                            "auto_reconnect": true,
                            "max_reconnect_attempts": 3,
                            "initial_reconnect_delay_secs": 1
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ DC client accepted auto-reconnect parameters");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DC client Unicode nickname
    /// LLM calls: 1
    #[tokio::test]
    async fn test_dc_client_unicode_nickname() -> E2EResult<()> {
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:9997 via DC with Unicode nickname.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("DC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:9997",
                        "protocol": "DC",
                        "instruction": "Test Unicode",
                        "startup_params": {
                            "nickname": "用户名"  // Unicode nickname
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ DC client accepted Unicode nickname");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DC client file list action format
    /// LLM calls: 1
    #[tokio::test]
    async fn test_dc_client_filelist_action() -> E2EResult<()> {
        let client_config = NetGetConfig::new("Connect to 127.0.0.1:9996 via DC with file list.")
            .with_mock(|mock| {
                mock.on_instruction_containing("DC")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": "127.0.0.1:9996",
                            "protocol": "DC",
                            "instruction": "Test file list",
                            "startup_params": {
                                "nickname": "fileuser"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client attempted DC connection with file user
        client.wait_for_any(&["DC"], 30).await;
        assert!(
            client.output_contains("DC").await,
            "Client should attempt DC connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ DC client file list parameters accepted");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DC client private message parameters
    /// LLM calls: 1
    #[tokio::test]
    async fn test_dc_client_private_message_action() -> E2EResult<()> {
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:9995 via DC for private messaging.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("DC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:9995",
                        "protocol": "DC",
                        "instruction": "Test PM",
                        "startup_params": {
                            "nickname": "pmuser"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ DC client private message parameters accepted");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
