//! E2E tests for ARP client
//!
//! These tests verify ARP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start ARP client, < 10 LLM calls total.
//!
//! IMPORTANT: ARP tests require root privileges for packet capture and injection.
//! Run tests with: sudo ./cargo-isolated.sh test --no-default-features --features arp --test client -- client::arp::e2e_test

#[cfg(all(unix, feature = "libpcap"))]
mod arp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test ARP client can start on a network interface
    /// LLM calls: 1 (client startup)
    ///
    /// NOTE: This test requires root privileges. It will be skipped if not running as root.
    #[tokio::test]
    async fn test_arp_client_start_on_interface() -> E2EResult<()> {
        // Check if running as root (required for pcap)
        if !is_root() {
            println!("⚠️  Skipping test_arp_client_start_on_interface - requires root privileges");
            return Ok(());
        }

        // Get available network interface (typically "lo" for loopback)
        let interface = get_loopback_interface()?;

        println!("🔍 Using network interface: {}", interface);

        // Start ARP client on loopback interface with mocks
        let client_config =
            NetGetConfig::new(format!("Monitor ARP traffic on interface {}", interface)).with_mock(
                |mock| {
                    mock
                        // Mock 1: Client startup (user command)
                        .on_instruction_containing("Monitor ARP traffic")
                        .and_instruction_containing("interface")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": interface,
                                "protocol": "ARP",
                                "instruction": "Monitor ARP traffic"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                },
            );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client output shows ARP client started
        client.wait_for_any(&["ARP"], 30).await;
        assert!(
            client.output_contains("ARP").await,
            "Client should show ARP protocol. Output: {:?}",
            client.get_output().await
        );

        println!("✅ ARP client started on interface successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test ARP client can send ARP request
    /// LLM calls: 2 (client startup, send request)
    ///
    /// NOTE: This test requires root privileges.
    #[tokio::test]
    async fn test_arp_client_send_request() -> E2EResult<()> {
        // Check if running as root
        if !is_root() {
            println!("⚠️  Skipping test_arp_client_send_request - requires root privileges");
            return Ok(());
        }

        let interface = get_loopback_interface()?;

        println!("🔍 Using network interface: {}", interface);

        // Start ARP client with instruction to send ARP request with mocks
        let client_config = NetGetConfig::new(format!(
            "Monitor ARP on interface {}. Send who-has query for 127.0.0.1.",
            interface
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Monitor ARP")
                .and_instruction_containing("who-has query")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": interface,
                        "protocol": "ARP",
                        "instruction": "Send who-has query for 127.0.0.1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client started event (send ARP request)
                .on_event("arp_client_started")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_arp_request",
                        "sender_mac": "de:ad:be:ef:00:01",
                        "sender_ip": "127.0.0.1",
                        "target_ip": "127.0.0.1"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to send request
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Verify client is running
        assert_eq!(client.protocol, "ARP", "Client should be ARP protocol");

        println!("✅ ARP client sent request successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test ARP client can monitor ARP traffic
    /// LLM calls: 1 (client startup)
    ///
    /// NOTE: This test requires root privileges.
    #[tokio::test]
    async fn test_arp_client_monitor_traffic() -> E2EResult<()> {
        // Check if running as root
        if !is_root() {
            println!("⚠️  Skipping test_arp_client_monitor_traffic - requires root privileges");
            return Ok(());
        }

        let interface = get_loopback_interface()?;

        println!("🔍 Using network interface: {}", interface);

        // Start ARP client in monitoring mode with mocks
        let client_config = NetGetConfig::new(format!(
            "Monitor all ARP traffic on interface {}. Log all ARP packets.",
            interface
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Monitor all ARP traffic")
                .and_instruction_containing("Log all ARP packets")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": interface,
                        "protocol": "ARP",
                        "instruction": "Monitor all ARP traffic and log packets"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to start monitoring
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client is monitoring
        client.wait_for_any(&["ARP", "started"], 30).await;
        assert!(
            client.output_contains("ARP").await || client.output_contains("started").await,
            "Client should show ARP monitoring. Output: {:?}",
            client.get_output().await
        );

        println!("✅ ARP client monitoring traffic successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    // Helper function to check if running as root
    fn is_root() -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Check if effective user ID is 0 (root)
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            // On non-Unix systems, assume root for now
            false
        }
    }

    // Helper function to get loopback interface name
    fn get_loopback_interface() -> E2EResult<String> {
        #[cfg(target_os = "linux")]
        {
            Ok("lo".to_string())
        }
        #[cfg(target_os = "macos")]
        {
            Ok("lo0".to_string())
        }
        #[cfg(target_os = "windows")]
        {
            // Windows loopback interface may vary
            Ok("lo".to_string())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Unsupported platform for loopback interface").into())
        }
    }
}
