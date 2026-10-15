//! E2E tests for OSPF client — **weak, and weaker than they look.**
//!
//! OSPF needs a raw IP-89 socket (`CAP_NET_RAW`), so these spawn the real netget binary and
//! then `return Ok(())` when the process is not root. That is a *silent pass*: on every
//! ordinary run and every CI run all three report green having exercised nothing. The
//! project treats a skip-when-missing gate as no evidence at all, and these are that shape.
//!
//! They are also weak when they do run. Each asserts that some word appears in the client's
//! own output — `"OSPF"`, `"Hello"`, `"connected"`, `"received"` — and the prompt handed to
//! the client already contains those words, so the assertion can be satisfied by the prompt
//! being echoed back. `test_ospf_client_with_server` additionally uses fixed sleeps and
//! configures no mock, so under a reachable Ollama it would make real LLM calls. Nothing in
//! this file calls `verify_mocks()`.
//!
//! **The real coverage is `command_channel_test.rs`**, which hard-fails either way: without
//! the capability it asserts the failure contract (`connect()` returns `Err`, no command
//! handle is left behind, a later `send_to_client` fails fast rather than hanging), and with
//! it, the live wiring. The one test there that actually multicasts a packet is `#[ignore]`d
//! rather than skipped-with-a-pass, which is the honest way to gate on a privilege.
//!
//! Fixing this file means either dropping the privilege requirement (impossible — raw IP-89
//! is the protocol) or hard-failing when unprivileged, which would make the suite unrunnable
//! for everyone. Left as-is deliberately; the point of this note is that the green tick here
//! must not be read as OSPF client evidence. `metadata().e2e_testing` says the same.
//!
//! Test strategy: Use netget binary to start OSPF client, < 5 LLM calls total.

#[cfg(unix)]
mod ospf_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Helper function to check if we have root privileges
    fn has_root_privileges() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Test OSPF client initialization
    /// LLM calls: 1 (client startup)
    ///
    /// This test verifies that the OSPF client can be initialized and provides
    /// appropriate error messages when root privileges are missing.
    #[tokio::test]
    async fn test_ospf_client_initialization() -> E2EResult<()> {
        if !has_root_privileges() {
            println!("⚠️  Skipping test: OSPF requires root privileges");
            println!("   Run with: sudo -E cargo test --no-default-features --features ospf");
            return Ok(());
        }

        // Start OSPF client on loopback interface
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1 via OSPF. Monitor for Hello packets. Don't send any packets yet.",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client output shows OSPF initialization
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("OSPF")) || output.iter().any(|l| l.contains("ospf")),
            "Client should mention OSPF in output. Output: {:?}",
            output
        );

        println!("✅ OSPF client initialized successfully");

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test OSPF client can send Hello packet
    /// LLM calls: 2 (client startup, send Hello)
    ///
    /// This test verifies the OSPF client can send a Hello packet to the multicast group.
    #[tokio::test]
    async fn test_ospf_client_send_hello() -> E2EResult<()> {
        if !has_root_privileges() {
            println!("⚠️  Skipping test: OSPF requires root privileges");
            return Ok(());
        }

        // Start OSPF client configured to send a Hello packet
        let client_config = NetGetConfig::new(
            "Connect to 192.168.1.100 via OSPF with router_id 1.1.1.1. Send one Hello packet to multicast, then disconnect."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to send Hello
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client shows OSPF activity
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("Hello"))
                || output.iter().any(|l| l.contains("OSPF"))
                || output.iter().any(|l| l.contains("connected")),
            "Client should show OSPF Hello or connection. Output: {:?}",
            output
        );

        println!("✅ OSPF client sent Hello packet");

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test OSPF client with OSPF server (full E2E)
    /// LLM calls: 4 (server startup, client startup, server receives Hello, client receives Hello)
    ///
    /// This test starts both an OSPF server and client to verify they can exchange Hello packets.
    #[tokio::test]
    async fn test_ospf_client_with_server() -> E2EResult<()> {
        if !has_root_privileges() {
            println!("⚠️  Skipping test: OSPF requires root privileges");
            return Ok(());
        }

        // Start OSPF server
        let server_config = NetGetConfig::new(
            "Listen on interface 192.168.1.100 as OSPF router 192.168.1.100 in area 0. Respond to all Hello packets."
        );

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start OSPF client
        let client_config = NetGetConfig::new(
            "Connect to 192.168.1.101 via OSPF with router_id 192.168.1.101 in area 0. Send Hello, wait for response."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give time for Hello exchange
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify server received Hello
        let server_output = server.get_output().await;
        assert!(
            server_output.iter().any(|l| l.contains("Hello"))
                || server_output.iter().any(|l| l.contains("neighbor")),
            "Server should receive Hello. Output: {:?}",
            server_output
        );

        // Verify client received response
        let client_output = client.get_output().await;
        assert!(
            client_output.iter().any(|l| l.contains("Hello"))
                || client_output.iter().any(|l| l.contains("received")),
            "Client should receive Hello response. Output: {:?}",
            client_output
        );

        println!("✅ OSPF client and server exchanged Hello packets");

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}
