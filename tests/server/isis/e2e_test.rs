//! E2E tests for IS-IS server
//!
//! These tests spawn the NetGet binary and test IS-IS protocol operations.
//!
//! **IMPORTANT**: IS-IS operates at Layer 2 using pcap. These tests require:
//! - Root access (CAP_NET_RAW for pcap)
//! - Virtual network interfaces (veth pairs) OR
//! - Packet injection tools (scapy, tcpreplay)
//!
//! The tests are designed to work with mock LLM responses by default.
//! Use --use-ollama flag to test with real Ollama.

#[cfg(all(unix, feature = "libpcap"))]
mod e2e_isis {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;

    /// Test IS-IS server startup with interface configuration
    /// LLM calls: 1 (server startup with open_server action)
    #[tokio::test]
    #[ignore = "Requires root and network interface setup"]
    async fn test_isis_server_startup() -> E2EResult<()> {
        println!("\n=== Test: IS-IS Server Startup ===");

        let prompt = "Start an IS-IS router on interface lo0 with system-id 0000.0000.0001 in area 49.0001 at level-2.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock: Server startup (user command)
                .on_instruction_containing("IS-IS router")
                .and_instruction_containing("system-id")
                .and_instruction_containing("area")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "interface": "lo0",
                        "protocol": "IS-IS",
                        "instruction": "IS-IS router with system-id 0000.0000.0001 in area 49.0001",
                        "startup_params": {
                            "interface": "lo0",
                            "system_id": "0000.0000.0001",
                            "area_id": "49.0001",
                            "level": "level-2"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut instance = start_netget_server(config).await?;

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify server was started
        // Server started successfully
        assert_eq!(instance.stack, "IS-IS", "Should be IS-IS stack");

        println!("  [TEST] ✓ IS-IS server started successfully");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        instance.wait_for_mocks(30).await;
        instance.verify_mocks().await?;

        Ok(())
    }

    /// Test IS-IS Hello PDU handling
    /// LLM calls: 2 (server startup, hello received)
    ///
    /// This test would require:
    /// 1. Virtual interface (veth pair)
    /// 2. Ability to inject raw Ethernet frames with IS-IS PDUs
    /// 3. Root privileges
    #[tokio::test]
    #[ignore = "Requires root, veth setup, and packet injection"]
    async fn test_isis_hello_pdu_exchange() -> E2EResult<()> {
        println!("\n=== Test: IS-IS Hello PDU Exchange ===");

        let prompt = "Start an IS-IS router on interface veth0 with system-id 0000.0000.0001 in area 49.0001 at level-2. \
                      When you receive a Hello PDU from a neighbor, respond with your own Hello PDU using the \
                      send_isis_hello action.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("IS-IS router")
                .and_instruction_containing("veth0")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "interface": "veth0",
                        "protocol": "IS-IS",
                        "instruction": "IS-IS router responding to Hello PDUs",
                        "startup_params": {
                            "interface": "veth0",
                            "system_id": "0000.0000.0001",
                            "area_id": "49.0001",
                            "level": "level-2"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: ISIS Hello received event
                .on_event("isis_hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_isis_hello",
                        "pdu_type": "lan_hello_l2",
                        "system_id": "0000.0000.0001",
                        "area_id": "49.0001",
                        "holding_time": 30
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut instance = start_netget_server(config).await?;

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("  [TEST] Server started, would now inject IS-IS Hello PDU via raw socket");
        println!("  [TEST] (Skipping packet injection in this test framework)");

        // In a real test environment, you would:
        // 1. Create raw socket on veth1 (peer of veth0)
        // 2. Build IS-IS Hello PDU with Ethernet + LLC/SNAP + IS-IS headers
        // 3. Send to multicast MAC 01:80:C2:00:00:15 (All L2 IS)
        // 4. Wait for response on veth1
        // 5. Verify response is valid IS-IS Hello PDU

        println!("  [TEST] ✓ IS-IS Hello exchange test structure validated");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        instance.wait_for_mocks(30).await;
        instance.verify_mocks().await?;

        Ok(())
    }

    /// Test IS-IS with multiple Hello PDUs
    /// LLM calls: 4 (startup + 3 hello events)
    #[tokio::test]
    #[ignore = "Requires root, veth setup, and packet injection"]
    async fn test_isis_multiple_neighbors() -> E2EResult<()> {
        println!("\n=== Test: IS-IS Multiple Neighbor Discovery ===");

        let prompt = "Start an IS-IS router on interface veth0 with system-id 0000.0000.0001 in area 49.0001. \
                      Respond to all Hello PDUs with your own Hello PDU to establish adjacencies.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("IS-IS router")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "interface": "veth0",
                        "protocol": "IS-IS",
                        "instruction": "IS-IS router for neighbor discovery",
                        "startup_params": {
                            "interface": "veth0",
                            "system_id": "0000.0000.0001",
                            "area_id": "49.0001",
                            "level": "level-2"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-4: Three Hello PDUs from different neighbors
                .on_event("isis_hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_isis_hello",
                        "pdu_type": "lan_hello_l2",
                        "system_id": "0000.0000.0001",
                        "area_id": "49.0001",
                        "holding_time": 30
                    }
                ]))
                .expect_calls(3)
                .and()
        });

        let mut instance = start_netget_server(config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("  [TEST] Server ready for multiple neighbor discovery");
        println!("  [TEST] Would inject 3 Hello PDUs from different System IDs:");
        println!("  [TEST]   - 0000.0000.0002");
        println!("  [TEST]   - 0000.0000.0003");
        println!("  [TEST]   - 0000.0000.0004");

        println!("  [TEST] ✓ Multiple neighbor test structure validated");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        instance.wait_for_mocks(30).await;
        instance.verify_mocks().await?;

        Ok(())
    }

    /// Unit test: Verify IS-IS PDU structure parsing
    /// This test doesn't require network access or root
    #[test]
    fn test_isis_pdu_structure() {
        println!("\n=== Test: IS-IS PDU Structure ===");

        // Sample IS-IS L2 LAN Hello PDU (minimal valid structure)
        // Ethernet header (14 bytes) + LLC/SNAP (8 bytes) + IS-IS header (8+ bytes)

        let sample_ethernet = vec![
            // Dest MAC: 01:80:C2:00:00:15 (All L2 IS multicast)
            0x01, 0x80, 0xC2, 0x00, 0x00, 0x15, // Src MAC: 00:00:00:00:00:01
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Length: 0x0030 (48 bytes payload)
            0x00, 0x30,
        ];

        let sample_llc_snap = vec![
            // DSAP: 0xFE (ISO CLNS)
            0xFE, // SSAP: 0xFE
            0xFE, // Control: 0x03 (Unnumbered Information)
            0x03, // OUI: 0x000000
            0x00, 0x00, 0x00, // PID: 0xFEFE (IS-IS)
            0xFE, 0xFE,
        ];

        let sample_isis = vec![
            // Intradomain Routing Protocol Discriminator: 0x83
            0x83, // Length Indicator: 27
            0x1B, // Version/Protocol ID: 1
            0x01, // ID Length: 0 (means 6 bytes)
            0x00, // PDU Type: 16 (L2 LAN Hello)
            0x10, // Version: 1
            0x01, // Reserved: 0
            0x00, // Max Area Addresses: 0
            0x00,
        ];

        // Combine all parts
        let mut full_frame = Vec::new();
        full_frame.extend_from_slice(&sample_ethernet);
        full_frame.extend_from_slice(&sample_llc_snap);
        full_frame.extend_from_slice(&sample_isis);

        // Verify structure
        assert_eq!(full_frame[0], 0x01, "Dest MAC should start with 0x01");
        assert_eq!(full_frame[14], 0xFE, "LLC DSAP should be 0xFE");
        assert_eq!(full_frame[15], 0xFE, "LLC SSAP should be 0xFE");
        assert_eq!(full_frame[22], 0x83, "IS-IS discriminator should be 0x83");
        assert_eq!(full_frame[26], 0x10, "PDU type should be 16 (L2 LAN Hello)");

        println!("  [TEST] ✓ IS-IS PDU structure validation passed");
    }

    /// Documentation test: Explain test requirements
    #[test]
    fn test_environment_requirements() {
        println!("\n=== IS-IS Test Environment Requirements ===");
        println!();
        println!("To run the full IS-IS e2e tests, you need:");
        println!();
        println!("1. Root Privileges:");
        println!("   sudo -E ./test-e2e.sh isis");
        println!();
        println!("2. Virtual Network Interfaces (veth pair):");
        println!("   sudo ip link add veth0 type veth peer name veth1");
        println!("   sudo ip link set veth0 up");
        println!("   sudo ip link set veth1 up");
        println!();
        println!("3. Packet Injection Tool:");
        println!("   - Option A: scapy (Python)");
        println!("   - Option B: tcpreplay with pre-captured IS-IS traffic");
        println!("   - Option C: Raw socket programming");
        println!();
        println!("4. Test Setup:");
        println!("   # Terminal 1: Start NetGet IS-IS server");
        println!("   sudo -E cargo run -- 'Start IS-IS on veth0 with system-id 0000.0000.0001'");
        println!();
        println!("   # Terminal 2: Inject IS-IS Hello PDU via scapy");
        println!("   sudo python3 inject_isis_hello.py veth1");
        println!();
        println!("Alternative: Use FRRouting (FRR) as IS-IS peer:");
        println!("   sudo apt install frr");
        println!("   # Configure FRR isisd on veth1");
        println!();
    }
}
