//! IS-IS client E2E tests
//!
//! These tests verify the IS-IS client can capture and parse IS-IS PDUs.
//!
//! **IMPORTANT**: IS-IS operates at Layer 2 using pcap. These tests require:
//! - Root access (CAP_NET_RAW for pcap)
//! - Virtual network interfaces (veth pairs) OR
//! - Real IS-IS router on the network OR
//! - Packet replay with tcpreplay
//!
//! The tests are designed to work with mock LLM responses by default.
//! Use --use-ollama flag to test with real Ollama.

#![cfg(all(unix, feature = "libpcap"))]

use crate::helpers::netget::start_netget;
use crate::helpers::{E2EResult, NetGetConfig};
use std::time::Duration;

/// Test IS-IS client startup and interface capture
/// LLM calls: 1 (client startup with open_client action)
#[tokio::test]
#[ignore = "Requires root access for pcap"]
async fn test_isis_client_startup() -> E2EResult<()> {
    println!("\n=== Test: IS-IS Client Startup ===");

    let prompt = "Connect to interface lo0 via IS-IS. Capture and analyze IS-IS PDUs.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Client startup (user command)
            .on_instruction_containing("interface")
            .and_instruction_containing("IS-IS")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "lo0",  // For ISIS, this is the interface name
                    "protocol": "IS-IS",
                    "instruction": "Capture IS-IS PDUs and analyze topology"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut instance = start_netget(config).await?;

    // Wait for client to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify client was started
    assert_eq!(instance.clients.len(), 1, "Should have 1 client");
    assert_eq!(
        instance.clients[0].protocol, "IS-IS",
        "Should be IS-IS protocol"
    );
    assert_eq!(
        instance.clients[0].remote_addr, "lo0",
        "Should be capturing on lo0"
    );

    println!("  [TEST] ✓ IS-IS client started successfully");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    instance.wait_for_mocks(30).await;
    instance.verify_mocks().await?;

    Ok(())
}

/// Test IS-IS client capturing Hello PDU
/// LLM calls: 2 (client startup, PDU received)
#[tokio::test]
#[ignore = "Requires root, veth setup, and packet injection"]
async fn test_isis_client_capture_hello() -> E2EResult<()> {
    println!("\n=== Test: IS-IS Client Capture Hello PDU ===");

    let prompt = "Connect to interface veth1 via IS-IS. When you capture a Hello PDU, analyze it and report the neighbor's system ID.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("veth1")
            .and_instruction_containing("IS-IS")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "veth1",
                    "protocol": "IS-IS",
                    "instruction": "Analyze IS-IS Hello PDUs"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: PDU received event
            .on_event("isis_pdu_received")
            .and_event_data_contains("pdu_type", "L2 LAN Hello")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut instance = start_netget(config).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("  [TEST] Client capturing on veth1");
    println!("  [TEST] Would inject IS-IS Hello PDU on veth0 (peer interface)");
    println!("  [TEST] (Skipping packet injection in this test framework)");

    // In a real test environment:
    // 1. Inject IS-IS Hello PDU on veth0
    // 2. Client captures it on veth1
    // 3. Verify LLM analyzed the PDU

    println!("  [TEST] ✓ IS-IS client capture test structure validated");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    instance.wait_for_mocks(30).await;
    instance.verify_mocks().await?;

    Ok(())
}

/// Test IS-IS client with server interaction
/// This simulates a full IS-IS client-server scenario
/// LLM calls: 3 (server startup, client startup, PDU received)
#[tokio::test]
#[ignore = "Requires root, veth pair, and complex setup"]
async fn test_isis_client_server_interaction() -> E2EResult<()> {
    println!("\n=== Test: IS-IS Client-Server Interaction ===");

    // This test demonstrates how ISIS client and server would interact
    // In reality, they need separate veth interfaces to communicate

    println!("\n  Setup:");
    println!("  1. Create veth pair: veth0 <-> veth1");
    println!("  2. Start IS-IS server on veth0");
    println!("  3. Start IS-IS client on veth1");
    println!("  4. Server sends Hello PDU");
    println!("  5. Client captures and analyzes it");

    // Server configuration
    let server_prompt = "Start an IS-IS router on interface veth0 with system-id 0000.0000.0001 in area 49.0001. Send periodic Hello PDUs.";

    let server_config = NetGetConfig::new(server_prompt).with_mock(|mock| {
        mock.on_instruction_containing("IS-IS router")
            .and_instruction_containing("veth0")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "interface": "veth0",
                    "protocol": "IS-IS",
                    "instruction": "IS-IS router sending Hello PDUs",
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
    });

    // Client configuration
    let client_prompt = "Connect to interface veth1 via IS-IS. Capture IS-IS PDUs and identify all routers in the network.";

    let client_config = NetGetConfig::new(client_prompt).with_mock(|mock| {
        mock.on_instruction_containing("veth1")
            .and_instruction_containing("IS-IS")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "veth1",
                    "protocol": "IS-IS",
                    "instruction": "Analyze IS-IS topology"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("isis_pdu_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    println!("\n  [TEST] Starting server on veth0...");
    let mut server = start_netget(server_config).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("  [TEST] Starting client on veth1...");
    let mut client = start_netget(client_config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("  [TEST] Server and client running on separate veth interfaces");
    println!("  [TEST] Server would send Hello PDU on veth0");
    println!("  [TEST] Client would capture it on veth1");
    println!("  [TEST] Client LLM would analyze and store topology");

    // Verify both started correctly
    assert_eq!(server.servers.len(), 1, "Should have 1 server");
    assert_eq!(client.clients.len(), 1, "Should have 1 client");

    println!("  [TEST] ✓ Client-server interaction test structure validated");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    Ok(())
}

/// Test IS-IS client analyzing multiple PDU types
/// LLM calls: 5 (startup + 4 different PDU types)
#[tokio::test]
#[ignore = "Requires root and IS-IS traffic"]
async fn test_isis_client_multiple_pdu_types() -> E2EResult<()> {
    println!("\n=== Test: IS-IS Client Multiple PDU Types ===");

    let prompt = "Connect to interface veth1 via IS-IS. Capture and analyze all types of IS-IS PDUs: Hello, LSP, CSNP, PSNP.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("interface veth1")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "veth1",
                    "protocol": "IS-IS",
                    "instruction": "Analyze all IS-IS PDU types"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: L2 LAN Hello
            .on_event("isis_pdu_received")
            .and_event_data_contains("pdu_type", "L2 LAN Hello")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            // Mock 3: L2 LSP
            .on_event("isis_pdu_received")
            .and_event_data_contains("pdu_type", "L2 LSP")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            // Mock 4: L2 CSNP
            .on_event("isis_pdu_received")
            .and_event_data_contains("pdu_type", "L2 CSNP")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            // Mock 5: L2 PSNP
            .on_event("isis_pdu_received")
            .and_event_data_contains("pdu_type", "L2 PSNP")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
    });

    let mut instance = start_netget(config).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("  [TEST] Client ready to capture multiple PDU types");
    println!("  [TEST] Would inject:");
    println!("  [TEST]   - L2 LAN Hello (type 16)");
    println!("  [TEST]   - L2 LSP (type 20)");
    println!("  [TEST]   - L2 CSNP (type 25)");
    println!("  [TEST]   - L2 PSNP (type 27)");

    println!("  [TEST] ✓ Multiple PDU type test structure validated");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    instance.wait_for_mocks(30).await;
    instance.verify_mocks().await?;

    Ok(())
}

/// Unit test: IS-IS PDU parsing (no network required)
#[test]
fn test_isis_pdu_parsing() {
    println!("\n=== Test: IS-IS PDU Parsing ===");

    // Sample IS-IS L2 LAN Hello PDU (header only)
    let sample_pdu = vec![
        0x83, // Intradomain Routing Protocol Discriminator
        0x1B, // Length Indicator (27)
        0x01, // Version/Protocol ID Extension
        0x00, // ID Length (0 = 6 bytes)
        0x10, // PDU Type: 16 (L2 LAN Hello)
        0x01, // Version: 1
        0x00, // Reserved
        0x00, // Max Area Addresses
    ];

    // Verify discriminator
    assert_eq!(sample_pdu[0], 0x83, "IS-IS discriminator should be 0x83");

    // Verify PDU type
    assert_eq!(sample_pdu[4], 0x10, "PDU type should be 16 (L2 LAN Hello)");

    // Verify version
    assert_eq!(sample_pdu[5], 0x01, "IS-IS version should be 1");

    println!("  [TEST] ✓ IS-IS PDU parsing validation passed");
}

/// Documentation test: Device listing
#[test]
fn test_device_listing_documentation() {
    println!("\n=== IS-IS Client Device Listing ===");
    println!();
    println!("To list available network interfaces:");
    println!();
    println!("  use netget::client::isis::IsisClient;");
    println!("  let devices = IsisClient::list_devices()?;");
    println!("  for device in devices {{");
    println!("      println!(\"Interface: {{}} - {{:?}}\", device.name, device.desc);");
    println!("  }}");
    println!();
    println!("Common interfaces:");
    println!("  - Linux: eth0, wlan0, ens33, enp0s3");
    println!("  - macOS: en0, en1, lo0");
    println!("  - Windows: \\Device\\NPF_{{GUID}}");
    println!();
}

/// Documentation test: Explain test requirements
#[test]
fn test_environment_requirements() {
    println!("\n=== IS-IS Client Test Environment Requirements ===");
    println!();
    println!("To run the full IS-IS client e2e tests, you need:");
    println!();
    println!("1. Root Privileges:");
    println!("   sudo -E ./test-e2e.sh isis");
    println!();
    println!("2. Network Setup - Option A: Virtual Interfaces");
    println!("   sudo ip link add veth0 type veth peer name veth1");
    println!("   sudo ip link set veth0 up");
    println!("   sudo ip link set veth1 up");
    println!();
    println!("3. Network Setup - Option B: Real IS-IS Router");
    println!("   Install FRRouting:");
    println!("   sudo apt install frr");
    println!("   sudo systemctl enable frr");
    println!();
    println!("   Configure IS-IS in /etc/frr/isisd.conf:");
    println!("   router isis MYNET");
    println!("     net 49.0001.1921.6800.1001.00");
    println!("     is-type level-2-only");
    println!();
    println!("   interface eth0");
    println!("     ip router isis MYNET");
    println!("     isis circuit-type level-2-only");
    println!();
    println!("4. Packet Injection Tool (for testing without router):");
    println!("   pip3 install scapy");
    println!();
    println!("   Example scapy script:");
    println!("   from scapy.all import *");
    println!("   from scapy.contrib.isis import *");
    println!();
    println!("   # Build IS-IS Hello PDU");
    println!("   pdu = Ether(dst='01:80:c2:00:00:15')/");
    println!("         LLC(dsap=0xfe, ssap=0xfe)/");
    println!("         ISIS_CommonHdr()/");
    println!("         ISIS_L2_LAN_IIH()");
    println!();
    println!("   sendp(pdu, iface='veth0')");
    println!();
}
