//! E2E tests for IGMP server
//!
//! These tests spawn the NetGet binary and test IGMP protocol operations
//! by manually constructing IGMP packets and verifying responses.
//!
//! **REQUIRES ROOT / CAP_NET_RAW.** The IGMP *server* opens a raw IP socket
//! (IPPROTO_IGMP), so `server_startup` refuses to spawn it on an unprivileged
//! process even though the test *client* below only needs a UDP socket. Every
//! test here is therefore `#[ignore]`d; run them under `sudo` to exercise them.
//!
//! Known issue for whoever un-ignores these: the client uses the blocking
//! `std::net::UdpSocket`, and `#[tokio::test]` runs each test on a
//! *current-thread* runtime. The mocked Ollama server is a task on that same
//! runtime, so a blocking `recv_from` parks the only worker, the mock cannot
//! answer NetGet's LLM request, and the read times out for a reason that has
//! nothing to do with IGMP. Port these to `tokio::net::UdpSocket` (as
//! `tests/server/sip/e2e_test.rs` now does) before expecting them to pass.

#[cfg(unix)]
mod e2e_igmp {
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;
    use tokio::time::sleep;

    /// Build an IGMPv2 Membership Query packet
    fn build_igmp_query(group_addr: Ipv4Addr, max_response_time: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Type: Membership Query (0x11)
        packet.push(0x11);

        // Max Response Time (in deciseconds)
        packet.push(max_response_time);

        // Checksum: placeholder (will calculate)
        packet.push(0x00);
        packet.push(0x00);

        // Group Address
        packet.extend_from_slice(&group_addr.octets());

        // Calculate and insert checksum
        let checksum = calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }

    /// Build an IGMPv2 Membership Report packet
    fn build_igmp_report(group_addr: Ipv4Addr) -> Vec<u8> {
        let mut packet = Vec::new();

        // Type: Membership Report (0x16)
        packet.push(0x16);

        // Max Response Time: 0 for reports
        packet.push(0x00);

        // Checksum: placeholder
        packet.push(0x00);
        packet.push(0x00);

        // Group Address
        packet.extend_from_slice(&group_addr.octets());

        // Calculate and insert checksum
        let checksum = calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }

    /// Calculate Internet Checksum (RFC 1071)
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        // Sum 16-bit words
        while i < data.len() - 1 {
            sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
            i += 2;
        }

        // Add remaining byte if odd length
        if i < data.len() {
            sum += u32::from(data[i]) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Return one's complement
        !sum as u16
    }

    /// Parse IGMP message type from response
    fn parse_igmp_type(data: &[u8]) -> Option<u8> {
        if data.len() >= 8 {
            Some(data[0])
        } else {
            None
        }
    }

    /// Test IGMP general membership query and response
    #[tokio::test]
    #[ignore = "Requires raw IP socket privileges (root or CAP_NET_RAW): without them server_startup refuses IGMP with \"Cannot start IGMP server: Raw IP socket access\", netget starts no server, and the harness fails with \"No servers or clients started\". Run under sudo to exercise. See the file header for a second issue (blocking UdpSocket starves the in-process mock) that must be fixed before these can pass."]
    async fn test_igmp_general_query_response() -> E2EResult<()> {
        println!("\n=== Test: IGMP General Query Response ===");

        let prompt = r#"Start IGMP server on port 0. Join multicast group 239.255.255.250.
When you receive a general membership query (group address 0.0.0.0), respond with a
membership report for 239.255.255.250."#;

        let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Start IGMP server")
                .and_instruction_containing("239.255.255.250")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IGMP",
                        "instruction": "Join group 239.255.255.250 and respond to queries"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: General query received (igmp_query_received event)
                .on_event("igmp_query_received")
                .and_event_data_contains("group_address", "0.0.0.0")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "join_group",
                        "group_address": "239.255.255.250"
                    },
                    {
                        "type": "send_membership_report",
                        "group_address": "239.255.255.250"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to initialize
        sleep(Duration::from_millis(500)).await;

        // Create UDP socket to send IGMP packets
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;

        let server_addr = format!("127.0.0.1:{}", server.port);
        println!("  [TEST] Sending general query to {}", server_addr);

        // Send general membership query (group = 0.0.0.0)
        let query = build_igmp_query(Ipv4Addr::new(0, 0, 0, 0), 100);
        socket.send_to(&query, &server_addr)?;

        // Wait for response
        let mut buffer = vec![0u8; 1024];
        match socket.recv_from(&mut buffer) {
            Ok((n, _)) => {
                println!("  [TEST] Received {} bytes", n);
                if let Some(msg_type) = parse_igmp_type(&buffer[..n]) {
                    // Should be Membership Report (0x16)
                    assert_eq!(msg_type, 0x16, "Should receive IGMPv2 Membership Report");
                    println!("  [TEST] ✓ Received Membership Report (type 0x16)");

                    // Check group address in response (bytes 4-7)
                    if n >= 8 {
                        let group = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
                        println!("  [TEST] ✓ Report for group: {}", group);
                        assert_eq!(
                            group,
                            Ipv4Addr::new(239, 255, 255, 250),
                            "Report should be for 239.255.255.250"
                        );
                    }
                } else {
                    panic!("Invalid IGMP response");
                }
            }
            Err(e) => {
                println!("  [TEST] ✗ No response received: {}", e);
                panic!("Expected IGMP response");
            }
        }

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    /// Test IGMP group-specific query
    #[tokio::test]
    #[ignore = "Requires raw IP socket privileges (root or CAP_NET_RAW): without them server_startup refuses IGMP with \"Cannot start IGMP server: Raw IP socket access\", netget starts no server, and the harness fails with \"No servers or clients started\". Run under sudo to exercise. See the file header for a second issue (blocking UdpSocket starves the in-process mock) that must be fixed before these can pass."]
    async fn test_igmp_group_specific_query() -> E2EResult<()> {
        println!("\n=== Test: IGMP Group-Specific Query ===");

        let prompt = r#"Start IGMP server on port 0. Join multicast groups 224.0.1.1 and 239.1.2.3.
When you receive a group-specific query for a group you're a member of, respond with
a membership report for that group. Ignore queries for groups you haven't joined."#;

        let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Start IGMP server")
                .and_instruction_containing("224.0.1.1")
                .and_instruction_containing("239.1.2.3")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IGMP",
                        "instruction": "Join groups 224.0.1.1 and 239.1.2.3"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Group-specific query for joined group (224.0.1.1)
                .on_event("igmp_query_received")
                .and_event_data_contains("group_address", "224.0.1.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_membership_report",
                        "group_address": "224.0.1.1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Group-specific query for non-joined group (225.0.0.1)
                .on_event("igmp_query_received")
                .and_event_data_contains("group_address", "225.0.0.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ignore_message"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to initialize
        sleep(Duration::from_millis(500)).await;

        // Create UDP socket
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;

        let server_addr = format!("127.0.0.1:{}", server.port);

        // Test 1: Query for joined group (224.0.1.1)
        println!("  [TEST] Sending group-specific query for 224.0.1.1");
        let query = build_igmp_query(Ipv4Addr::new(224, 0, 1, 1), 100);
        socket.send_to(&query, &server_addr)?;

        let mut buffer = vec![0u8; 1024];
        match socket.recv_from(&mut buffer) {
            Ok((n, _)) => {
                println!("  [TEST] Received {} bytes", n);
                if let Some(msg_type) = parse_igmp_type(&buffer[..n]) {
                    assert_eq!(msg_type, 0x16, "Should receive Membership Report");
                    println!("  [TEST] ✓ Received report for joined group");
                }
            }
            Err(e) => {
                println!("  [TEST] Warning: No response for joined group: {}", e);
            }
        }

        // Test 2: Query for non-joined group (225.0.0.1)
        println!("  [TEST] Sending group-specific query for non-joined group 225.0.0.1");
        let query = build_igmp_query(Ipv4Addr::new(225, 0, 0, 1), 100);
        socket.send_to(&query, &server_addr)?;

        // Should either timeout or receive no response
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        match socket.recv_from(&mut buffer) {
            Ok((_, _)) => {
                println!(
                    "  [TEST] Note: Received response for non-joined group (may be acceptable)"
                );
            }
            Err(_) => {
                println!("  [TEST] ✓ No response for non-joined group (correct)");
            }
        }

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    /// Test IGMP report suppression
    #[tokio::test]
    #[ignore = "Requires raw IP socket privileges (root or CAP_NET_RAW): without them server_startup refuses IGMP with \"Cannot start IGMP server: Raw IP socket access\", netget starts no server, and the harness fails with \"No servers or clients started\". Run under sudo to exercise. See the file header for a second issue (blocking UdpSocket starves the in-process mock) that must be fixed before these can pass."]
    async fn test_igmp_report_from_peer() -> E2EResult<()> {
        println!("\n=== Test: IGMP Report from Peer ===");

        let prompt = r#"Start IGMP server on port 0. Join multicast group 224.1.1.1.
When you receive a membership report from another host for a group you're in,
you can suppress your own report (this is optional per IGMP spec)."#;

        let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Start IGMP server")
                .and_instruction_containing("224.1.1.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IGMP",
                        "instruction": "Join group 224.1.1.1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Peer report received (igmp_report_received event)
                .on_event("igmp_report_received")
                .and_event_data_contains("group_address", "224.1.1.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ignore_message"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to initialize
        sleep(Duration::from_millis(500)).await;

        // Create UDP socket
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;

        let server_addr = format!("127.0.0.1:{}", server.port);

        // Send a membership report from "another host" for 224.1.1.1
        println!("  [TEST] Sending membership report from peer for 224.1.1.1");
        let report = build_igmp_report(Ipv4Addr::new(224, 1, 1, 1));
        socket.send_to(&report, &server_addr)?;

        // Wait a moment for server to process
        sleep(Duration::from_secs(1)).await;

        // Server should process it (no crash, accepts the packet)
        println!("  [TEST] ✓ Server accepted peer report");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    /// Test comprehensive IGMP scenario with multiple groups
    #[tokio::test]
    #[ignore = "Requires raw IP socket privileges (root or CAP_NET_RAW): without them server_startup refuses IGMP with \"Cannot start IGMP server: Raw IP socket access\", netget starts no server, and the harness fails with \"No servers or clients started\". Run under sudo to exercise. See the file header for a second issue (blocking UdpSocket starves the in-process mock) that must be fixed before these can pass."]
    async fn test_igmp_multiple_groups() -> E2EResult<()> {
        println!("\n=== Test: IGMP Multiple Groups ===");

        let prompt = r#"Start IGMP server on port 0. This is a comprehensive test:
1. Initially join multicast groups: 224.0.0.251 (mDNS) and 239.255.255.250 (SSDP)
2. When you receive a general query, respond with reports for all joined groups
3. Track which groups you've joined and respond appropriately to group-specific queries"#;

        let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Start IGMP server")
                .and_instruction_containing("224.0.0.251")
                .and_instruction_containing("239.255.255.250")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IGMP",
                        "instruction": "Join mDNS and SSDP multicast groups"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: General query received
                .on_event("igmp_query_received")
                .and_event_data_contains("group_address", "0.0.0.0")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_membership_report",
                        "group_address": "224.0.0.251"
                    },
                    {
                        "type": "send_membership_report",
                        "group_address": "239.255.255.250"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to initialize and join groups
        sleep(Duration::from_millis(500)).await;

        // Create UDP socket
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;

        let server_addr = format!("127.0.0.1:{}", server.port);

        // Send general query
        println!("  [TEST] Sending general membership query");
        let query = build_igmp_query(Ipv4Addr::new(0, 0, 0, 0), 100);
        socket.send_to(&query, &server_addr)?;

        // Expect at least one report (server may send multiple or combined)
        let mut buffer = vec![0u8; 1024];
        let mut reports_received = 0;

        // Try to receive up to 2 reports (with timeout)
        for attempt in 1..=3 {
            socket.set_read_timeout(Some(Duration::from_secs(if attempt == 1 { 5 } else { 2 })))?;
            match socket.recv_from(&mut buffer) {
                Ok((n, _)) => {
                    if let Some(msg_type) = parse_igmp_type(&buffer[..n]) {
                        if msg_type == 0x16 {
                            reports_received += 1;
                            if n >= 8 {
                                let group =
                                    Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
                                println!(
                                    "  [TEST] ✓ Received report #{} for group {}",
                                    reports_received, group
                                );
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        assert!(
            reports_received >= 1,
            "Should receive at least 1 membership report"
        );
        println!("  [TEST] ✓ Received {} report(s) total", reports_received);

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }
}
