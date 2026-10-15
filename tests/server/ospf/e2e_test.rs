//! OSPF E2E tests
//!
//! Tests OSPF server with manual OSPF client

#[cfg(unix)]
mod tests {
    use crate::helpers::*;
    use tokio::net::UdpSocket;

    // Helper: Parse IPv4 address to bytes
    fn ipv4_to_bytes(ip: &str) -> [u8; 4] {
        let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();

        if parts.len() == 4 {
            [parts[0], parts[1], parts[2], parts[3]]
        } else {
            [0, 0, 0, 0]
        }
    }

    // Helper: Build OSPF Hello packet
    fn build_ospf_hello(
        router_id: &str,
        area_id: &str,
        network_mask: &str,
        priority: u8,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // OSPF Header (24 bytes)
        packet.push(2); // Version = 2 (OSPFv2)
        packet.push(1); // Type = 1 (Hello)
        packet.extend_from_slice(&[0, 0]); // Packet Length (placeholder)

        // Router ID
        let router_id_bytes = ipv4_to_bytes(router_id);
        packet.extend_from_slice(&router_id_bytes);

        // Area ID
        let area_id_bytes = ipv4_to_bytes(area_id);
        packet.extend_from_slice(&area_id_bytes);

        packet.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        packet.extend_from_slice(&[0, 0]); // AuType = 0 (no authentication)
        packet.extend_from_slice(&[0; 8]); // Authentication (8 bytes, zeros)

        // Hello packet body
        let network_mask_bytes = ipv4_to_bytes(network_mask);
        packet.extend_from_slice(&network_mask_bytes);

        packet.extend_from_slice(&10u16.to_be_bytes()); // Hello interval = 10 seconds
        packet.push(0); // Options = 0
        packet.push(priority); // Router priority
        packet.extend_from_slice(&40u32.to_be_bytes()); // Router dead interval = 40 seconds

        // Designated Router (0.0.0.0 = none)
        packet.extend_from_slice(&[0, 0, 0, 0]);

        // Backup Designated Router (0.0.0.0 = none)
        packet.extend_from_slice(&[0, 0, 0, 0]);

        // Neighbor list (empty for now)

        // Update packet length
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());

        // Calculate checksum (simplified - Fletcher checksum)
        let checksum = calculate_ospf_checksum(&packet);
        packet[12..14].copy_from_slice(&checksum.to_be_bytes());

        packet
    }

    // Helper: OSPF packet checksum.
    //
    // This was a hand-rolled *Fletcher* checksum, which is the algorithm OSPF uses for LSA
    // headers and NOT for packet headers - RFC 2328 A.3.1 specifies the standard IP
    // one's-complement sum. It is the exact bug `OspfProtocol::calculate_checksum` documents
    // as having made every packet NetGet emitted fail a real router's validity check. Keeping
    // a second, wrong implementation next to the fixed one is how that comes back, so this
    // now delegates. (It also underflowed on any input shorter than 14 bytes.)
    fn calculate_ospf_checksum(data: &[u8]) -> u16 {
        OspfProtocol::calculate_checksum(data)
    }

    // ========================================================================
    // The three tests below do NOT test OSPF. Read this before trusting them.
    //
    // They pass `"base_stack": "UDP"`, which `open_server` renames to `protocol` - so what
    // starts is the **generic UDP server** in src/server/udp/, not src/server/ospf/. The
    // `"application_protocol": "OSPF"` alongside it is read by nothing anywhere in src/.
    // The mocked event is `udp_datagram_received` and the mocked action is
    // `send_udp_response`, both of which belong to the UDP server; this protocol raises
    // `ospf_hello` / `ospf_database_description` / `ospf_link_state_{request,update,ack}`
    // and executes `send_hello` and friends, and no test in the tree mocks any of those.
    //
    // So the exchange is: the test builds OSPF-shaped bytes, the mock hands OSPF-shaped
    // bytes back, and a UDP server relays them. Nothing in src/server/ospf/ is entered, and
    // `assert_eq!(buf[1], 1)` is asserting a constant the test itself wrote two functions
    // earlier. Nor could they drive OSPF: `spawn_with_llm_actions` opens a raw IP-89 socket
    // before anything else, which needs CAP_NET_RAW.
    //
    // They are kept because they are real coverage of the *UDP* server carrying an
    // arbitrary binary payload, and deleting them would remove that. What they must not be
    // is cited as evidence about OSPF - `metadata().e2e_testing` says so too. The genuine
    // OSPF coverage in this file is the unit tests below, which call OspfProtocol directly.
    // ========================================================================

    #[tokio::test]
    async fn test_ospf_hello_exchange() -> E2EResult<()> {
        println!("\n=== UDP-transport test (NOT an OSPF test - see the note above) ===");

        // PROMPT: Tell the LLM to act as an OSPF router
        let prompt = "Listen on port {AVAILABLE_PORT} via UDP. Act as OSPF router with router_id 1.1.1.1 in area 0.0.0.0. \
                     When receiving OSPF Hello packets, respond with Hello packets including the sender's router_id in the neighbor list.";

        // Start the server with mocks
        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("OSPF")
                .and_instruction_containing("router")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "UDP",
                        "application_protocol": "OSPF",
                        "instruction": "Act as OSPF router 1.1.1.1 in area 0.0.0.0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Receive OSPF Hello packet
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_udp_response",
                        "data": hex::encode(build_ospf_hello_response())
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        println!("OSPF server started on port {}", server.port);

        // Create UDP client
        let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = format!("127.0.0.1:{}", server.port);
        client_socket.connect(&server_addr).await?;
        println!("✓ UDP client connected");

        // Build and send OSPF Hello packet
        let hello_packet = build_ospf_hello(
            "2.2.2.2",       // our router_id
            "0.0.0.0",       // area_id (backbone)
            "255.255.255.0", // network_mask
            1,               // priority
        );

        println!(
            "Sending OSPF Hello packet ({} bytes)...",
            hello_packet.len()
        );
        client_socket.send(&hello_packet).await?;

        // Receive Hello response
        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_socket.recv(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => {
                println!("✓ Received OSPF response ({} bytes)", n);

                // Basic validation of OSPF header
                assert!(n >= 24, "OSPF packet must be at least 24 bytes (header)");
                assert_eq!(buf[0], 2, "OSPF version should be 2");
                assert_eq!(buf[1], 1, "OSPF type should be 1 (Hello)");

                println!("✓ OSPF Hello response validated");
            }
            Ok(Err(e)) => {
                panic!("Failed to receive OSPF response: {}", e);
            }
            Err(_) => {
                panic!("Timeout waiting for OSPF response");
            }
        }

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_ospf_neighbor_discovery() -> E2EResult<()> {
        println!("\n=== E2E Test: OSPF Neighbor Discovery ===");

        let prompt = "Listen on port {AVAILABLE_PORT} via UDP. Act as OSPF router 1.1.1.1 in area 0.0.0.0. \
                     Track neighbors from received Hello packets. When receiving Hello, respond with Hello including all known neighbors.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("OSPF")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "UDP",
                        "application_protocol": "OSPF",
                        "instruction": "Track and respond to OSPF neighbors"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-3: Multiple Hello exchanges
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_udp_response",
                        "data": hex::encode(build_ospf_hello_response())
                    }
                ]))
                .expect_calls(2)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        println!("OSPF server started on port {}", server.port);

        let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
        client_socket
            .connect(format!("127.0.0.1:{}", server.port))
            .await?;

        // Send first Hello packet
        println!("Sending first OSPF Hello...");
        let hello1 = build_ospf_hello("3.3.3.3", "0.0.0.0", "255.255.255.0", 1);
        client_socket.send(&hello1).await?;

        // Receive first response
        let mut buf = vec![0u8; 1024];
        let n1 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_socket.recv(&mut buf),
        )
        .await??;
        println!("✓ Received first Hello response ({} bytes)", n1);

        // Send second Hello packet
        println!("Sending second OSPF Hello...");
        let hello2 = build_ospf_hello("3.3.3.3", "0.0.0.0", "255.255.255.0", 1);
        client_socket.send(&hello2).await?;

        // Receive second response
        let n2 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_socket.recv(&mut buf),
        )
        .await??;
        println!("✓ Received second Hello response ({} bytes)", n2);
        println!("✓ OSPF neighbor discovery test passed");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_ospf_multiple_routers() -> E2EResult<()> {
        println!("\n=== E2E Test: OSPF Multiple Routers ===");

        let prompt = "Listen on port {AVAILABLE_PORT} via UDP. Act as OSPF router 1.1.1.1 in area 0.0.0.0. \
                     Accept Hello packets from multiple routers and maintain neighbor relationships.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("OSPF")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "UDP",
                        "application_protocol": "OSPF",
                        "instruction": "Handle multiple OSPF neighbors"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-4: Multiple Hello packets from different routers
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_udp_response",
                        "data": hex::encode(build_ospf_hello_response())
                    }
                ]))
                .expect_calls(3)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        println!("OSPF server started on port {}", server.port);

        // Create three "routers" (UDP clients with different router IDs)
        let routers = vec![
            ("4.4.4.4", "Router 4"),
            ("5.5.5.5", "Router 5"),
            ("6.6.6.6", "Router 6"),
        ];

        for (router_id, name) in &routers {
            let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
            client_socket
                .connect(format!("127.0.0.1:{}", server.port))
                .await?;

            println!("Sending Hello from {} ({})", name, router_id);
            let hello = build_ospf_hello(router_id, "0.0.0.0", "255.255.255.0", 1);
            client_socket.send(&hello).await?;

            // Receive response
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client_socket.recv(&mut buf),
            )
            .await??;
            println!("✓ {} received response ({} bytes)", name, n);
        }

        println!("✓ All routers successfully exchanged Hello packets");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }

    // Helper function to build a simple OSPF Hello response
    fn build_ospf_hello_response() -> Vec<u8> {
        build_ospf_hello(
            "1.1.1.1",       // server router_id
            "0.0.0.0",       // area_id
            "255.255.255.0", // network_mask
            128,             // priority (DR eligible)
        )
    }

    #[test]
    fn test_ospf_hello_packet_construction() {
        // Test Hello packet construction
        let hello = build_ospf_hello(
            "2.2.2.2",       // router_id
            "0.0.0.0",       // area_id (backbone)
            "255.255.255.0", // network_mask
            1,               // priority
        );

        // Verify packet structure
        assert_eq!(hello[0], 2); // Version = 2
        assert_eq!(hello[1], 1); // Type = Hello

        // Verify packet length
        let packet_len = u16::from_be_bytes([hello[2], hello[3]]);
        assert_eq!(packet_len as usize, hello.len());

        // Verify router ID
        assert_eq!(&hello[4..8], &[2, 2, 2, 2]);

        // Verify area ID (backbone)
        assert_eq!(&hello[8..12], &[0, 0, 0, 0]);

        // Verify Hello interval
        let hello_interval = u16::from_be_bytes([hello[28], hello[29]]);
        assert_eq!(hello_interval, 10);

        // Verify priority
        assert_eq!(hello[31], 1);

        // Verify router dead interval
        let dead_interval = u32::from_be_bytes([hello[32], hello[33], hello[34], hello[35]]);
        assert_eq!(dead_interval, 40);

        println!("✓ OSPF Hello packet constructed correctly");
        println!("  Router ID: 2.2.2.2");
        println!("  Area: 0.0.0.0 (backbone)");
        println!("  Packet length: {} bytes", hello.len());
    }

    // ========================================================================
    // Startup parameters -> wire
    //
    // hello_interval, network_mask, router_dead_interval and router_priority
    // were declared in get_startup_parameters() and read nowhere: spawn only
    // ever looked at router_id and area_id. They now populate an
    // OspfInterfaceConfig that supplies the defaults for every outgoing packet
    // and the RFC 2328 10.5 acceptance check for every incoming Hello. These
    // tests assert both halves at byte level, against the RFC 2328 A.3.2 field
    // offsets, because the raw-socket path itself needs root and cannot be
    // exercised here.
    // ========================================================================

    use ::netget::server::ospf::actions::{OspfInterfaceConfig, OspfProtocol};

    fn configured() -> OspfInterfaceConfig {
        OspfInterfaceConfig {
            router_id: "9.9.9.9".to_string(),
            area_id: "0.0.0.7".to_string(),
            network_mask: "255.255.0.0".to_string(),
            hello_interval: 5,
            router_dead_interval: 20,
            router_priority: 200,
        }
    }

    /// RFC 2328 A.3.2: the Hello body starts at byte 24 of the OSPF packet.
    ///   24..28 network mask, 28..30 HelloInterval, 30 Options, 31 Rtr Pri,
    ///   32..36 RouterDeadInterval, 36..40 DR, 40..44 BDR.
    #[test]
    fn ospf_startup_config_reaches_the_hello_packet() {
        let mut action = serde_json::json!({"type": "send_hello"});
        configured().apply_defaults(&mut action);

        let hello = OspfProtocol::build_hello_packet(&action).expect("build hello");

        assert_eq!(
            &hello[4..8],
            &[9, 9, 9, 9],
            "configured router_id must be the packet's Router ID"
        );
        assert_eq!(
            &hello[8..12],
            &[0, 0, 0, 7],
            "configured area_id must be the packet's Area ID"
        );
        assert_eq!(
            &hello[24..28],
            &[255, 255, 0, 0],
            "configured network_mask must be in the Hello body"
        );
        assert_eq!(
            u16::from_be_bytes([hello[28], hello[29]]),
            5,
            "configured hello_interval must be in the Hello body, not the hardcoded 10"
        );
        assert_eq!(
            hello[31], 200,
            "configured router_priority must be in the Hello body, not the hardcoded 1"
        );
        assert_eq!(
            u32::from_be_bytes([hello[32], hello[33], hello[34], hello[35]]),
            20,
            "configured router_dead_interval must be in the Hello body, not the hardcoded 40"
        );
    }

    /// The model still wins: an action that names a field keeps its own value, so a
    /// honeypot prompt can deliberately advertise timers that differ from the interface.
    #[test]
    fn ospf_action_values_override_startup_config() {
        let mut action = serde_json::json!({
            "type": "send_hello",
            "router_id": "1.2.3.4",
            "hello_interval": 30,
            "priority": 255
        });
        configured().apply_defaults(&mut action);

        let hello = OspfProtocol::build_hello_packet(&action).expect("build hello");

        assert_eq!(&hello[4..8], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([hello[28], hello[29]]), 30);
        assert_eq!(hello[31], 255);
        // Untouched fields still come from the configuration.
        assert_eq!(
            u32::from_be_bytes([hello[32], hello[33], hello[34], hello[35]]),
            20
        );
        assert_eq!(&hello[24..28], &[255, 255, 0, 0]);
    }

    /// Non-Hello packets take router_id and area_id but must not grow Hello body fields.
    #[test]
    fn ospf_config_defaults_apply_to_non_hello_packets() {
        let mut action = serde_json::json!({"type": "send_database_description"});
        configured().apply_defaults(&mut action);

        assert_eq!(action["router_id"], "9.9.9.9");
        assert_eq!(action["area_id"], "0.0.0.7");
        assert!(
            action.get("hello_interval").is_none(),
            "Hello body fields have no meaning in a DD packet"
        );
        assert!(action.get("priority").is_none());
    }

    /// RFC 2328 10.5: a Hello whose HelloInterval, RouterDeadInterval or network mask
    /// differs from the receiving interface's is not acceptable and cannot form an
    /// adjacency. Exactly those three fields, and nothing else, are checked.
    #[test]
    fn ospf_hello_mismatch_check_follows_rfc_2328_10_5() {
        let config = configured();

        assert!(
            config.hello_mismatches(5, 20, "255.255.0.0").is_empty(),
            "a matching Hello must be accepted"
        );

        let m = config.hello_mismatches(10, 20, "255.255.0.0");
        assert_eq!(m.len(), 1, "only hello_interval differs: {m:?}");
        assert!(m[0].contains("hello_interval"));

        let m = config.hello_mismatches(5, 40, "255.255.0.0");
        assert_eq!(m.len(), 1, "only router_dead_interval differs: {m:?}");
        assert!(m[0].contains("router_dead_interval"));

        let m = config.hello_mismatches(5, 20, "255.255.255.0");
        assert_eq!(m.len(), 1, "only network_mask differs: {m:?}");
        assert!(m[0].contains("network_mask"));

        assert_eq!(
            config.hello_mismatches(10, 40, "255.255.255.0").len(),
            3,
            "all three fields differing must all be reported"
        );
    }

    /// The defaults are RFC 2328 Appendix C.3's, so a server started with no parameters
    /// behaves exactly as it did before the configuration existed.
    #[test]
    fn ospf_default_config_matches_rfc_defaults() {
        let d = OspfInterfaceConfig::default();
        assert_eq!(d.hello_interval, 10);
        assert_eq!(d.router_dead_interval, 40);
        assert_eq!(d.router_priority, 1);
        assert_eq!(d.network_mask, "255.255.255.0");

        let mut action = serde_json::json!({"type": "send_hello"});
        d.apply_defaults(&mut action);
        let hello = OspfProtocol::build_hello_packet(&action).expect("build hello");
        assert_eq!(u16::from_be_bytes([hello[28], hello[29]]), 10);
        assert_eq!(
            u32::from_be_bytes([hello[32], hello[33], hello[34], hello[35]]),
            40
        );
        assert_eq!(hello[31], 1);
    }

    /// Every declared startup parameter must be one the implementation reads. A parameter
    /// declared and never read is dead weight the model will try to use.
    #[test]
    fn ospf_declares_exactly_the_parameters_it_reads() {
        use ::netget::llm::actions::protocol_trait::Protocol;

        let mut declared: Vec<String> = OspfProtocol::new()
            .get_startup_parameters()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        declared.sort();

        let mut expected = vec![
            "area_id",
            "hello_interval",
            "network_mask",
            "router_dead_interval",
            "router_id",
            "router_priority",
        ];
        expected.sort_unstable();

        assert_eq!(
            declared, expected,
            "every one of these is read into OspfInterfaceConfig by \
             OspfServer::spawn_with_llm_actions; adding a declaration without a read \
             re-creates the defect this test exists for"
        );
    }

    /// OSPF's LLM-failure contract is *deliberate silence*, and that has to be pinned or it
    /// reads as the "protocol goes quiet on LLM error" defect it is not.
    ///
    /// OSPF defines no error or NAK packet: Hello, DD, LSR, LSU and LSAck are all positive
    /// routing assertions. Emitting any of them to signal "netget is broken" would claim an
    /// adjacency, a DR role or database contents netget cannot back — worse for the peer than
    /// saying nothing, which its own RouterDeadInterval already handles. So the failure goes
    /// to the operator only, and the three cases stay apart by `decision=` tag.
    #[test]
    fn ospf_llm_failure_is_silent_on_the_wire_and_tagged_in_the_log() {
        use ::netget::llm::actions::protocol_trait::Protocol;

        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/server/ospf/mod.rs"
        ))
        .expect("src/server/ospf/mod.rs must be readable");

        let err_branch = src
            .split("Err(e) => {\n                // The LLM call failed.")
            .nth(1)
            .expect("dispatch_event must keep its documented LLM-failure branch");
        // Only the log call may follow; the moment a send appears here the contract changed.
        let err_branch = &err_branch[..err_branch.find("\n        }").unwrap_or(err_branch.len())];
        assert!(
            !err_branch.contains("send_ospf_packet"),
            "the LLM-failure branch must put nothing on the wire — OSPF has no failure packet"
        );
        assert!(
            err_branch.contains("decision={}"),
            "the LLM-failure branch must carry a decision= tag in its log line"
        );
        for tag in ["\"fail_closed_overloaded\"", "\"fail_closed_unavailable\""] {
            assert!(
                err_branch.contains(tag),
                "the LLM-failure branch must distinguish {tag} so an operator can tell an \
                 overloaded backend from a broken one"
            );
        }
        for tag in ["\"model_wait\"", "\"model_no_action\""] {
            assert!(
                src.contains(tag),
                "the model choosing silence and the model returning nothing usable must stay \
                 distinguishable in the log ({tag})"
            );
        }

        let notes = OspfProtocol::new().metadata().notes.unwrap_or_default();
        assert!(
            notes.contains("no error or NAK packet"),
            "metadata().notes must state that the silence is deliberate, not an oversight"
        );
    }

    // ========================================================================
    // Checksum
    //
    // The only checksum test here used to be of `calculate_ospf_checksum` above -
    // this file's own Fletcher helper, which is the algorithm `OspfProtocol` records
    // as the bug it was fixed for ("every packet NetGet emitted failed the receiver's
    // validity check", so FRR/BIRD dropped all of them). It asserted `!= 0`, which any
    // garbage satisfies, and it never touched production code. These do.
    // ========================================================================

    /// RFC 2328 A.3.1 defines the check a receiver performs: recompute the one's-complement
    /// sum over the packet with the checksum field left in place, and the result must be
    /// zero. That property is the whole contract, so assert it directly rather than pinning
    /// a magic constant.
    #[test]
    fn ospf_packet_checksum_validates_the_way_a_receiver_checks_it() {
        let mut action = serde_json::json!({"type": "send_hello"});
        configured().apply_defaults(&mut action);
        let hello = OspfProtocol::build_hello_packet(&action).expect("build hello");

        assert_ne!(
            u16::from_be_bytes([hello[12], hello[13]]),
            0,
            "a built packet must carry a real checksum"
        );
        assert_eq!(
            OspfProtocol::calculate_checksum(&hello),
            0,
            "recomputing the checksum over a valid packet must yield 0 - this is exactly \
             the validity check FRR/BIRD run before parsing"
        );
    }

    /// A packet whose body was altered in flight must fail that same check.
    #[test]
    fn ospf_packet_checksum_catches_a_corrupted_packet() {
        let mut action = serde_json::json!({"type": "send_hello"});
        configured().apply_defaults(&mut action);
        let mut hello = OspfProtocol::build_hello_packet(&action).expect("build hello");

        hello[31] ^= 0xff; // Router Priority, in the Hello body
        assert_ne!(
            OspfProtocol::calculate_checksum(&hello),
            0,
            "a corrupted packet must not validate"
        );
    }

    /// The 64-bit authentication field (header bytes 16..24) is excluded from the sum, so a
    /// router that fills it in does not invalidate its own packet. Easy to get wrong, and
    /// nothing else here would catch it.
    #[test]
    fn ospf_packet_checksum_excludes_the_authentication_field() {
        let mut action = serde_json::json!({"type": "send_hello"});
        configured().apply_defaults(&mut action);
        let mut hello = OspfProtocol::build_hello_packet(&action).expect("build hello");

        hello[16..24].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            OspfProtocol::calculate_checksum(&hello),
            0,
            "bytes 16..24 must not contribute to the packet checksum (RFC 2328 A.3.1)"
        );
    }

    // ========================================================================
    // LSA headers and request triples on the wire
    //
    // send_link_state_ack and send_link_state_request used to emit a bare 24-byte header
    // with an empty body. An LSAck is matched against the neighbour's retransmission list
    // header by header (RFC 2328 13.7), so a body-less one acknowledges nothing and the
    // neighbour retransmits forever - it is not a harmless no-op.
    // ========================================================================

    /// Exactly what `parse_lsa_headers` emits for one header, `lsa_type_name` included, so
    /// the round-trip assertion below can be a plain equality. `push_lsa_header` ignores
    /// `lsa_type_name` on the way out — it is derived from `lsa_type`, not a wire field.
    fn sample_lsa_header() -> serde_json::Value {
        serde_json::json!({
            "age": 1,
            "options": 2,
            "lsa_type": 1,
            "lsa_type_name": "router",
            "link_state_id": "2.2.2.2",
            "advertising_router": "3.3.3.3",
            "sequence": 2147483649_u32,
            "checksum": 65262,
            "length": 48
        })
    }

    /// RFC 2328 A.4.1 field offsets, and the round trip through the parser the events use.
    #[test]
    fn ospf_lsack_carries_the_lsa_headers_at_rfc_offsets() {
        let ack = OspfProtocol::build_link_state_ack_packet(&serde_json::json!({
            "type": "send_link_state_ack",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "lsa_headers": [sample_lsa_header()],
        }))
        .expect("build lsack");

        assert_eq!(ack[1], 5, "type 5 = Link State Acknowledgment");
        assert_eq!(
            ack.len(),
            24 + 20,
            "24-byte header + one 20-byte LSA header"
        );
        assert_eq!(
            u16::from_be_bytes([ack[2], ack[3]]) as usize,
            ack.len(),
            "packet length must cover the body"
        );

        let body = &ack[24..];
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), 1, "LS age");
        assert_eq!(body[2], 2, "options");
        assert_eq!(body[3], 1, "LS type");
        assert_eq!(&body[4..8], &[2, 2, 2, 2], "Link State ID");
        assert_eq!(&body[8..12], &[3, 3, 3, 3], "Advertising Router");
        assert_eq!(
            u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
            2147483649,
            "LS sequence number"
        );
        assert_eq!(
            u16::from_be_bytes([body[16], body[17]]),
            65262,
            "LS checksum must be echoed verbatim - RFC 2328 13.7 matches on it"
        );
        assert_eq!(u16::from_be_bytes([body[18], body[19]]), 48, "length");

        // The acknowledgement a peer would read back must be the header we were given.
        let parsed = OspfProtocol::parse_lsa_headers(body, 8);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], sample_lsa_header());
    }

    /// Several headers, and the packet still validates as a whole.
    #[test]
    fn ospf_lsack_round_trips_several_headers() {
        let mut second = sample_lsa_header();
        second["lsa_type"] = serde_json::json!(5);
        second["link_state_id"] = serde_json::json!("10.0.0.0");

        let ack = OspfProtocol::build_link_state_ack_packet(&serde_json::json!({
            "type": "send_link_state_ack",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "lsa_headers": [sample_lsa_header(), second.clone()],
        }))
        .expect("build lsack");

        assert_eq!(ack.len(), 24 + 40);
        assert_eq!(OspfProtocol::calculate_checksum(&ack), 0);

        let parsed = OspfProtocol::parse_lsa_headers(&ack[24..], 8);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1]["lsa_type_name"], "as_external");
        assert_eq!(parsed[1]["link_state_id"], "10.0.0.0");
    }

    /// RFC 2328 A.3.4: the LSR body is a repeating LSType(4) | LinkStateID(4) |
    /// AdvertisingRouter(4) triple.
    #[test]
    fn ospf_lsr_carries_the_request_triples() {
        let lsr = OspfProtocol::build_link_state_request_packet(&serde_json::json!({
            "type": "send_link_state_request",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "requests": [
                {"lsa_type": 1, "link_state_id": "2.2.2.2", "advertising_router": "2.2.2.2"},
                {"lsa_type": 5, "link_state_id": "10.0.0.0", "advertising_router": "3.3.3.3"},
            ],
        }))
        .expect("build lsr");

        assert_eq!(lsr[1], 3, "type 3 = Link State Request");
        assert_eq!(lsr.len(), 24 + 24, "two 12-byte triples");
        assert_eq!(OspfProtocol::calculate_checksum(&lsr), 0);

        let body = &lsr[24..];
        assert_eq!(u32::from_be_bytes([body[0], body[1], body[2], body[3]]), 1);
        assert_eq!(&body[4..8], &[2, 2, 2, 2]);
        assert_eq!(&body[8..12], &[2, 2, 2, 2]);
        assert_eq!(
            u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
            5
        );
        assert_eq!(&body[16..20], &[10, 0, 0, 0]);
        assert_eq!(&body[20..24], &[3, 3, 3, 3]);
    }

    /// Omitting the body is still allowed - it just produces a packet that asks for and
    /// acknowledges nothing, which is what these two used to do unconditionally.
    #[test]
    fn ospf_lsack_and_lsr_bodies_are_optional() {
        let bare = serde_json::json!({"router_id": "1.1.1.1", "area_id": "0.0.0.0"});
        assert_eq!(
            OspfProtocol::build_link_state_ack_packet(&bare)
                .expect("build")
                .len(),
            24
        );
        assert_eq!(
            OspfProtocol::build_link_state_request_packet(&bare)
                .expect("build")
                .len(),
            24
        );
    }

    /// A malformed dotted quad used to become 0.0.0.0 and return Ok, so a typo'd router_id
    /// produced a well-formed packet claiming to be a different router, with nothing logged.
    #[test]
    fn ospf_rejects_a_malformed_ipv4_field_instead_of_substituting_zero() {
        for bad in ["1.1.1", "999.1.1.1", "1.1.1.1.1", "not-an-ip", ""] {
            let action = serde_json::json!({
                "type": "send_hello",
                "router_id": bad,
                "area_id": "0.0.0.0",
            });
            let err = OspfProtocol::build_hello_packet(&action).expect_err(
                "a malformed router_id must be an error, not a packet advertising 0.0.0.0",
            );
            assert!(
                err.to_string().contains(bad) || bad.is_empty(),
                "the error should name the offending value, got {err:#}"
            );
        }

        // The good case still builds.
        let action = serde_json::json!({
            "type": "send_hello",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
        });
        assert_eq!(
            &OspfProtocol::build_hello_packet(&action).expect("build hello")[4..8],
            &[1, 1, 1, 1]
        );
    }
}
