#[cfg(unix)]
mod tests {
    use crate::server::helpers::*;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::{IcmpCode, IcmpTypes};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
    use pnet::packet::Packet;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    /// Check if we have CAP_NET_RAW or root privileges
    fn has_raw_socket_capability() -> bool {
        // Try to create a raw ICMP socket - this will fail without privileges
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }

    /// Build an ICMP Echo Request packet (IP + ICMP)
    fn build_icmp_echo_request(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        // ICMP packet
        let icmp_size = 8 + payload.len(); // 8-byte header + payload
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut echo_req = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            echo_req.set_icmp_type(IcmpTypes::EchoRequest);
            echo_req.set_icmp_code(IcmpCode::new(0));
            echo_req.set_identifier(identifier);
            echo_req.set_sequence_number(sequence);
            echo_req.set_payload(payload);
        }

        // Calculate ICMP checksum
        let icmp_checksum = {
            use pnet::packet::icmp::MutableIcmpPacket;
            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            pnet::packet::icmp::checksum(&icmp_packet.to_immutable())
        };

        {
            let mut echo_req = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            echo_req.set_checksum(icmp_checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            let ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);
        }

        ip_buffer
    }

    #[tokio::test]
    #[ignore = "needs raw IP sockets (root, or CAP_NET_RAW on Linux): without them \
                server_startup refuses ICMP before the server exists, so nothing here can be \
                exercised. Run under sudo with --ignored. It used to skip-and-return-Ok, which \
                cargo reported as a pass on every unprivileged machine - i.e. it looked like \
                ICMP coverage and was none."]
    async fn test_icmp_echo_server() -> E2EResult<()> {
        // Reached only via --ignored, i.e. someone explicitly asked for the privileged test.
        // Failing is the honest answer: skipping would report a pass for a test that verified
        // nothing.
        assert!(
            has_raw_socket_capability(),
            "test_icmp_echo_server requires raw IP socket access and this process does not have \
             it (root, or `setcap cap_net_raw+ep` on Linux). It asserts nothing without it and \
             must not report a pass."
        );

        println!("✓ Raw socket capability detected");

        // Use loopback interface for testing
        let interface = "lo";
        let test_ip = Ipv4Addr::new(127, 0, 0, 1);

        // Configure ICMP server with mock LLM responses
        let config = NetGetConfig::new(format!(
            r#"listen on interface {} via icmp

You are an ICMP echo server. When you receive echo requests:
1. For identifier 1234, sequence 1: Respond with echo reply
2. For identifier 5678, sequence 2: Respond with echo reply
3. For all other requests: Respond with echo reply"#,
            interface
        ))
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("listen on interface")
                .and_instruction_containing("icmp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "interface": interface,
                        "base_stack": "ICMP",
                        "instruction": "Respond to ICMP echo requests with echo replies"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: ICMP echo request (identifier=1234, sequence=1)
                .on_event("icmp_echo_request")
                .and_event_data_contains("identifier", "1234")
                .and_event_data_contains("sequence", "1")
                .respond_with_actions_from_event(|event_data| {
                    let source_ip = event_data["source_ip"].as_str().unwrap_or("127.0.0.1");
                    let identifier = event_data["identifier"].as_u64().unwrap_or(1234);
                    let sequence = event_data["sequence"].as_u64().unwrap_or(1);
                    let payload_hex = event_data["payload_hex"].as_str().unwrap_or("");

                    serde_json::json!([{
                        "type": "send_echo_reply",
                        "source_ip": "127.0.0.1",
                        "destination_ip": source_ip,
                        "identifier": identifier,
                        "sequence": sequence,
                        "payload_hex": payload_hex
                    }])
                })
                .expect_calls(1)
                .and()
                // Mock 3: ICMP echo request (identifier=5678, sequence=2)
                .on_event("icmp_echo_request")
                .and_event_data_contains("identifier", "5678")
                .and_event_data_contains("sequence", "2")
                .respond_with_actions_from_event(|event_data| {
                    let source_ip = event_data["source_ip"].as_str().unwrap_or("127.0.0.1");
                    let identifier = event_data["identifier"].as_u64().unwrap_or(5678);
                    let sequence = event_data["sequence"].as_u64().unwrap_or(2);
                    let payload_hex = event_data["payload_hex"].as_str().unwrap_or("");

                    serde_json::json!([{
                        "type": "send_echo_reply",
                        "source_ip": "127.0.0.1",
                        "destination_ip": source_ip,
                        "identifier": identifier,
                        "sequence": sequence,
                        "payload_hex": payload_hex
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let test_state = start_netget_server(config).await?;

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("✓ ICMP server started on interface {}", interface);

        // Create raw socket for sending and receiving ICMP
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        // `build_icmp_echo_request` below produces a whole IPv4 packet. Without IP_HDRINCL the
        // kernel prepends one of its own and ours arrives as the ICMP message - which is
        // exactly the "IP-in-IP encapsulation on loopback" the server still tolerates on its
        // receive path. This test was the source of that traffic.
        socket.set_header_included_v4(true)?;

        println!("✓ Opened raw ICMP socket for testing");

        // Test 1: Send ICMP Echo Request (identifier=1234, sequence=1)
        println!("\n[Test 1] ICMP Echo Request (identifier=1234, sequence=1)");
        let payload1 = b"Hello ICMP";
        let mut request1 = build_icmp_echo_request(test_ip, test_ip, 1234, 1, payload1);
        ::netget::server::icmp::prepare_ipv4_for_raw_send(&mut request1);

        socket.send_to(&request1, &SocketAddr::from((test_ip, 0)).into())?;
        println!("  Sent ICMP Echo Request");

        // Wait for Echo Reply
        let mut buffer = vec![std::mem::MaybeUninit::uninit(); 65535];
        let reply_found = match socket.recv_from(&mut buffer) {
            Ok((n, _)) => {
                let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, n) };

                // Parse IP packet
                use pnet::packet::ipv4::Ipv4Packet;
                if let Some(ip_packet) = Ipv4Packet::new(data) {
                    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        // Parse ICMP packet
                        use pnet::packet::icmp::echo_reply::EchoReplyPacket;
                        if let Some(echo_reply) = EchoReplyPacket::new(ip_packet.payload()) {
                            let reply_id = echo_reply.get_identifier();
                            let reply_seq = echo_reply.get_sequence_number();
                            let reply_payload = echo_reply.payload();

                            println!(
                                "  Received Echo Reply: identifier={}, sequence={}",
                                reply_id, reply_seq
                            );

                            // Verify it matches our request
                            if reply_id == 1234 && reply_seq == 1 && reply_payload == payload1 {
                                println!("  ✓ Echo Reply matches request");
                                true
                            } else {
                                println!("  ✗ Echo Reply mismatch");
                                false
                            }
                        } else {
                            println!("  ✗ Not an Echo Reply packet");
                            false
                        }
                    } else {
                        println!("  ✗ Not an ICMP packet");
                        false
                    }
                } else {
                    println!("  ✗ Failed to parse IP packet");
                    false
                }
            }
            Err(e) => {
                println!("  ⚠ Timeout waiting for Echo Reply: {}", e);
                false
            }
        };

        // Test 2: Send ICMP Echo Request (identifier=5678, sequence=2)
        println!("\n[Test 2] ICMP Echo Request (identifier=5678, sequence=2)");
        let payload2 = b"Ping test 2";
        let mut request2 = build_icmp_echo_request(test_ip, test_ip, 5678, 2, payload2);
        ::netget::server::icmp::prepare_ipv4_for_raw_send(&mut request2);

        socket.send_to(&request2, &SocketAddr::from((test_ip, 0)).into())?;
        println!("  Sent ICMP Echo Request");

        // Wait for Echo Reply
        let reply_found2 = match socket.recv_from(&mut buffer) {
            Ok((n, _)) => {
                let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, n) };

                use pnet::packet::ipv4::Ipv4Packet;
                if let Some(ip_packet) = Ipv4Packet::new(data) {
                    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        use pnet::packet::icmp::echo_reply::EchoReplyPacket;
                        if let Some(echo_reply) = EchoReplyPacket::new(ip_packet.payload()) {
                            let reply_id = echo_reply.get_identifier();
                            let reply_seq = echo_reply.get_sequence_number();
                            let reply_payload = echo_reply.payload();

                            println!(
                                "  Received Echo Reply: identifier={}, sequence={}",
                                reply_id, reply_seq
                            );

                            if reply_id == 5678 && reply_seq == 2 && reply_payload == payload2 {
                                println!("  ✓ Echo Reply matches request");
                                true
                            } else {
                                println!("  ✗ Echo Reply mismatch");
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Err(e) => {
                println!("  ⚠ Timeout waiting for Echo Reply: {}", e);
                false
            }
        };

        // Give server time to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify mocks were called correctly
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        test_state.wait_for_mocks(30).await;
        test_state.verify_mocks().await?;

        // Print summary
        println!("\n=== Test Summary ===");
        println!(
            "Test 1 (id=1234, seq=1): {}",
            if reply_found { "✓ PASS" } else { "✗ FAIL" }
        );
        println!(
            "Test 2 (id=5678, seq=2): {}",
            if reply_found2 { "✓ PASS" } else { "✗ FAIL" }
        );
        println!("Mock verification: ✓ PASS");

        // No echo reply means the packet path did not work, and that is the only thing this
        // test can say that `packet_codec_test.rs` cannot. Returning Ok() here made a run with
        // zero replies indistinguishable from a passing one - which is how the missing
        // IP_HDRINCL on the send socket survived for as long as it did.
        //
        // Caveat worth knowing when this fails: on loopback the kernel answers echo requests
        // itself, so a reply arriving does not by itself prove netget sent it. The mock
        // expectations above are what tie the reply to netget having been asked.
        assert!(
            reply_found || reply_found2,
            "no ICMP echo reply was received for either request; the server's reply never \
             reached the wire"
        );
        println!("\n✓ ICMP server test passed");
        Ok(())
    }
}
