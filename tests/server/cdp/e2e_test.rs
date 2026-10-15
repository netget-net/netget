//! CDP end-to-end tests over the declared UDP test transport.
//!
//! The real CDP transport is raw 802.3 through libpcap and cannot run unprivileged, so the
//! server declares a `transport: "udp"` startup parameter under which each datagram is one
//! complete 802.3 CDP frame. That makes the whole chain testable without root — capture-side
//! decode, the `cdp_neighbor_advertisement` event, the LLM round trip, the action executor, the
//! frame encoder and the send — with only the pcap read/write calls left unexercised.
//!
//! Three things are asserted here that the pure codec tests cannot reach:
//!
//! 1. A neighbour's advertisement reaches the model as **structured fields**, and the frame the
//!    model's answer produces is a well-formed CDP advertisement carrying what it asked for.
//! 2. An **LLM failure emits nothing at all.** CDP has no error frame, so silence is the only
//!    correct answer and this test pins it.
//! 3. `no_advertisement` — the model's explicit refusal — also emits nothing, and is distinct in
//!    the log from the failure above.

#[cfg(all(unix, feature = "libpcap"))]
mod tests {
    use crate::helpers::*;
    use ::netget::server::cdp::codec;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// A real CDPv2 payload from a Catalyst 2950 (scapy's regression vector), used as the
    /// neighbour's advertisement. Its bytes come from a capture, not from our own encoder.
    const NEIGHBOUR_PAYLOAD: &str = concat!(
        "02b48cfa0001000c6d7973776974636800020011000000010101cc0004c0a800fd000300134661737445746865726e65",
        "74302f31000400080000002800050114436973636f20496e7465726e6574776f726b204f7065726174696e6720537973",
        "74656d20536f667477617265200a494f532028746d2920433239353020536f667477617265202843323935302d49364b",
        "324c3251342d4d292c2056657273696f6e2031322e3128323229454131342c2052454c4541534520534f465457415245",
        "2028666331290a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74",
        "656368737570706f72740a436f707972696768742028632920313938362d3230313020627920636973636f2053797374",
        "656d732c20496e632e0a436f6d70696c6564205475652032362d4f63742d31302031303a3335206279206e6275727261",
        "00060015636973636f2057532d43323935302d31320008002400000c011200000000ffffffff010221ff000000000000",
        "000bbe189a40ff00000009000c4d59444f4d41494e000a00060001000b000501000e000701000a001200050000130005",
        "0000160011000000010101cc0004c0a800fd",
    );

    /// The MAC the neighbour appears to come from. Must differ from the server's configured
    /// `source_mac`, or the server correctly refuses to answer its own reflection.
    const NEIGHBOUR_MAC: [u8; 6] = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    const SERVER_MAC: &str = "02:00:0c:cc:cc:01";

    /// Build the neighbour's frame by hand from the specification, so the test does not depend
    /// on the code it is testing to produce its input.
    fn neighbour_frame() -> Vec<u8> {
        let payload = hex::decode(NEIGHBOUR_PAYLOAD).expect("vector is hex");
        let mut frame = Vec::with_capacity(22 + payload.len());
        frame.extend_from_slice(&[0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]); // CDP multicast
        frame.extend_from_slice(&NEIGHBOUR_MAC);
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // 802.3 length
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00]); // LLC/SNAP
        frame.extend_from_slice(&payload);
        frame
    }

    fn open_server_action(instruction: &str) -> serde_json::Value {
        serde_json::json!([{
            "type": "open_server",
            "base_stack": "CDP",
            "host": "127.0.0.1",
            "port": 0,
            "instruction": instruction,
            "startup_params": {
                "transport": "udp",
                "source_mac": SERVER_MAC
            }
        }])
    }

    /// A neighbour advertises itself; the model answers; a real CDP frame comes back.
    #[tokio::test]
    async fn test_cdp_answers_a_neighbour_with_the_identity_the_model_chose() -> E2EResult<()> {
        println!("\n=== E2E Test: CDP neighbour exchange ===");

        let prompt = "Start a CDP server on 127.0.0.1 port {AVAILABLE_PORT} using the udp test \
                      transport. Impersonate a Cisco Catalyst 2960 named SW-CORE-01.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("CDP")
                .respond_with_actions(open_server_action(
                    "You are a Cisco Catalyst 2960 named SW-CORE-01 on GigabitEthernet0/1.",
                ))
                .expect_calls(1)
                .and()
                // The event must carry the neighbour's fields as structured values. Matching on
                // them is the assertion: if the server hands the model a hex blob, or names the
                // fields differently, this rule never fires and `verify_mocks` reports 0 calls.
                .on_event("cdp_neighbor_advertisement")
                .and_event_data_contains("device_id", "myswitch")
                .and_event_data_contains("port_id", "FastEthernet0/1")
                .and_event_data_contains("platform", "cisco WS-C2950-12")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_cdp_advertisement",
                    "device_id": "SW-CORE-01",
                    "port_id": "GigabitEthernet0/1",
                    "platform": "cisco WS-C2960-24TT-L",
                    "software_version": "Cisco IOS Software, C2960 Software, Version 15.0(2)SE11",
                    "capabilities": ["switch", "igmp"],
                    "native_vlan": 42,
                    "duplex": "full",
                    "addresses": ["192.168.1.1"],
                    "management_addresses": ["192.168.1.1"],
                    "ttl": 180,
                    "version": 2
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        println!("CDP server (udp transport) on port {}", server.port);
        assert_ne!(
            server.port, 0,
            "the UDP transport must report the port it bound"
        );

        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(format!("127.0.0.1:{}", server.port)).await?;

        let frame = neighbour_frame();
        println!(
            "Sending a captured CDP advertisement ({} bytes)",
            frame.len()
        );
        client.send(&frame).await?;

        let mut buf = vec![0u8; 65535];
        let n = match tokio::time::timeout(Duration::from_secs(15), client.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("receiving the CDP reply failed: {e}"),
            Err(_) => panic!("timed out waiting for a CDP advertisement from the server"),
        };
        let reply = &buf[..n];
        println!("✓ received {} bytes back", n);

        // --- an independent dissector reads the frame before we do --------------------------
        //
        // The pcap oracle. Every other check here goes through
        // `netget::server::cdp::codec`, which is the code that wrote the frame; the
        // checksum assertion in particular compares our encoder against our decoder.
        // Wireshark's `cdp` dissector shares nothing with either: it recomputes the
        // checksum itself, walks the TLV list, and — because this is 802.3 rather than
        // Ethernet II — objects if the length field is not a length. That last case is
        // the defect Programme 2 found here by hand (an EtherType where the 802.3
        // length belongs), and it is worth knowing that it raises no expert info at
        // all: tshark simply hands the frame to the generic `data` dissector, which is
        // why the oracle fails on the dissector chain as well as on expert severity.
        //
        // The datagram is a complete 802.3 frame — that is what the `transport: "udp"`
        // test transport carries — so it goes to the oracle as a link-layer frame with
        // no synthetic framing added at all.
        crate::helpers::pcap_oracle::PcapOracle::ethernet("cdp")
            .frame(reply)
            .assert_clean();

        // --- assert the raw framing directly, before trusting any of our own parsers ---------
        assert!(n > 22, "reply is too short to be a CDP frame");
        assert_eq!(
            &reply[0..6],
            &[0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc],
            "CDP always goes to the 01:00:0c:cc:cc:cc multicast group"
        );
        assert_eq!(
            codec::mac_to_string(&reply[6..12].try_into().unwrap()),
            SERVER_MAC,
            "source MAC must be the configured source_mac startup parameter"
        );
        assert_eq!(
            u16::from_be_bytes([reply[12], reply[13]]) as usize,
            n - 14,
            "802.3 length field must cover LLC + SNAP + payload"
        );
        assert_eq!(
            &reply[14..22],
            &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00],
            "LLC/SNAP header: DSAP/SSAP 0xAA, control 0x03, OUI 00:00:0c, protocol 0x2000"
        );
        assert_eq!(reply[22], 2, "CDP version");
        assert_eq!(reply[23], 180, "CDP TTL");

        // --- then the fields the model chose ------------------------------------------------
        let (_, payload) = codec::decode_frame(reply).expect("reply is a CDP frame");
        let decoded = codec::decode_payload(payload).expect("reply payload parses");
        assert!(
            decoded.checksum_valid(),
            "the server must emit a correct checksum: carried 0x{:04x}, computes 0x{:04x}",
            decoded.declared_checksum,
            decoded.computed_checksum
        );

        let ad = decoded.advertisement;
        assert_eq!(ad.device_id.as_deref(), Some("SW-CORE-01"));
        assert_eq!(ad.port_id.as_deref(), Some("GigabitEthernet0/1"));
        assert_eq!(ad.platform.as_deref(), Some("cisco WS-C2960-24TT-L"));
        assert_eq!(
            ad.software_version.as_deref(),
            Some("Cisco IOS Software, C2960 Software, Version 15.0(2)SE11")
        );
        assert_eq!(ad.capabilities, Some(0x28), "switch | igmp");
        assert_eq!(
            ad.native_vlan,
            Some(42),
            "the field CDP is famous for leaking"
        );
        assert_eq!(ad.duplex, Some(codec::Duplex::Full));
        assert_eq!(ad.addresses.len(), 1);
        assert_eq!(ad.addresses[0].address, "192.168.1.1");
        assert_eq!(ad.management_addresses[0].address, "192.168.1.1");
        println!("✓ the advertisement carries exactly what the model asked for");

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }

    /// An LLM failure must put **nothing** on the wire.
    ///
    /// CDP defines no error or NAK frame; its only frame asserts that a device with a given
    /// identity exists on this link, and the neighbour caches it. So a fabricated reply would
    /// turn a backend outage into a fake switch in someone's neighbour table. The mock answers
    /// with text that is not a valid action, which is what a broken/hallucinating backend looks
    /// like, and the assertion is that no datagram comes back at all.
    #[tokio::test]
    async fn test_cdp_emits_nothing_when_the_llm_fails() -> E2EResult<()> {
        println!("\n=== E2E Test: CDP is silent on LLM failure ===");

        let prompt = "Start a CDP server on 127.0.0.1 port {AVAILABLE_PORT} using the udp test \
                      transport. Answer neighbours as a Catalyst switch.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("CDP")
                .respond_with_actions(open_server_action(
                    "You are a Cisco Catalyst 2960. Answer CDP neighbours.",
                ))
                .expect_calls(1)
                .and()
                // Not JSON, not an action: the retry/repair loop exhausts and `call_llm`
                // returns Err, which is the path being tested.
                .on_event("cdp_neighbor_advertisement")
                .respond_with_raw("the backend is having a bad day and this is not an action")
                .expect_at_least(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        println!("CDP server (udp transport) on port {}", server.port);

        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(format!("127.0.0.1:{}", server.port)).await?;
        client.send(&neighbour_frame()).await?;

        // Wait for the LLM exchange to have actually happened and failed, so the silence below
        // is the silence of a *failed* answer rather than of an answer still in flight.
        server
            .wait_for_any(
                &["decision=fail_closed_llm_error", "no advertisement emitted"],
                30,
            )
            .await;

        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf)).await {
            Err(_) => println!("✓ nothing was emitted, as required"),
            Ok(Ok(n)) => panic!(
                "CDP emitted {} bytes after an LLM failure; it must emit nothing at all. \
                 Frame: {}",
                n,
                hex::encode(&buf[..n])
            ),
            Ok(Err(e)) => panic!("unexpected socket error: {e}"),
        }

        // The distinction has to survive somewhere, and the log is the only place it can.
        let lines = server.get_output().await;
        let tagged = lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error"));
        assert!(
            tagged,
            "the failure must be logged with a decision= tag distinguishing it from a model \
             that chose silence. Output was:\n{}",
            lines.join("\n")
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("CDP advertisement sent via")),
            "no advertisement may be sent on the LLM-failure path"
        );

        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }

    /// `no_advertisement` is the model refusing, and refusal is also silence — but a *different*
    /// silence, and the log has to say which.
    #[tokio::test]
    async fn test_cdp_no_advertisement_is_silent_and_logged_as_a_refusal() -> E2EResult<()> {
        println!("\n=== E2E Test: CDP explicit refusal ===");

        let prompt = "Start a CDP server on 127.0.0.1 port {AVAILABLE_PORT} using the udp test \
                      transport. Stay invisible to unknown neighbours.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("CDP")
                .respond_with_actions(open_server_action(
                    "Do not disclose our identity to unrecognised neighbours.",
                ))
                .expect_calls(1)
                .and()
                .on_event("cdp_neighbor_advertisement")
                .respond_with_actions(serde_json::json!([{
                    "type": "no_advertisement",
                    "reason": "unrecognised neighbour on an access port"
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(format!("127.0.0.1:{}", server.port)).await?;
        client.send(&neighbour_frame()).await?;

        server.wait_for_any(&["decision=model_reject"], 30).await;

        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf)).await {
            Err(_) => println!("✓ nothing was emitted, as required"),
            Ok(Ok(n)) => panic!(
                "no_advertisement emitted {} bytes; it must emit nothing: {}",
                n,
                hex::encode(&buf[..n])
            ),
            Ok(Err(e)) => panic!("unexpected socket error: {e}"),
        }

        let lines = server.get_output().await;
        assert!(
            lines.iter().any(|l| l.contains("decision=model_reject")),
            "an explicit refusal must be logged as decision=model_reject, distinct from \
             fail_closed_llm_error. Output was:\n{}",
            lines.join("\n")
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test completed ===\n");
        Ok(())
    }
}
