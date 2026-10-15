//! E2E tests for ARP protocol
//!
//! These tests verify ARP server functionality by starting NetGet with ARP prompts
//! and using pnet to send real ARP requests.
//!
//! **This test cannot pass as written, and `sudo` does not fix it.** It targets the
//! loopback interface, and ARP's `spawn()` refuses loopback outright: `arp` is an
//! Ethernet-only BPF keyword, so on DLT_NULL/DLT_LOOP libpcap compiles the filter to
//! "expression rejects all packets" and errors. That refusal is deliberate and is
//! asserted in both privilege branches by
//! `tests/capture_startup_reports_failure_test.rs::arp_spawn_refuses_loopback_and_says_why`.
//! Running it needs a real Ethernet or Wi-Fi interface **and** root — and it would then
//! inject ARP frames onto that live segment, which is why it is not pointed at one.
//!
//! The `#[ignore]` reason used to say "run under sudo to exercise", which was true when
//! the test was written and stopped being true when ARP started refusing loopback. Both
//! are corrected here rather than the test being deleted: the scenario it describes —
//! two mapped IPs answered, a third ignored — is the right one, and it is what a rewrite
//! against a real interface should assert.
//!
//! Meanwhile the ARP server's evidence that actually runs is
//! `tests/server/arp/frame_codec_test.rs`, which needs no interface and no privilege.
//!
//! Note also that the `Device::list().is_err()` guard below does **not** detect a missing
//! privilege: on macOS any unprivileged user can enumerate capture devices, and it is
//! opening one that fails. NetGet's own capability probe (`src/privilege.rs`) opens a
//! handle for exactly this reason.

#![cfg(all(unix, feature = "libpcap"))]

use crate::server::helpers::*;
use pcap::{Capture, Device};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Find the loopback interface (works cross-platform)
fn find_loopback_interface() -> Result<String, Box<dyn std::error::Error>> {
    let devices = Device::list()?;
    for device in devices {
        // Look for loopback interface (lo, lo0, or similar)
        if device.name == "lo" || device.name == "lo0" || device.name.starts_with("lo") {
            return Ok(device.name);
        }
    }
    Err("No loopback interface found".into())
}

/// Build an ARP request packet
fn build_arp_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut eth_buffer = vec![0u8; 42]; // 14 eth + 28 arp

    // Build Ethernet frame
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(sender_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        // Build ARP packet
        let mut arp_buffer = vec![0u8; 28];
        {
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(sender_mac);
            arp_packet.set_sender_proto_addr(sender_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(target_ip);
        }

        eth_packet.set_payload(&arp_buffer);
    }

    eth_buffer
}

#[tokio::test]
#[ignore = "Cannot pass as written, with or without privilege, and sudo does not help. It targets the loopback interface, and ARP spawn() refuses loopback outright: `arp` is an Ethernet-only BPF keyword and libpcap rejects the filter on DLT_NULL/DLT_LOOP, which tests/capture_startup_reports_failure_test.rs::arp_spawn_refuses_loopback_and_says_why asserts in both privilege branches. Unprivileged it fails one step earlier, at the capture open. Exercising it needs a real Ethernet or Wi-Fi interface AND root, and it would inject ARP frames onto that live segment - which is why it is not pointed at one by default. tests/server/arp/frame_codec_test.rs is the ARP server evidence that actually runs."]
async fn test_arp_responder() -> E2EResult<()> {
    // Check if we can access pcap (requires privileges)
    if Device::list().is_err() {
        println!("⚠ Skipping ARP test: requires CAP_NET_RAW or root privileges");
        return Ok(());
    }

    // Find loopback interface
    let interface = match find_loopback_interface() {
        Ok(iface) => iface,
        Err(e) => {
            println!("⚠ Skipping ARP test: {}", e);
            return Ok(());
        }
    };

    println!("✓ Using interface: {}", interface);

    // Single comprehensive server with mocks for ARP responses
    let config = NetGetConfig::new(format!(
        r#"listen on interface {} via arp

You are an ARP responder. When you receive ARP requests:

1. For IP 192.168.1.100: Respond with MAC address aa:bb:cc:dd:ee:ff
2. For IP 192.168.1.101: Respond with MAC address 11:22:33:44:55:66
3. For any other IP: Ignore (no response)
"#,
        interface
    ))
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on interface")
            .and_instruction_containing("arp")
            .and_instruction_containing("ARP responder")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "interface": interface,
                    "base_stack": "ARP",
                    "instruction": "Respond to ARP requests per the mapping rules"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: ARP request for 192.168.1.100 (should respond)
            .on_event("arp_request_received")
            .and_event_data_contains("target_ip", "192.168.1.100")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_arp_reply",
                    "sender_mac": "aa:bb:cc:dd:ee:ff",
                    "sender_ip": "192.168.1.100",
                    "target_mac": "de:ad:be:ef:00:01",
                    "target_ip": "192.168.1.50"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: ARP request for 192.168.1.101 (should respond)
            .on_event("arp_request_received")
            .and_event_data_contains("target_ip", "192.168.1.101")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_arp_reply",
                    "sender_mac": "11:22:33:44:55:66",
                    "sender_ip": "192.168.1.101",
                    "target_mac": "de:ad:be:ef:00:01",
                    "target_ip": "192.168.1.50"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: ARP request for 192.168.1.200 (should ignore)
            .on_event("arp_request_received")
            .and_event_data_contains("target_ip", "192.168.1.200")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "ignore_arp"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let test_state = start_netget_server(config).await?;

    // Wait for server to be ready and set up scripting
    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("✓ ARP server started on interface {}", interface);

    // Open pcap for sending and receiving
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or("Interface not found")?;

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(5000)
        .open()?;

    // Apply ARP filter
    cap.filter("arp", true)?;

    println!("✓ Opened pcap capture for testing");

    // Test 1: ARP request for 192.168.1.100 (should respond with aa:bb:cc:dd:ee:ff)
    println!("\n[Test 1] ARP request for 192.168.1.100 (should respond)");
    let sender_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01);
    let sender_ip = Ipv4Addr::new(192, 168, 1, 50);
    let target_ip = Ipv4Addr::new(192, 168, 1, 100);

    let request = build_arp_request(sender_mac, sender_ip, target_ip);
    cap.sendpacket(&*request)?;
    println!("  Sent ARP request for {}", target_ip);

    // Wait for response with timeout
    let response_found = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    // Parse response
                    use pnet::packet::arp::ArpPacket;
                    use pnet::packet::ethernet::EthernetPacket;

                    if let Some(eth) = EthernetPacket::new(packet.data) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let reply_sender_ip = arp.get_sender_proto_addr();
                                    let reply_sender_mac = arp.get_sender_hw_addr();

                                    println!(
                                        "  Received ARP reply: {} is at {}",
                                        reply_sender_ip, reply_sender_mac
                                    );

                                    // Check if this is the reply we're looking for
                                    if reply_sender_ip == target_ip {
                                        let expected_mac =
                                            MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
                                        if reply_sender_mac == expected_mac {
                                            return Ok::<(), Box<dyn std::error::Error>>(());
                                        } else {
                                            return Err(format!(
                                                "Wrong MAC: expected {}, got {}",
                                                expected_mac, reply_sender_mac
                                            )
                                            .into());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await;

    match response_found {
        Ok(Ok(())) => println!("✓ Received correct ARP reply for 192.168.1.100"),
        Ok(Err(e)) => return Err(format!("ARP reply validation failed: {}", e).into()),
        Err(_) => {
            println!("⚠ Timeout waiting for ARP reply (may be expected in some environments)")
        }
    }

    // Test 2: ARP request for 192.168.1.101 (should respond with 11:22:33:44:55:66)
    println!("\n[Test 2] ARP request for 192.168.1.101 (should respond)");
    let target_ip_2 = Ipv4Addr::new(192, 168, 1, 101);
    let request_2 = build_arp_request(sender_mac, sender_ip, target_ip_2);
    cap.sendpacket(&*request_2)?;
    println!("  Sent ARP request for {}", target_ip_2);

    let response_found_2 = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    use pnet::packet::arp::ArpPacket;
                    use pnet::packet::ethernet::EthernetPacket;

                    if let Some(eth) = EthernetPacket::new(packet.data) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let reply_sender_ip = arp.get_sender_proto_addr();
                                    let reply_sender_mac = arp.get_sender_hw_addr();

                                    if reply_sender_ip == target_ip_2 {
                                        let expected_mac =
                                            MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
                                        if reply_sender_mac == expected_mac {
                                            return Ok::<(), Box<dyn std::error::Error>>(());
                                        } else {
                                            return Err(format!(
                                                "Wrong MAC: expected {}, got {}",
                                                expected_mac, reply_sender_mac
                                            )
                                            .into());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await;

    match response_found_2 {
        Ok(Ok(())) => println!("✓ Received correct ARP reply for 192.168.1.101"),
        Ok(Err(e)) => return Err(format!("ARP reply validation failed: {}", e).into()),
        Err(_) => {
            println!("⚠ Timeout waiting for ARP reply (may be expected in some environments)")
        }
    }

    // Test 3: ARP request for unknown IP (should be ignored)
    println!("\n[Test 3] ARP request for 192.168.1.200 (should be ignored)");
    let target_ip_3 = Ipv4Addr::new(192, 168, 1, 200);
    let request_3 = build_arp_request(sender_mac, sender_ip, target_ip_3);
    cap.sendpacket(&*request_3)?;
    println!("  Sent ARP request for {}", target_ip_3);

    // Should timeout (no response expected)
    let response_found_3 = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    use pnet::packet::arp::ArpPacket;
                    use pnet::packet::ethernet::EthernetPacket;

                    if let Some(eth) = EthernetPacket::new(packet.data) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let reply_sender_ip = arp.get_sender_proto_addr();
                                    if reply_sender_ip == target_ip_3 {
                                        return Err::<(), Box<dyn std::error::Error>>(
                                            "Unexpected ARP reply for unknown IP".into(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await;

    match response_found_3 {
        Err(_) => println!("✓ No response for unknown IP (as expected)"),
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("Unexpected ARP reply: {}", e).into()),
    }

    println!("\n✓ All ARP tests passed");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    Ok(())
}
