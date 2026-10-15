//! BOOTP E2E tests
//!
//! Tests BOOTP server with mock LLM responses.


use crate::helpers::*;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Test basic BOOTP request/reply flow with mocks
/// LLM calls: 2 (server startup, bootp request received)
#[tokio::test]
async fn test_bootp_basic_flow() -> E2EResult<()> {
    let instruction = r#"
BOOTP server that assigns IP addresses from 192.168.1.100 onwards.
When receiving BOOTREQUEST:
  - Assign the next available IP starting from 192.168.1.100
  - Use server IP: 192.168.1.1
  - Boot file: "boot/pxeboot.n12"
  - Server hostname: "bootserver"
"#;

    // Start BOOTP server with mocks
    let server_config = NetGetConfig::new(format!(
        "Listen on port {{AVAILABLE_PORT}} via BOOTP. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: BOOTP request received (bootp_request event) - MUST COME FIRST for specificity
            .on_event("bootp_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_reply",
                    "assigned_ip": "192.168.1.100",
                    "server_ip": "192.168.1.1",
                    "boot_file": "boot/pxeboot.n12",
                    "server_hostname": "bootserver"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server startup (user command)
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("via BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,  // Port 0 = OS assigns available port automatically
                    "base_stack": "BOOTP",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;

    // Give server time to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create BOOTP BOOTREQUEST packet manually
    // BOOTP packet structure (RFC 951):
    // - op (1 byte): 1 = BOOTREQUEST, 2 = BOOTREPLY
    // - htype (1 byte): 1 = Ethernet
    // - hlen (1 byte): 6 = MAC address length
    // - hops (1 byte): 0
    // - xid (4 bytes): transaction ID
    // - secs (2 bytes): seconds since client started
    // - flags (2 bytes): broadcast flag
    // - ciaddr (4 bytes): client IP (0.0.0.0 initially)
    // - yiaddr (4 bytes): your IP (assigned by server)
    // - siaddr (4 bytes): server IP
    // - giaddr (4 bytes): gateway IP
    // - chaddr (16 bytes): client MAC address
    // - sname (64 bytes): server hostname
    // - file (128 bytes): boot file name
    // - vend (64 bytes): vendor-specific area (legacy, can be zeros)

    let mut bootrequest = vec![0u8; 300];

    // op = 1 (BOOTREQUEST)
    bootrequest[0] = 1;

    // htype = 1 (Ethernet)
    bootrequest[1] = 1;

    // hlen = 6 (MAC address length)
    bootrequest[2] = 6;

    // hops = 0
    bootrequest[3] = 0;

    // xid = 0x12345678
    bootrequest[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

    // secs = 0
    bootrequest[8..10].copy_from_slice(&[0, 0]);

    // flags = 0x8000 (broadcast)
    bootrequest[10..12].copy_from_slice(&[0x80, 0x00]);

    // ciaddr = 0.0.0.0
    bootrequest[12..16].copy_from_slice(&[0, 0, 0, 0]);

    // yiaddr = 0.0.0.0 (to be filled by server)
    bootrequest[16..20].copy_from_slice(&[0, 0, 0, 0]);

    // siaddr = 0.0.0.0
    bootrequest[20..24].copy_from_slice(&[0, 0, 0, 0]);

    // giaddr = 0.0.0.0
    bootrequest[24..28].copy_from_slice(&[0, 0, 0, 0]);

    // chaddr = 00:11:22:33:44:55 (client MAC)
    bootrequest[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Rest of chaddr padding (10 bytes)
    bootrequest[34..44].copy_from_slice(&[0; 10]);

    // sname (64 bytes) = empty
    bootrequest[44..108].copy_from_slice(&[0; 64]);

    // file (128 bytes) = empty
    bootrequest[108..236].copy_from_slice(&[0; 128]);

    // vend (64 bytes) = DHCP magic cookie for compatibility
    bootrequest[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootrequest[240..300].copy_from_slice(&[0; 60]);

    // Send BOOTREQUEST
    let client = UdpSocket::bind("0.0.0.0:0").await?;
    client
        .send_to(&bootrequest, format!("127.0.0.1:{}", server.port))
        .await?;

    // Wait for BOOTREPLY
    let mut response_buf = vec![0u8; 1500];
    let timeout =
        tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut response_buf)).await;

    assert!(timeout.is_ok(), "BOOTP response timeout");
    let (response_len, _) = timeout??;

    // Verify BOOTREPLY structure
    assert!(response_len >= 236, "Response too short");

    // op should be 2 (BOOTREPLY)
    assert_eq!(response_buf[0], 2, "Expected BOOTREPLY (op=2)");

    // xid should match request
    assert_eq!(
        &response_buf[4..8],
        &[0x12, 0x34, 0x56, 0x78],
        "Transaction ID mismatch"
    );

    // yiaddr should be assigned (192.168.1.100 = 0xC0A80164)
    let yiaddr = Ipv4Addr::new(
        response_buf[16],
        response_buf[17],
        response_buf[18],
        response_buf[19],
    );
    assert_eq!(
        yiaddr,
        Ipv4Addr::new(192, 168, 1, 100),
        "Expected IP 192.168.1.100"
    );

    // chaddr should match request (client MAC)
    assert_eq!(
        &response_buf[28..34],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        "Client MAC mismatch"
    );

    println!("✓ BOOTP basic request/reply flow successful");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// Test BOOTP with boot file configuration with mocks
/// LLM calls: 2 (server startup, bootp request received)
#[tokio::test]
async fn test_bootp_boot_file() -> E2EResult<()> {
    let instruction = r#"
BOOTP server for PXE boot.
When receiving BOOTREQUEST:
  - Assign IP 10.0.0.100
  - Server IP: 10.0.0.1
  - Boot file: "tftp/netboot.img"
  - Server hostname: "netboot.example.com"
"#;

    // Start BOOTP server with mocks
    let server_config = NetGetConfig::new(format!(
        "Listen on port {{AVAILABLE_PORT}} via BOOTP. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: BOOTP request received (bootp_request event) - MUST COME FIRST for specificity
            .on_event("bootp_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_reply",
                    "assigned_ip": "10.0.0.100",
                    "server_ip": "10.0.0.1",
                    "boot_file": "tftp/netboot.img",
                    "server_hostname": "netboot.example.com"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server startup (user command)
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("via BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,  // Port 0 = OS assigns available port automatically
                    "base_stack": "BOOTP",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create BOOTREQUEST
    let mut bootrequest = vec![0u8; 300];
    bootrequest[0] = 1; // BOOTREQUEST
    bootrequest[1] = 1; // Ethernet
    bootrequest[2] = 6; // MAC length
    bootrequest[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    bootrequest[10..12].copy_from_slice(&[0x80, 0x00]); // Broadcast flag
    bootrequest[28..34].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    bootrequest[236..240].copy_from_slice(&[99, 130, 83, 99]); // Magic cookie

    // Send request
    let client = UdpSocket::bind("0.0.0.0:0").await?;
    client
        .send_to(&bootrequest, format!("127.0.0.1:{}", server.port))
        .await?;

    // Wait for response
    let mut response_buf = vec![0u8; 1500];
    let timeout =
        tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut response_buf)).await;

    assert!(timeout.is_ok(), "BOOTP response timeout");
    let (response_len, _) = timeout??;

    assert!(response_len >= 236, "Response too short");

    // Check yiaddr
    let yiaddr = Ipv4Addr::new(
        response_buf[16],
        response_buf[17],
        response_buf[18],
        response_buf[19],
    );
    assert_eq!(
        yiaddr,
        Ipv4Addr::new(10, 0, 0, 100),
        "Expected IP 10.0.0.100"
    );

    // Check siaddr (server IP)
    let siaddr = Ipv4Addr::new(
        response_buf[20],
        response_buf[21],
        response_buf[22],
        response_buf[23],
    );
    assert_eq!(
        siaddr,
        Ipv4Addr::new(10, 0, 0, 1),
        "Expected server IP 10.0.0.1"
    );

    // Check file field (boot file name) - starts at offset 108
    let file_bytes = &response_buf[108..236];
    let file_str = String::from_utf8_lossy(file_bytes);
    let file_trimmed = file_str.trim_matches('\0');
    assert!(
        file_trimmed.contains("tftp/netboot.img") || file_trimmed.contains("netboot"),
        "Boot file not set correctly: '{}'",
        file_trimmed
    );

    println!("✓ BOOTP boot file configuration successful");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// Test BOOTP static MAC-based assignment with mocks
/// LLM calls: 2 (server startup, bootp request received)
#[tokio::test]
async fn test_bootp_static_assignment() -> E2EResult<()> {
    let instruction = r#"
BOOTP server with static MAC-to-IP mappings.
When receiving BOOTREQUEST:
  - If MAC is 00:11:22:33:44:55, assign IP 192.168.1.50 with boot file "linux/vmlinuz"
  - If MAC is 00:AA:BB:CC:DD:EE, assign IP 192.168.1.51 with boot file "windows/bootmgr.efi"
  - For any other MAC, assign IP from 192.168.1.100 onwards with boot file "boot/default.pxe"
Use server IP 192.168.1.1 for all responses.
"#;

    // Start BOOTP server with mocks
    let server_config = NetGetConfig::new(format!(
        "Listen on port {{AVAILABLE_PORT}} via BOOTP. {}",
        instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: BOOTP request received (bootp_request event) for specific MAC - MUST COME FIRST for specificity
            .on_event("bootp_request")
            .and_event_data_contains("client_mac", "001122334455")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_reply",
                    "assigned_ip": "192.168.1.50",
                    "server_ip": "192.168.1.1",
                    "boot_file": "linux/vmlinuz"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server startup (user command)
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("via BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,  // Port 0 = OS assigns available port automatically
                    "base_stack": "BOOTP",
                    "instruction": instruction
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test first static mapping (00:11:22:33:44:55 → 192.168.1.50)
    let mut bootrequest1 = vec![0u8; 300];
    bootrequest1[0] = 1; // BOOTREQUEST
    bootrequest1[1] = 1;
    bootrequest1[2] = 6;
    bootrequest1[4..8].copy_from_slice(&[0x11, 0x11, 0x11, 0x11]);
    bootrequest1[10..12].copy_from_slice(&[0x80, 0x00]);
    bootrequest1[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    bootrequest1[236..240].copy_from_slice(&[99, 130, 83, 99]);

    let client = UdpSocket::bind("0.0.0.0:0").await?;
    client
        .send_to(&bootrequest1, format!("127.0.0.1:{}", server.port))
        .await?;

    let mut response_buf = vec![0u8; 1500];
    let timeout =
        tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut response_buf)).await;

    assert!(timeout.is_ok(), "BOOTP response timeout");
    let (response_len, _) = timeout??;

    assert!(response_len >= 236, "Response too short");

    let yiaddr = Ipv4Addr::new(
        response_buf[16],
        response_buf[17],
        response_buf[18],
        response_buf[19],
    );
    assert_eq!(
        yiaddr,
        Ipv4Addr::new(192, 168, 1, 50),
        "Expected static IP 192.168.1.50"
    );

    println!("✓ BOOTP static MAC-based assignment successful");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}
