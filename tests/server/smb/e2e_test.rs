//! E2E tests for SMB server
//!
//! These tests spawn the NetGet binary and test SMB2 protocol operations
//! using raw TCP socket communication to send SMB2 packets, each framed with the Direct TCP
//! transport header (MS-SMB2 2.1) a real client writes on port 445.

use crate::server::helpers::{start_netget_server, E2EResult};

use super::wire_util::{nbss, read_frame_into, read_frame_sync, tree_connect};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// Helper: Build SMB2 Negotiate Protocol Request (Direct TCP framing added by `nbss`)
fn build_smb2_negotiate() -> Vec<u8> {
    let mut packet = Vec::new();

    // SMB2 Header (64 bytes); `nbss` adds the transport header
    packet.extend_from_slice(b"\xFESMB"); // Protocol ID
    packet.extend_from_slice(&[64, 0]); // Header length = 64
    packet.extend_from_slice(&[0; 2]); // Credit charge
    packet.extend_from_slice(&[0; 4]); // Status (0 = success)
    packet.extend_from_slice(&[0x00, 0x00]); // Command = NEGOTIATE (0x0000)
    packet.extend_from_slice(&[1, 0]); // Credit request
    packet.extend_from_slice(&[0; 4]); // Flags
    packet.extend_from_slice(&[0; 4]); // Next command offset
    packet.extend_from_slice(&[0; 8]); // Message ID
    packet.extend_from_slice(&[0; 4]); // Reserved
    packet.extend_from_slice(&[0; 4]); // Tree ID
    packet.extend_from_slice(&[0; 8]); // Session ID
    packet.extend_from_slice(&[0; 16]); // Signature

    // SMB2 Negotiate Request Body (36 bytes)
    packet.extend_from_slice(&[36, 0]); // Structure size
    packet.extend_from_slice(&[1, 0]); // Dialect count = 1
    packet.extend_from_slice(&[0; 2]); // Security mode
    packet.extend_from_slice(&[0; 2]); // Reserved
    packet.extend_from_slice(&[0; 4]); // Capabilities
    packet.extend_from_slice(&[0; 16]); // Client GUID
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Negotiation context offset/count
    packet.extend_from_slice(&[0x10, 0x02]); // SMB 2.1 dialect (0x0210)

    nbss(packet)
}

/// Helper: Build SMB2 Session Setup Request (Direct TCP framing added by `nbss`)
fn build_smb2_session_setup() -> Vec<u8> {
    let mut packet = Vec::new();

    // SMB2 Header (64 bytes); `nbss` adds the transport header
    packet.extend_from_slice(b"\xFESMB");
    packet.extend_from_slice(&[64, 0]); // Header length
    packet.extend_from_slice(&[0; 2]); // Credit charge
    packet.extend_from_slice(&[0; 4]); // Status
    packet.extend_from_slice(&[0x01, 0x00]); // Command = SESSION_SETUP (0x0001)
    packet.extend_from_slice(&[1, 0]); // Credit request
    packet.extend_from_slice(&[0; 4]); // Flags
    packet.extend_from_slice(&[0; 4]); // Next command
    packet.extend_from_slice(&[1; 8]); // Message ID = 1
    packet.extend_from_slice(&[0; 4]); // Reserved
    packet.extend_from_slice(&[0; 4]); // Tree ID
    packet.extend_from_slice(&[0; 8]); // Session ID
    packet.extend_from_slice(&[0; 16]); // Signature

    // SMB2 Session Setup Request Body (minimal, guest auth)
    packet.extend_from_slice(&[25, 0]); // Structure size
    packet.extend_from_slice(&[0; 1]); // Flags
    packet.extend_from_slice(&[0; 1]); // Security mode
    packet.extend_from_slice(&[0; 4]); // Capabilities
    packet.extend_from_slice(&[0; 4]); // Channel
    packet.extend_from_slice(&[88, 0]); // Security buffer offset (64 + 24)
    packet.extend_from_slice(&[0, 0]); // Security buffer length = 0 (guest)
    packet.extend_from_slice(&[0; 8]); // Previous session ID

    nbss(packet)
}

/// Helper: Parse SMB2 response and extract status (Direct TCP framing added by `nbss`)
fn parse_smb2_status(response: &[u8]) -> Option<u32> {
    if response.len() < 64 {
        return None;
    }

    // Check for SMB2 signature at offset 0 (Direct TCP mode)
    if &response[0..4] != b"\xFESMB" {
        return None;
    }

    // Status is at offset 8 (8 bytes into SMB2 header, no NetBIOS offset)
    Some(u32::from_le_bytes([
        response[8],
        response[9],
        response[10],
        response[11],
    ]))
}

/// Test: SMB2 Negotiate Protocol
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_negotiate() -> E2EResult<()> {
    println!("\n=== Test: SMB2 Negotiate Protocol ===");

    let prompt = "Start an SMB file server on port 8445. \
                 Accept all guest connections without password. \
                 Provide a virtual filesystem with /documents directory containing welcome.txt";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup (use on_any since instruction extraction is unreliable)
            .on_any()
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    // Wait for server to be ready
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Connect via TCP
    let addr = format!("127.0.0.1:{}", server.port);
    println!("  [TEST] Connecting to {}", addr);

    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?; // Increased for debugging
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send SMB2 Negotiate
    println!("  [TEST] Sending SMB2 Negotiate request");
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    // Read response
    let mut response = vec![0u8; 2048];
    let n = read_frame_into(&mut stream, &mut response)?;
    response.truncate(n);

    println!("  [TEST] Received {} bytes", n);

    // Verify it's a valid SMB2 response (Direct TCP, 64-byte minimum)
    assert!(n >= 64, "Response too short for SMB2 message");

    // Check SMB2 signature (Direct TCP format, no NetBIOS wrapper)
    assert_eq!(&response[0..4], b"\xFESMB", "Invalid SMB2 signature");

    // Check status (should be 0 = success)
    if let Some(status) = parse_smb2_status(&response) {
        println!("  [TEST] Negotiate status: 0x{:08X}", status);
        assert_eq!(status, 0, "Negotiate should succeed with status 0");
    }

    println!("  [TEST] ✓ SMB2 Negotiate successful");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: SMB2 Session Setup (Guest Authentication)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_session_setup() -> E2EResult<()> {
    println!("\n=== Test: SMB2 Session Setup (Guest) ===");

    let prompt = "Start an SMB file server on port 8446. \
                 Allow guest authentication without credentials.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: SMB operation events (session_setup) - MUST come before on_any()
            .on_event("smb_operation")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success"}
            ]))
            .expect_at_least(1)
            .and()
            // Mock 2: Server startup (user command) - Catch-all for other LLM calls
            .on_any()
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);
    println!("  [TEST] Connecting to {}", addr);

    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?; // Increased for debugging
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send SMB2 Negotiate
    println!("  [TEST] Step 1: Negotiate");
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let n = read_frame_into(&mut stream, &mut response)?;
    println!("  [TEST] Negotiate response: {} bytes", n);

    // Send SMB2 Session Setup
    println!("  [TEST] Step 2: Session Setup (guest)");
    let session_setup = build_smb2_session_setup();
    stream.write_all(&session_setup)?;
    stream.flush()?;

    response.clear();
    response.resize(2048, 0);
    let n = read_frame_into(&mut stream, &mut response)?;
    response.truncate(n);

    println!("  [TEST] Session Setup response: {} bytes", n);

    // Verify SMB2 response (Direct TCP, 64-byte minimum)
    assert!(n >= 64, "Response too short for SMB2 message");
    assert_eq!(&response[0..4], b"\xFESMB", "Invalid SMB2 signature");

    // `if let Some(status)` used to wrap this, so a response too malformed to parse a
    // status out of skipped the check entirely and the test passed.
    let status = parse_smb2_status(&response)
        .expect("SESSION_SETUP response was too short to carry an NTSTATUS");
    println!("  [TEST] Session Setup status: 0x{:08X}", status);
    // The model approved this login, so STATUS_SUCCESS is the only correct answer.
    // 0xC0000016 used to be accepted here as "more processing required" — it is
    // STATUS_MORE_PROCESSING_REQUIRED, an intermediate SPNEGO status this server never has
    // cause to send, and accepting it is what let the deny path go unnoticed for so long:
    // the same constant was being sent for an approval and for a refusal.
    assert_eq!(
        status, 0,
        "an approved SESSION_SETUP must answer STATUS_SUCCESS"
    );

    println!("  [TEST] ✓ SMB2 Session Setup successful");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: Multiple Concurrent SMB Connections
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_concurrent_connections() -> E2EResult<()> {
    println!("\n=== Test: Multiple Concurrent SMB Connections ===");

    let prompt = "Start an SMB file server on port 8447. \
                 Handle multiple concurrent client connections.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_any() // Changed from on_instruction_containing since instruction extraction is unreliable
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);

    // Test with 3 concurrent connections
    let mut handles = vec![];

    for i in 0..3 {
        let addr = addr.clone();
        let handle = tokio::spawn(async move {
            println!("  [TEST] Client {} connecting", i);

            let mut stream = TcpStream::connect(&addr).expect("Failed to connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("Failed to set timeout");

            // Send negotiate
            let negotiate = build_smb2_negotiate();
            stream.write_all(&negotiate).expect("Failed to write");
            stream.flush().expect("Failed to flush");

            // Read response
            let mut response = vec![0u8; 2048];
            let n = read_frame_into(&mut stream, &mut response).expect("Failed to read");

            // Verify response
            assert!(n >= 64, "Client {}: Response too short", i);
            assert_eq!(
                &response[0..4],
                b"\xFESMB",
                "Client {}: Invalid SMB2 signature",
                i
            );

            println!("  [TEST] Client {} ✓ received valid response", i);
        });
        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        handle.await.expect("Client task failed");
    }

    println!("  [TEST] ✓ Multiple concurrent connections successful");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: Server Responds to SMB Traffic
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_server_responsiveness() -> E2EResult<()> {
    println!("\n=== Test: SMB Server Responsiveness ===");

    let prompt = "Start an SMB file server on port 8448. \
                 Respond to all SMB2 requests with appropriate messages.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_any() // Changed from on_instruction_containing since instruction extraction is unreliable
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);
    println!("  [TEST] Connecting to {}", addr);

    // Test connection and basic protocol
    match TcpStream::connect(&addr) {
        Ok(mut stream) => {
            println!("  [TEST] ✓ TCP connection established");

            stream.set_read_timeout(Some(Duration::from_secs(30)))?; // Increased for debugging
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;

            // Send negotiate
            let negotiate = build_smb2_negotiate();
            match stream.write_all(&negotiate) {
                Ok(_) => {
                    println!("  [TEST] ✓ Sent SMB2 Negotiate");
                    stream.flush()?;

                    // Try to read response
                    let mut response = vec![0u8; 2048];
                    match read_frame_into(&mut stream, &mut response) {
                        Ok(n) if n > 0 => {
                            println!("  [TEST] ✓ Received {} bytes response", n);

                            // Check if it looks like SMB2 (Direct TCP format)
                            if n >= 4 && &response[0..4] == b"\xFESMB" {
                                println!("  [TEST] ✓ Valid SMB2 response signature");
                            } else {
                                println!("  [TEST] Note: Response doesn't look like SMB2, but server is responsive");
                            }
                        }
                        Ok(_) => {
                            println!("  [TEST] Note: Connection closed by server");
                        }
                        Err(e) => {
                            println!("  [TEST] Note: Read error: {} (server may not be fully implemented)", e);
                        }
                    }
                }
                Err(e) => {
                    println!("  [TEST] Note: Write failed: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("Failed to connect to SMB server: {}", e);
        }
    }

    println!("  [TEST] ✓ Server is responsive to SMB traffic");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: Verify Server Stack
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_correct_stack() -> E2EResult<()> {
    println!("\n=== Test: SMB Server Uses Correct Stack ===");

    let prompt = "Start an SMB file server on port 8449 via smb.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_any() // Changed from on_instruction_containing since instruction extraction is unreliable
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    // Verify the server started with SMB stack
    assert!(
        server.stack.contains("SMB"),
        "Server should use SMB stack, got: {}",
        server.stack
    );

    println!("  [TEST] ✓ Server started with {} stack", server.stack);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: SMB Authentication Success via LLM
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_auth_llm_controlled() -> E2EResult<()> {
    println!("\n=== Test: SMB LLM-Controlled Authentication ===");

    let prompt = "Start an SMB file server on port 8450 via smb. \
                 When users try to authenticate, check their username. \
                 Allow user 'alice' by responding with smb_auth_success. \
                 For all other users, respond with smb_auth_deny.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: SMB operation events - MUST come before on_any()
            // `smb_auth_deny` is the denial action. This used to send
            // `{"type": "wait_for_more"}` with the comment "// Deny auth" - SMB declares no
            // such action, so the response was rejected as an unknown action, the retry
            // loop fired an extra LLM call, and `verify_mocks` failed on the call count.
            // The test never actually exercised a denial.
            .on_event("smb_operation")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_deny", "username": "guest", "reason": "only alice may log in"}
            ]))
            .expect_at_least(1)
            .and()
            // Mock 2: Server startup - Catch-all
            .on_any()
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);
    println!("  [TEST] Connecting to {}", addr);

    // Test 1: Try to connect (Negotiate + Session Setup for guest)
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?; // Increased for debugging
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send Negotiate
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let n = read_frame_into(&mut stream, &mut response)?;
    println!("  [TEST] Negotiate response: {} bytes", n);

    // Verify SMB2 response (Direct TCP, 64-byte minimum)
    assert!(n >= 64, "Negotiate response too short");
    assert_eq!(&response[0..4], b"\xFESMB", "Invalid SMB2 signature");

    // Send Session Setup
    let session_setup = build_smb2_session_setup();
    stream.write_all(&session_setup)?;
    stream.flush()?;

    response.clear();
    response.resize(2048, 0);
    let n = read_frame_into(&mut stream, &mut response)?;
    response.truncate(n);

    println!("  [TEST] Session Setup response: {} bytes", n);

    // The model denied guest, so the server must say so on the wire. Printing either
    // outcome as a success - which this test used to do - means it passes whatever
    // happens, including when the LLM response is rejected outright.
    // 0xC0000022, not 0xC0000016. This assertion used to name ACCESS_DENIED while pinning
    // STATUS_MORE_PROCESSING_REQUIRED — the status that tells a client the SPNEGO exchange
    // is still going — so it held the server's denial path to a value that does not deny.
    assert_eq!(
        parse_smb2_status(&response),
        Some(0xC000_0022),
        "smb_auth_deny must produce STATUS_ACCESS_DENIED (0xC0000022)"
    );

    println!("  [TEST] ✓ Denied login answered with STATUS_ACCESS_DENIED");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: Connection Tracking in UI
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_connection_tracking() -> E2EResult<()> {
    println!("\n=== Test: SMB Connection Tracking ===");

    let prompt = "Start an SMB file server on port 8451 via smb.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_any() // Changed from on_instruction_containing since instruction extraction is unreliable
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);

    // Make a connection
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?; // Increased for debugging

    // Send negotiate to establish connection
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let _ = read_frame_into(&mut stream, &mut response)?;

    // Give time for connection to be tracked
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check server output for connection tracking indicators
    let output = server.get_output().await;
    let has_connection_tracking = output.iter().any(|line| {
        line.contains("SMB connection")
            || line.contains("connection from")
            || line.contains("bytes")
    });

    if has_connection_tracking {
        println!("  [TEST] ✓ Connection tracking detected in output");
    } else {
        println!("  [TEST] Note: Connection tracking messages may not be in captured output");
    }

    // Close connection
    drop(stream);

    println!("  [TEST] ✓ Connection lifecycle completed");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

// ============================================================================
// Wire-level tests for the payload encoding and the routed operation actions
//
// The tests above assert that the server answers; these assert *what* it puts on
// the wire. That distinction is the whole point: `smb_read_file.content` was
// documented as "base64 encoded for binary" while the executor did `.as_bytes()`,
// so a model following the documentation delivered literal base64 ASCII as the
// file's contents and every test still passed.
// ============================================================================

/// Helper: Build an SMB2 CREATE request for `path` on tree 1 of session 1.
///
/// MS-SMB2 2.2.13. The name is UTF-16LE in the buffer at absolute offset 120, which is
/// what NameOffset advertises - the server must locate it through NameOffset/NameLength.
fn build_smb2_create(message_id: u64, path: &str) -> Vec<u8> {
    let name_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut packet = Vec::new();

    // SMB2 header
    packet.extend_from_slice(b"\xFESMB");
    packet.extend_from_slice(&[64, 0]); // Header length
    packet.extend_from_slice(&[0; 2]); // Credit charge
    packet.extend_from_slice(&[0; 4]); // Status
    packet.extend_from_slice(&[0x05, 0x00]); // Command = CREATE
    packet.extend_from_slice(&[1, 0]); // Credit request
    packet.extend_from_slice(&[0; 4]); // Flags
    packet.extend_from_slice(&[0; 4]); // Next command
    packet.extend_from_slice(&message_id.to_le_bytes());
    packet.extend_from_slice(&[0; 4]); // Reserved
    packet.extend_from_slice(&[1, 0, 0, 0]); // Tree ID
    packet.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // Session ID
    packet.extend_from_slice(&[0; 16]); // Signature
    assert_eq!(packet.len(), 64);

    // CREATE request body (57 fixed bytes, then the name buffer)
    packet.extend_from_slice(&[57, 0]); // StructureSize
    packet.push(0); // SecurityFlags
    packet.push(0); // RequestedOplockLevel
    packet.extend_from_slice(&[0; 4]); // ImpersonationLevel
    packet.extend_from_slice(&[0; 8]); // SmbCreateFlags
    packet.extend_from_slice(&[0; 8]); // Reserved
    packet.extend_from_slice(&[0x89, 0x00, 0x12, 0x00]); // DesiredAccess
    packet.extend_from_slice(&[0x80, 0, 0, 0]); // FileAttributes = NORMAL
    packet.extend_from_slice(&[0x07, 0, 0, 0]); // ShareAccess
    packet.extend_from_slice(&[0x01, 0, 0, 0]); // CreateDisposition = FILE_OPEN
                                                // CreateOptions: neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE, so the model's
                                                // answer alone decides which the handle is.
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&120u16.to_le_bytes()); // NameOffset (from header start)
    packet.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes()); // NameLength
    packet.extend_from_slice(&[0; 4]); // CreateContextsOffset
    packet.extend_from_slice(&[0; 4]); // CreateContextsLength
    assert_eq!(packet.len(), 120, "name buffer must start at absolute 120");
    packet.extend_from_slice(&name_utf16);

    nbss(packet)
}

/// Helper: Build an SMB2 READ request for `file_id` (MS-SMB2 2.2.19, body is 49 bytes).
fn build_smb2_read(message_id: u64, file_id: &[u8], length: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(b"\xFESMB");
    packet.extend_from_slice(&[64, 0]);
    packet.extend_from_slice(&[0; 2]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[0x08, 0x00]); // Command = READ
    packet.extend_from_slice(&[1, 0]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&message_id.to_le_bytes());
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[1, 0, 0, 0]);
    packet.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&[0; 16]);

    packet.extend_from_slice(&[49, 0]); // StructureSize
    packet.push(0); // Padding
    packet.push(0); // Flags
    packet.extend_from_slice(&length.to_le_bytes()); // Length (offset 4)
    packet.extend_from_slice(&0u64.to_le_bytes()); // Offset (offset 8)
    packet.extend_from_slice(file_id); // FileId (offset 16, 16 bytes)
    packet.extend_from_slice(&[0; 4]); // MinimumCount
    packet.extend_from_slice(&[0; 4]); // Channel
    packet.extend_from_slice(&[0; 4]); // RemainingBytes
    packet.extend_from_slice(&[0; 2]); // ReadChannelInfoOffset
    packet.extend_from_slice(&[0; 2]); // ReadChannelInfoLength
    packet.push(0); // Buffer
    assert_eq!(packet.len(), 64 + 49);

    nbss(packet)
}

/// Helper: Build an SMB2 WRITE request (MS-SMB2 2.2.21: 48 fixed bytes, then the data).
fn build_smb2_write(message_id: u64, file_id: &[u8], data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(b"\xFESMB");
    packet.extend_from_slice(&[64, 0]);
    packet.extend_from_slice(&[0; 2]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[0x09, 0x00]); // Command = WRITE
    packet.extend_from_slice(&[1, 0]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&message_id.to_le_bytes());
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(&[1, 0, 0, 0]);
    packet.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&[0; 16]);

    packet.extend_from_slice(&[49, 0]); // StructureSize
    packet.extend_from_slice(&112u16.to_le_bytes()); // DataOffset (64 + 48)
    packet.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length (offset 4)
    packet.extend_from_slice(&0u64.to_le_bytes()); // Offset (offset 8)
    packet.extend_from_slice(file_id); // FileId (offset 16)
    packet.extend_from_slice(&[0; 4]); // Channel
    packet.extend_from_slice(&[0; 4]); // RemainingBytes
    packet.extend_from_slice(&[0; 2]); // WriteChannelInfoOffset
    packet.extend_from_slice(&[0; 2]); // WriteChannelInfoLength
    packet.extend_from_slice(&[0; 4]); // Flags
                                       // StructureSize 49 counts the first byte of Buffer, which is the first byte of data:
                                       // DataOffset 112 points here, so no padding byte goes between.
    assert_eq!(packet.len(), 64 + 48);

    packet.extend_from_slice(data);
    nbss(packet)
}

/// Read exactly one SMB2 response message off the socket: one Direct TCP frame, unwrapped.
fn read_smb2_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    read_frame_sync(stream)
}

/// Extract the 16-byte FileId from a CREATE response.
///
/// MS-SMB2 2.2.14: the 89-byte body is StructureSize(2) OplockLevel(1) Flags(1)
/// CreateAction(4) four 8-byte timestamps (32) AllocationSize(8) EndOfFile(8)
/// FileAttributes(4) Reserved2(4) FileId(16) CreateContextsOffset(4)
/// CreateContextsLength(4) Buffer(1), so FileId sits at body offset 64.
fn create_response_file_id(response: &[u8]) -> Vec<u8> {
    assert!(
        response.len() >= 64 + 89,
        "CREATE response too short: {} bytes",
        response.len()
    );
    response[64 + 64..64 + 80].to_vec()
}

/// Extract the FileAttributes field of a CREATE response (body offset 56..60).
fn create_response_file_attributes(response: &[u8]) -> u32 {
    u32::from_le_bytes([
        response[64 + 56],
        response[64 + 57],
        response[64 + 58],
        response[64 + 59],
    ])
}

/// Extract the data buffer of a READ response using its own DataOffset/DataLength.
///
/// MS-SMB2 2.2.20: StructureSize(2) DataOffset(1) Reserved(1) DataLength(4)
/// DataRemaining(4) Reserved2(4). DataOffset is measured from the start of the SMB2
/// header, so reading at it - rather than at a hardcoded position - is what makes this
/// test catch a server whose declared offset disagrees with where it actually put the
/// payload. It did.
fn read_response_payload(response: &[u8]) -> Vec<u8> {
    let data_offset = response[64 + 2] as usize;
    let data_length = u32::from_le_bytes([
        response[64 + 4],
        response[64 + 5],
        response[64 + 6],
        response[64 + 7],
    ]) as usize;
    assert!(
        data_offset + data_length <= response.len(),
        "READ response claims {} bytes at offset {} but is only {} long",
        data_length,
        data_offset,
        response.len()
    );
    response[data_offset..data_offset + data_length].to_vec()
}

/// Drive NEGOTIATE + SESSION_SETUP + TREE_CONNECT so the connection is ready for file
/// operations on tree 1 of session 1, which is what the request builders above address.
fn smb_handshake(stream: &mut TcpStream) -> E2EResult<()> {
    stream.write_all(&build_smb2_negotiate())?;
    stream.flush()?;
    let _ = read_smb2_response(stream)?;

    stream.write_all(&build_smb2_session_setup())?;
    stream.flush()?;
    let response = read_smb2_response(stream)?;
    assert_eq!(
        parse_smb2_status(&response),
        Some(0),
        "SESSION_SETUP must succeed for the rest of the flow"
    );

    stream.write_all(&nbss(tree_connect(2, 1, "\\\\127.0.0.1\\share")))?;
    stream.flush()?;
    let response = read_smb2_response(stream)?;
    assert_eq!(
        parse_smb2_status(&response),
        Some(0),
        "TREE_CONNECT must succeed"
    );
    assert_eq!(
        u32::from_le_bytes([response[36], response[37], response[38], response[39]]),
        1,
        "the first tree on the connection is tree 1"
    );
    Ok(())
}

/// Test: a binary file survives CREATE -> READ intact.
///
/// The model answers `smb_read_file` with base64 and `encoding: "base64"`; the bytes that
/// come back in the READ response body must be the decoded bytes, not the base64 text.
/// The payload is deliberately non-printable and not valid UTF-8, so `as_bytes()` on the
/// documented base64 - the original defect - produces a visibly different, longer buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_read_binary_content_is_decoded() -> E2EResult<()> {
    println!("\n=== Test: SMB READ decodes base64 content ===");

    // 0xff/0xfe cannot appear in UTF-8; 0xc3 0x28 is an invalid two-byte sequence.
    const BINARY: &[u8] = &[0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28];
    // Standard base64 of the above.
    const BINARY_B64: &str = "AP/+AYB/wyg=";

    assert!(
        std::str::from_utf8(&BINARY.to_vec()).is_err(),
        "the payload must not be valid UTF-8, or the test proves nothing"
    );

    let prompt = "Start an SMB file server via smb serving one binary file.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            // Asserts the CREATE path parser too: the mock only matches if the server
            // located the UTF-16LE name through NameOffset/NameLength.
            .and_event_data_contains("path", "/documents/binary.dat")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/documents/binary.dat"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "read")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "smb_read_file",
                    "path": "/documents/binary.dat",
                    "content": BINARY_B64,
                    "encoding": "base64"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(2, "/documents/binary.dat"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    assert_eq!(parse_smb2_status(&create_response), Some(0));
    assert_eq!(
        create_response_file_attributes(&create_response) & 0x10,
        0,
        "smb_create_file must NOT set FILE_ATTRIBUTE_DIRECTORY"
    );
    let file_id = create_response_file_id(&create_response);

    stream.write_all(&build_smb2_read(3, &file_id, 4096))?;
    stream.flush()?;
    let read_response = read_smb2_response(&mut stream)?;
    assert_eq!(parse_smb2_status(&read_response), Some(0));

    let payload = read_response_payload(&read_response);
    assert_eq!(
        payload,
        BINARY.to_vec(),
        "READ must deliver the decoded bytes ({}), not the base64 text ({:?})",
        BINARY.len(),
        String::from_utf8_lossy(&payload)
    );
    println!("  [TEST] ✓ {} binary bytes returned intact", payload.len());

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Test: text content still works without an `encoding` field, and a directory handle
/// carries FILE_ATTRIBUTE_DIRECTORY and cannot be READ.
///
/// `utf8` is the default precisely so that every pre-existing prompt keeps working; a
/// string that happens to look like base64 must be delivered literally when unmarked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_default_encoding_is_literal_text() -> E2EResult<()> {
    println!("\n=== Test: SMB default encoding is literal UTF-8 ===");

    // Valid base64 *and* perfectly ordinary text. Without an explicit encoding the
    // server must not guess - it must deliver these 8 characters.
    const AMBIGUOUS: &str = "SGVsbG8=";

    let prompt = "Start an SMB file server via smb.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            // One rule for both opens, branching on the path: /documents is a directory,
            // the file inside it is a file.
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions_from_event(|event| {
                let path = event["path"].as_str().unwrap_or_default().to_string();
                if path == "/documents" {
                    serde_json::json!([{"type": "smb_create_directory", "path": path}])
                } else {
                    serde_json::json!([{"type": "smb_create_file", "path": path}])
                }
            })
            .expect_calls(2)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "read")
            .and_event_data_contains("path", "/documents/b64.txt")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_read_file", "path": "/documents/b64.txt", "content": AMBIGUOUS}
            ]))
            // Exactly one: the READ of the directory handle is refused without asking.
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(3, "/documents"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    assert_eq!(
        create_response_file_attributes(&create_response) & 0x10,
        0x10,
        "smb_create_directory must set FILE_ATTRIBUTE_DIRECTORY (0x10) in the CREATE response"
    );
    let dir_id = create_response_file_id(&create_response);

    // MS-SMB2 3.3.5.12: a READ on a directory fails with STATUS_INVALID_DEVICE_REQUEST.
    stream.write_all(&build_smb2_read(4, &dir_id, 4096))?;
    stream.flush()?;
    let refused = read_smb2_response(&mut stream)?;
    assert_eq!(
        parse_smb2_status(&refused),
        Some(0xC000_0010),
        "READ on a directory handle must answer STATUS_INVALID_DEVICE_REQUEST"
    );

    stream.write_all(&build_smb2_create(5, "/documents/b64.txt"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    assert_eq!(parse_smb2_status(&create_response), Some(0));
    let file_id = create_response_file_id(&create_response);

    stream.write_all(&build_smb2_read(6, &file_id, 4096))?;
    stream.flush()?;
    let read_response = read_smb2_response(&mut stream)?;

    let payload = read_response_payload(&read_response);
    assert_eq!(
        payload,
        AMBIGUOUS.as_bytes().to_vec(),
        "without an 'encoding' field the content must be delivered literally, not base64-decoded"
    );
    println!("  [TEST] ✓ ambiguous string delivered literally");

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Test: a WRITE is refused unless the model returns `smb_write_file`.
///
/// Silence from the model must not read as approval (the fail-open pattern the project
/// treats as its most dangerous). The same flow also asserts the inbound half of the
/// encoding pair: a non-printable payload reaches the model base64-encoded rather than
/// mangled by `from_utf8_lossy`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_write_requires_model_approval() -> E2EResult<()> {
    println!("\n=== Test: SMB WRITE is refused without smb_write_file ===");

    // Bytes 0x00 and 0xff would both become U+FFFD under from_utf8_lossy.
    const BINARY: &[u8] = &[0x00, 0xff, 0x41, 0x42, 0xfe];
    const BINARY_B64: &str = "AP9BQv4=";

    let prompt = "Start an SMB file server via smb that rejects all writes.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/documents/out.dat"}
            ]))
            .expect_calls(1)
            .and()
            // Matching on the base64 form asserts the inbound encoding: the written
            // bytes must reach the model losslessly.
            .on_event("smb_operation")
            .and_event_data_contains("operation", "write")
            .and_event_data_contains("data", BINARY_B64)
            .and_event_data_contains("encoding", "base64")
            // Deliberately return no smb_write_file: the server must refuse.
            .respond_with_actions(serde_json::json!([
                {"type": "show_message", "message": "writes are not allowed"}
            ]))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(2, "/documents/out.dat"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    let file_id = create_response_file_id(&create_response);

    stream.write_all(&build_smb2_write(3, &file_id, BINARY))?;
    stream.flush()?;
    let write_response = read_smb2_response(&mut stream)?;

    assert_eq!(
        parse_smb2_status(&write_response),
        Some(0xC0000022),
        "an unapproved WRITE must answer STATUS_ACCESS_DENIED, not STATUS_SUCCESS"
    );
    println!("  [TEST] ✓ unapproved write refused with STATUS_ACCESS_DENIED");

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Test: an approved WRITE succeeds and reports the byte count the model chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_write_approved_reports_byte_count() -> E2EResult<()> {
    println!("\n=== Test: SMB WRITE approved ===");

    const PAYLOAD: &[u8] = b"hello smb write";

    let prompt = "Start an SMB file server via smb that accepts writes.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/documents/out.txt"}
            ]))
            .expect_calls(1)
            .and()
            // Printable ASCII must arrive as text, not base64.
            .on_event("smb_operation")
            .and_event_data_contains("operation", "write")
            .and_event_data_contains("data", "hello smb write")
            .and_event_data_contains("encoding", "utf8")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_write_file", "path": "/documents/out.txt"}
            ]))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    smb_handshake(&mut stream)?;

    stream.write_all(&build_smb2_create(2, "/documents/out.txt"))?;
    stream.flush()?;
    let create_response = read_smb2_response(&mut stream)?;
    let file_id = create_response_file_id(&create_response);

    stream.write_all(&build_smb2_write(3, &file_id, PAYLOAD))?;
    stream.flush()?;
    let write_response = read_smb2_response(&mut stream)?;

    assert_eq!(parse_smb2_status(&write_response), Some(0));
    let count = u32::from_le_bytes([
        write_response[64 + 4],
        write_response[64 + 5],
        write_response[64 + 6],
        write_response[64 + 7],
    ]);
    assert_eq!(
        count as usize,
        PAYLOAD.len(),
        "WRITE response must report every byte the client sent as written"
    );
    println!("  [TEST] ✓ {} bytes acknowledged", count);

    drop(stream);
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A file operation on a connection that never authenticated must be refused.
///
/// `SmbConnectionState.sessions` was written by the successful SESSION_SETUP path and then
/// read by nothing but a log line, so the model's authentication decision governed exactly
/// one response and nothing after it. A peer could open a socket and send CREATE straight
/// away — no NEGOTIATE, no SESSION_SETUP, no LLM call about admission at all — and get
/// STATUS_SUCCESS and a live file handle back. A peer whose login the model had just
/// *denied* could send CREATE on the same connection and be served identically.
///
/// This connects and sends CREATE as its first byte. The mock declares the create rule with
/// `expect_calls(0)`, so the test fails both ways: if the wire status is not
/// STATUS_USER_SESSION_DELETED, and if the server consulted the model about a `create` it
/// should never have reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_file_operation_without_a_session_is_refused() -> E2EResult<()> {
    println!("\n=== Test: SMB CREATE before SESSION_SETUP is refused ===");

    let prompt = "Start an SMB file server via smb.";

    let config = crate::helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/secret.txt"}
            ]))
            // The gate is upstream of the LLM call, so this rule must never fire. If it
            // does, the server asked the model to admit a handle on an unauthenticated
            // connection — which is the defect, whatever the model then answered.
            .expect_calls(0)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": prompt}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // No handshake. Straight to a file operation.
    stream.write_all(&build_smb2_create(1, "/secret.txt"))?;
    stream.flush()?;
    let response = read_smb2_response(&mut stream)?;

    assert_eq!(
        parse_smb2_status(&response),
        Some(0xC000_0203),
        "CREATE on a connection with no session must answer STATUS_USER_SESSION_DELETED, \
         not a file handle"
    );

    // And no handle may come back with it.
    assert!(
        response.len() < 64 + 89,
        "the refusal carried a CREATE response body ({} bytes); a refused open must not \
         hand out a file handle",
        response.len()
    );

    println!("  [TEST] ✓ unauthenticated CREATE refused with STATUS_USER_SESSION_DELETED");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The payload codec is a bijection: whatever the server shows the model on a write,
/// feeding it straight back as `smb_read_file` content reproduces the exact bytes.
#[test]
fn smb_payload_encoding_round_trips() {
    use netget::server::smb::actions::{decode_smb_payload, encode_smb_payload};

    for original in [
        b"Hello, SMB!".to_vec(),
        vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28],
        (0u8..=255).collect::<Vec<u8>>(),
        Vec::new(),
    ] {
        let (payload, encoding) = encode_smb_payload(&original);
        let decoded = decode_smb_payload(&payload, Some(encoding))
            .unwrap_or_else(|e| panic!("re-decoding {encoding} payload failed: {e}"));
        assert_eq!(
            decoded, original,
            "round trip through {encoding} lost bytes"
        );
    }

    // Ambiguous string: the declared encoding decides, never a guess.
    assert_eq!(
        decode_smb_payload("SGVsbG8=", None).unwrap(),
        b"SGVsbG8=".to_vec()
    );
    assert_eq!(
        decode_smb_payload("SGVsbG8=", Some("base64")).unwrap(),
        b"Hello".to_vec()
    );
    assert_eq!(
        decode_smb_payload("48656c6c6f", Some("hex")).unwrap(),
        b"Hello".to_vec()
    );
    assert!(decode_smb_payload("!!!not base64!!!", Some("base64")).is_err());
    assert!(decode_smb_payload("x", Some("rot13")).is_err());
}

/// Every action the model is offered on `smb_operation` must have an executor branch,
/// and every action in `get_sync_actions()` must be offered.
///
/// Five of ten sync actions used to be routed nowhere: the model could emit
/// `smb_delete_file`, `smb_create_directory` and three others and nothing whatsoever
/// happened. Deletes were removed (SMB2 deletes via SET_INFO, which this server does not
/// implement); the rest are now routed.
#[test]
fn smb_declared_actions_are_all_routed() {
    use netget::llm::actions::protocol_trait::Protocol;
    use netget::server::smb::actions::{SmbProtocol, SMB_OPERATION_EVENT};

    let protocol = SmbProtocol::new();
    let sync: Vec<String> = protocol
        .get_sync_actions()
        .iter()
        .map(|a| a.name.clone())
        .collect();
    let on_event: Vec<String> = SMB_OPERATION_EVENT
        .actions
        .iter()
        .map(|a| a.name.clone())
        .collect();

    for name in &sync {
        assert!(
            on_event.contains(name),
            "{name} is in get_sync_actions() but not attached to smb_operation, so call_llm \
             never offers it to the model"
        );
    }
    for name in &on_event {
        assert!(
            sync.contains(name),
            "{name} is offered on smb_operation but is not a declared sync action"
        );
    }

    for removed in ["smb_delete_file", "smb_delete_directory"] {
        assert!(
            !sync.contains(&removed.to_string()),
            "{removed} cannot be routed - SMB2 deletes via SET_INFO, which is not implemented"
        );
    }

    // The exact set the executor in src/server/smb/mod.rs handles.
    let mut expected = vec![
        "smb_auth_success",
        "smb_auth_deny",
        "smb_list_directory",
        "smb_read_file",
        "smb_write_file",
        "smb_get_file_info",
        "smb_create_file",
        "smb_create_directory",
    ];
    expected.sort_unstable();
    let mut actual: Vec<&str> = sync.iter().map(|s| s.as_str()).collect();
    actual.sort_unstable();
    assert_eq!(actual, expected);
}
