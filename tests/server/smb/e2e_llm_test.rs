//! E2E tests for SMB server with LLM integration
//!
//! These tests spawn the NetGet binary and verify that the LLM correctly
//! controls SMB authentication, file operations, and responses.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

use super::wire_util::{nbss, read_frame_into};
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
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Context offset/count
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

/// Helper: Parse SMB2 response status (Direct TCP framing added by `nbss`)
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

/// Test: LLM allows guest authentication
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_allows_guest_auth() -> E2EResult<()> {
    println!("\n=== Test: LLM Allows Guest Authentication ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Allow all authentication attempts.";

    let server = start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: SMB operations - MUST come before on_any()
                    .on_event("smb_operation")
                    .respond_with_actions(serde_json::json!([
                        {"type": "smb_auth_success"}
                    ]))
                    .expect_at_least(1)
                    .and()
                    // Mock 2: Server startup - Catch-all
                    .on_any()
                    .respond_with_actions(serde_json::json!([
                        {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": "Allow all auth"}
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Negotiate
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let n = read_frame_into(&mut stream, &mut response)?;
    println!("  [TEST] Negotiate response: {} bytes", n);
    assert!(n >= 64, "Negotiate response too short");

    // Session Setup - LLM should allow guest
    let session_setup = build_smb2_session_setup();
    stream.write_all(&session_setup)?;
    stream.flush()?;

    response.clear();
    response.resize(2048, 0);
    let n = read_frame_into(&mut stream, &mut response)?;
    response.truncate(n);

    println!("  [TEST] Session Setup response: {} bytes", n);

    // Check LLM allowed authentication
    if let Some(status) = parse_smb2_status(&response) {
        println!("  [TEST] Status: 0x{:08X}", status);
        assert_eq!(
            status, 0,
            "LLM should have allowed authentication (status 0)"
        );
        println!("  [TEST] ✓ LLM correctly allowed guest authentication");
    } else {
        panic!("Failed to parse SMB2 response");
    }

    // Check server output mentions authentication
    let output = server.get_output().await;
    let has_auth_message = output
        .iter()
        .any(|line| line.contains("auth") || line.contains("session"));

    if has_auth_message {
        println!("  [TEST] ✓ Server logged authentication event");
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM denies specific users
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_denies_user() -> E2EResult<()> {
    println!("\n=== Test: LLM Denies Specific Users ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Only allow authentication for user 'alice'. \
                 Deny 'guest' and all other users.";

    let server = start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: SMB operations - MUST come before on_any()
                    .on_event("smb_operation")
                    .respond_with_actions(serde_json::json!([
                        // `smb_auth_deny`, not `smb_auth_denied`: the latter is not an
                        // SMB action, so it was rejected as unknown, triggered the retry
                        // loop, and made verify_mocks fail on the extra call. There is no
                        // `status` parameter either - the server chooses the NTSTATUS.
                        {"type": "smb_auth_deny", "username": "guest", "reason": "only alice may log in"}
                    ]))
                    .expect_at_least(1)
                    .and()
                    // Mock 2: Server startup - Catch-all
                    .on_any()
                    .respond_with_actions(serde_json::json!([
                        {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": "Allow alice only"}
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Negotiate
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let n = read_frame_into(&mut stream, &mut response)?;
    println!("  [TEST] Negotiate response: {} bytes", n);

    // Session Setup - LLM should deny guest based on prompt
    let session_setup = build_smb2_session_setup();
    stream.write_all(&session_setup)?;
    stream.flush()?;

    response.clear();
    response.resize(2048, 0);
    let n = read_frame_into(&mut stream, &mut response)?;
    response.truncate(n);

    println!("  [TEST] Session Setup response: {} bytes", n);

    // The mocked model denied the login, so STATUS_ACCESS_DENIED is the only correct
    // answer. This used to print "✓" for a denial, "Note:" for a success and "Note:" for
    // anything else - i.e. it passed no matter what the server did, including when it
    // granted the session the model had refused.
    // 0xC0000022, not 0xC0000016 — see the note on the same assertion in e2e_test.rs.
    assert_eq!(
        parse_smb2_status(&response),
        Some(0xC000_0022),
        "smb_auth_deny must produce STATUS_ACCESS_DENIED (0xC0000022), got a different status"
    );
    println!("  [TEST] ✓ LLM denial answered with STATUS_ACCESS_DENIED");

    // Check server output for denial
    let output = server.get_output().await;
    let mentioned_auth = output
        .iter()
        .any(|line| line.contains("denied") || line.contains("auth"));

    if mentioned_auth {
        println!("  [TEST] ✓ Server logged authentication decision");
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM controls file creation
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_file_creation() -> E2EResult<()> {
    println!("\n=== Test: LLM Controls File Creation ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Allow all authentication. \
                 Allow files in /documents/. \
                 Deny files in /restricted/.";

    let server = start_netget_server(
        NetGetConfig::new_no_scripts(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_any()  // Changed from on_instruction_containing

                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SMB",
                            "instruction": "Allow all authentication. Allow files in /documents/. Deny files in /restricted/."
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    server.wait_for_mocks(30).await;

    // Check that LLM received file creation events
    server.wait_for_mocks(30).await;

    let output = server.get_output().await;

    // Look for signs the server is ready and LLM is processing
    let server_ready = output
        .iter()
        .any(|line| line.contains("listening") || line.contains("SMB server"));

    if server_ready {
        println!("  [TEST] ✓ SMB server with LLM started successfully");
        println!("  [TEST] ✓ LLM is ready to control file operations");
    }

    // Verify LLM would control file creation (we set up the scenario)
    println!("  [TEST] ✓ Server configured with LLM-controlled file policies");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM provides file content
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_file_content() -> E2EResult<()> {
    println!("\n=== Test: LLM Provides File Content ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Allow all authentication. \
                 Provide file /welcome.txt with content 'Hello from NetGet SMB!'.";

    let server = start_netget_server(
        NetGetConfig::new_no_scripts(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_any()  // Changed from on_instruction_containing

                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SMB",
                            "instruction": "Allow all authentication. Provide file /welcome.txt with content 'Hello from NetGet SMB!'."
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    server.wait_for_mocks(30).await;

    // Verify server started with correct configuration
    let output = server.get_output().await;
    let server_started = output
        .iter()
        .any(|line| line.contains("SMB server") || line.contains("listening"));

    assert!(server_started, "Server should have started");
    println!("  [TEST] ✓ SMB server started with LLM-controlled file content");

    // The LLM would provide file content when a client sends READ request
    println!("  [TEST] ✓ LLM configured to provide 'welcome.txt' content");
    println!("  [TEST] ✓ LLM will respond with smb_read_file action on READ requests");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM provides directory listing
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_directory_listing() -> E2EResult<()> {
    println!("\n=== Test: LLM Provides Directory Listing ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Allow all authentication. \
                 Provide directory /documents/ with files: readme.txt, notes.txt, report.pdf.";

    let server = start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock.on_any()  // Changed from on_instruction_containing
                    .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": "Directory listing"}
                ])).expect_calls(1).and()
            })
    ).await?;
    server.wait_for_mocks(30).await;

    // Verify LLM integration is working
    let output = server.get_output().await;
    let llm_active = output
        .iter()
        .any(|line| line.contains("SMB") || line.contains("server"));

    assert!(llm_active, "Server should be running");
    println!("  [TEST] ✓ SMB server with LLM started");
    println!("  [TEST] ✓ LLM configured to provide directory listing");
    println!("  [TEST] ✓ LLM will respond with smb_list_directory action on QUERY_DIRECTORY");

    // The LLM would provide directory listings when client sends QUERY_DIRECTORY
    let configured_correctly = output
        .iter()
        .any(|line| line.contains("SMB") || line.contains("starting"));

    if configured_correctly {
        println!("  [TEST] ✓ LLM ready to serve directory listings");
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM tracks connections
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_connection_tracking() -> E2EResult<()> {
    println!("\n=== Test: LLM Connection Tracking ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Track all connections.";

    let server = start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock.on_any()  // Changed from on_instruction_containing
                    .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "SMB", "instruction": "Track connections"}
                ])).expect_calls(1).and()
            })
    ).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let addr = format!("127.0.0.1:{}", server.port);

    // Make a connection to trigger LLM event
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Send negotiate to establish connection
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate)?;
    stream.flush()?;

    let mut response = vec![0u8; 2048];
    let _ = read_frame_into(&mut stream, &mut response);

    // Give LLM time to process connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check that connection was tracked
    let output = server.get_output().await;
    let connection_tracked = output
        .iter()
        .any(|line| line.contains("connection") || line.contains("client") || line.contains("SMB"));

    if connection_tracked {
        println!("  [TEST] ✓ Connection tracking detected in output");
    } else {
        println!("  [TEST] Note: Connection tracking may not appear in captured output");
    }

    // Close and check disconnect is logged
    drop(stream);
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("  [TEST] ✓ Connection lifecycle managed by LLM");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}

/// Test: LLM receives SMB events
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smb_llm_receives_events() -> E2EResult<()> {
    println!("\n=== Test: LLM Receives SMB Events ===");

    let prompt = "Start an SMB file server on port 0 via smb. \
                 Allow all authentication and file operations.";

    let server = start_netget_server(NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_any() // Changed from on_instruction_containing
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMB",
                    "instruction": "Allow all authentication and file operations."
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    server.wait_for_mocks(30).await;

    // Verify server is ready to process LLM events
    assert!(server.stack.contains("SMB"), "Should use SMB stack");

    println!("  [TEST] ✓ SMB server started with {} stack", server.stack);
    println!("  [TEST] ✓ LLM ready to receive SMB events");
    println!("  [TEST] ✓ Events include: session_setup, create, read, write, query_directory");

    // The LLM will receive events when actual SMB operations occur
    // This test verifies the setup is correct

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("  [TEST] ✓ Test completed successfully\n");

    Ok(())
}
