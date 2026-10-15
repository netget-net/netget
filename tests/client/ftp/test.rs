//! End-to-end FTP client tests for NetGet
//!
//! These tests verify that the FTP client can connect to FTP servers
//! and perform LLM-controlled FTP operations.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Test FTP client connection to a local FTP server
/// LLM calls: 3 (server startup, client startup, client connected event)
#[tokio::test]
async fn test_ftp_client_connect_to_server() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP Client Connection to Server ===");

    // Start an FTP server first with mocks
    let server_config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via FTP. Send greeting '220 FTP Server Ready'. \
        When client sends USER, respond with '331 Password required'. \
        When client sends PASS, respond with '230 Logged in'.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen on port")
            .and_instruction_containing("FTP")
            .and_instruction_containing("greeting")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": "FTP server - send 220 greeting on connect, handle USER/PASS"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Server receives CONNECTION_ESTABLISHED event
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 220,
                    "message": "FTP Server Ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Server receives USER command
            .on_event("ftp_command")
            .and_event_data_contains("command", "USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 331,
                    "message": "Password required"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("FTP Server started on port {}", server.port);

    // Give server time to start listening
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now start the FTP client that connects to this server
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via FTP. Login as anonymous.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock: Client startup (user command)
            .on_instruction_containing("Connect to")
            .and_instruction_containing("FTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", server.port),
                    "protocol": "FTP",
                    "instruction": "Connect and login as anonymous"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Client receives greeting (ftp_response event with code 220)
            .on_event("ftp_response")
            .and_event_data_contains("response_code", "220")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_command",
                    "command": "USER anonymous"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(client_config).await?;
    println!("FTP Client started");

    // Give time for client to connect and exchange greeting
    client.wait_for_mocks(30).await;

    println!("FTP client connected to server successfully");

    // Cleanup
    client.verify_mocks().await?;
    client.stop().await?;
    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}
