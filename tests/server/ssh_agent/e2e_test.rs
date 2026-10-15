//! E2E tests for SSH Agent server with Ollama mocks
//!
//! These tests verify SSH Agent protocol implementation with mock LLM responses.
//! Unlike most NetGet e2e tests, SSH Agent requires Unix domain sockets.

#![cfg(unix)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::super::helpers::{self, E2EResult, NetGetConfig};

/// Helper to construct SSH Agent REQUEST_IDENTITIES message (type 11)
fn build_request_identities() -> Vec<u8> {
    let mut msg = Vec::new();
    // Length: 1 byte (just the message type)
    msg.extend_from_slice(&1u32.to_be_bytes());
    // Message type: SSH_AGENTC_REQUEST_IDENTITIES (11)
    msg.push(11);
    msg
}

/// Helper to construct SSH Agent SIGN_REQUEST message (type 13)
fn build_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut msg = Vec::new();

    // Calculate total length: 1 (type) + 4 (key len) + key + 4 (data len) + data + 4 (flags)
    let total_len = 1 + 4 + key_blob.len() + 4 + data.len() + 4;

    msg.extend_from_slice(&(total_len as u32).to_be_bytes());
    msg.push(13); // Type: SIGN_REQUEST
    msg.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
    msg.extend_from_slice(key_blob);
    msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
    msg.extend_from_slice(data);
    msg.extend_from_slice(&flags.to_be_bytes());

    msg
}

/// Helper to construct SSH Agent ADD_IDENTITY message (type 17)
fn build_add_identity_ed25519(public_key: &[u8], private_key: &[u8], comment: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    let key_type = b"ssh-ed25519";

    // Calculate length
    let total_len = 1 // type
        + 4 + key_type.len() // key type string
        + 4 + public_key.len() // public key
        + 4 + private_key.len() // private key
        + 4 + comment.len(); // comment

    msg.extend_from_slice(&(total_len as u32).to_be_bytes());
    msg.push(17); // Type: ADD_IDENTITY

    // Key type
    msg.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    msg.extend_from_slice(key_type);

    // Public key
    msg.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    msg.extend_from_slice(public_key);

    // Private key
    msg.extend_from_slice(&(private_key.len() as u32).to_be_bytes());
    msg.extend_from_slice(private_key);

    // Comment
    msg.extend_from_slice(&(comment.len() as u32).to_be_bytes());
    msg.extend_from_slice(comment.as_bytes());

    msg
}

/// Wait for the server to bind its Unix socket, then connect.
///
/// This is a hard failure, not a note. Every test in this file used to wrap its whole body in
/// `if socket_path.exists() { .. } else { println!("socket file not created") }`, so a server
/// that never bound produced a green test which had asserted nothing at all about the
/// protocol. The same shape swallowed connect errors, read errors and timeouts below.
async fn connect_to_agent(path: &std::path::Path) -> E2EResult<UnixStream> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut last: Option<String> = None;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            match UnixStream::connect(path).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e.to_string()),
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "SSH Agent server never accepted a connection on {:?} within 20s (last error: {})",
        path,
        last.as_deref().unwrap_or("socket file never appeared")
    )
    .into())
}

/// Send one agent message and return the reply.
///
/// Silence is a failure. The agent protocol is strictly request/response and the client blocks
/// on the read, so "connection closed without response" and "response timeout" are defects to
/// be reported, not conditions to print and step past.
async fn agent_exchange(stream: &mut UnixStream, request: &[u8]) -> E2EResult<Vec<u8>> {
    stream.write_all(request).await?;
    stream.flush().await?;

    let mut response = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut response))
        .await
        .map_err(|_| "timed out waiting for an SSH Agent reply")??;
    if n == 0 {
        return Err("SSH Agent closed the connection without replying".into());
    }
    if n < 5 {
        return Err(format!("SSH Agent reply is {} bytes; the header alone is 5", n).into());
    }
    response.truncate(n);
    Ok(response)
}

/// Number of keys in an IDENTITIES_ANSWER.
fn identities_count(response: &[u8]) -> u32 {
    assert!(
        response.len() >= 9,
        "IDENTITIES_ANSWER is {} bytes; it needs 5 for the header and 4 for the key count",
        response.len()
    );
    u32::from_be_bytes([response[5], response[6], response[7], response[8]])
}

/// Parse SSH Agent message header (length and type)
fn parse_message_header(data: &[u8]) -> Option<(u32, u8)> {
    if data.len() < 5 {
        return None;
    }

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let msg_type = data[4];

    Some((length, msg_type))
}

/// Test SSH Agent REQUEST_IDENTITIES with mock LLM response
#[tokio::test]
async fn test_ssh_agent_request_identities_with_mocks() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Agent REQUEST_IDENTITIES with Mocks ===");

    // Create temporary socket path
    let socket_path =
        std::env::temp_dir().join(format!("netget-test-agent-{}.sock", std::process::id()));

    // Ensure socket doesn't exist
    let _ = std::fs::remove_file(&socket_path);

    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let prompt = format!(
        "Start SSH Agent server on {}. Handle REQUEST_IDENTITIES.",
        socket_path_str
    );

    let config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Start SSH Agent server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH Agent",
                    "instruction": "SSH Agent server",
                    "startup_params": {
                        "socket_path": socket_path_str
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Connection opened (no action needed)
            .on_event("ssh_agent_connection_opened")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // Mock 3: REQUEST_IDENTITIES event
            .on_event("ssh_agent_request_identities")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_identities_list",
                    "identities": [
                        {
                            "key_type": "ssh-ed25519",
                            "public_key_blob_hex": "0000000b7373682d6564323535313900000020abcd1234",
                            "comment": "test-key"
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;

    println!("SSH Agent server started on socket: {}", socket_path_str);

    let mut stream = connect_to_agent(&socket_path).await?;
    println!("OK Connected to SSH Agent server");

    // Let the connection_opened round-trip finish. Data arriving mid-call is queued by the
    // per-connection state machine, so this is politeness rather than correctness.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = agent_exchange(&mut stream, &build_request_identities()).await?;
    let (length, msg_type) =
        parse_message_header(&response).expect("Failed to parse response header");
    println!("Received response: length={}, type={}", length, msg_type);

    assert_eq!(
        msg_type, 12,
        "Expected IDENTITIES_ANSWER (12), got {}",
        msg_type
    );
    assert_eq!(identities_count(&response), 1, "Expected 1 key from mock");
    println!("OK REQUEST_IDENTITIES test passed");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test SSH Agent SIGN_REQUEST with mock LLM response
#[tokio::test]
async fn test_ssh_agent_sign_request_with_mocks() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Agent SIGN_REQUEST with Mocks ===");

    let socket_path = std::env::temp_dir().join(format!(
        "netget-test-agent-sign-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);

    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let prompt = format!(
        "Start SSH Agent server on {}. Handle SIGN_REQUEST.",
        socket_path_str
    );

    let config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Start SSH Agent server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH Agent",
                    "instruction": "SSH Agent with signing",
                    "startup_params": {
                        "socket_path": socket_path_str
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Connection opened (no action needed, just acknowledge)
            .on_event("ssh_agent_connection_opened")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // Mock 3: SIGN_REQUEST event
            .on_event("ssh_agent_sign_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_sign_response",
                    "signature_hex": "0000000b7373682d65643235353139000000400a1b2c3d4e5f"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;

    println!("SSH Agent server started on socket: {}", socket_path_str);

    let mut stream = connect_to_agent(&socket_path).await?;
    println!("OK Connected to SSH Agent server");

    // Let the connection_opened round-trip finish. Data arriving mid-call is queued by the
    // per-connection state machine, so this is politeness rather than correctness.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let key_blob = b"test_public_key";
    let data_to_sign = b"test_data";
    let response =
        agent_exchange(&mut stream, &build_sign_request(key_blob, data_to_sign, 0)).await?;

    let (length, msg_type) =
        parse_message_header(&response).expect("Failed to parse response header");
    println!("Received response: length={}, type={}", length, msg_type);
    assert_eq!(
        msg_type, 14,
        "Expected SIGN_RESPONSE (14), got {}",
        msg_type
    );
    println!("OK SIGN_REQUEST test passed");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test SSH Agent ADD_IDENTITY with mock LLM response
#[tokio::test]
async fn test_ssh_agent_add_identity_with_mocks() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Agent ADD_IDENTITY with Mocks ===");

    let socket_path =
        std::env::temp_dir().join(format!("netget-test-agent-add-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let prompt = format!(
        "Start SSH Agent server on {}. Accept keys with ADD_IDENTITY.",
        socket_path_str
    );

    let config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Start SSH Agent server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH Agent",
                    "instruction": "SSH Agent accepting keys",
                    "startup_params": {
                        "socket_path": socket_path_str
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Connection opened (no action needed)
            .on_event("ssh_agent_connection_opened")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // Mock 3: ADD_IDENTITY event
            .on_event("ssh_agent_add_identity")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_success"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;

    println!("SSH Agent server started on socket: {}", socket_path_str);

    let mut stream = connect_to_agent(&socket_path).await?;
    println!("OK Connected to SSH Agent server");

    // Let the connection_opened round-trip finish. Data arriving mid-call is queued by the
    // per-connection state machine, so this is politeness rather than correctness.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let public_key = b"test_public_key_32_bytes_here!!";
    let private_key = b"test_private_key_64_bytes_here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    let response = agent_exchange(
        &mut stream,
        &build_add_identity_ed25519(public_key, private_key, "test-key"),
    )
    .await?;

    let (length, msg_type) =
        parse_message_header(&response).expect("Failed to parse response header");
    println!("Received response: length={}, type={}", length, msg_type);
    assert_eq!(msg_type, 6, "Expected SUCCESS (6), got {}", msg_type);
    println!("OK ADD_IDENTITY test passed");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test SSH Agent with multiple operations in sequence
#[tokio::test]
async fn test_ssh_agent_multiple_operations_with_mocks() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Agent Multiple Operations with Mocks ===");

    let socket_path = std::env::temp_dir().join(format!(
        "netget-test-agent-multi-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);

    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let prompt = format!(
        "Start SSH Agent server on {}. Handle all operations.",
        socket_path_str
    );

    let config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Start SSH Agent server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH Agent",
                    "instruction": "SSH Agent multi-operation server",
                    "startup_params": {
                        "socket_path": socket_path_str
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Connection opened (no action needed)
            .on_event("ssh_agent_connection_opened")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // Mock 3: ADD_IDENTITY
            .on_event("ssh_agent_add_identity")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_success"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: REQUEST_IDENTITIES (both calls - returns 1 key for both)
            .on_event("ssh_agent_request_identities")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_identities_list",
                    "identities": [
                        {
                            "key_type": "ssh-ed25519",
                            "public_key_blob_hex": "0000000b7373682d6564323535313900000020abcd1234",
                            "comment": "added-key"
                        }
                    ]
                }
            ]))
            .expect_calls(2)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;

    println!("SSH Agent server started on socket: {}", socket_path_str);

    let mut stream = connect_to_agent(&socket_path).await?;
    println!("OK Connected to SSH Agent server");

    // Let the connection_opened round-trip finish. Data arriving mid-call is queued by the
    // per-connection state machine, so this is politeness rather than correctness.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Operation 1: REQUEST_IDENTITIES
    println!("Operation 1: REQUEST_IDENTITIES");
    let response = agent_exchange(&mut stream, &build_request_identities()).await?;
    assert_eq!(
        parse_message_header(&response).expect("header").1,
        12,
        "Expected IDENTITIES_ANSWER"
    );
    println!("  OK got {} keys", identities_count(&response));

    // Operation 2: ADD_IDENTITY
    println!("Operation 2: ADD_IDENTITY");
    let public_key = b"test_public_key_32_bytes_here!!";
    let private_key = b"test_private_key_64_bytes_here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    let response = agent_exchange(
        &mut stream,
        &build_add_identity_ed25519(public_key, private_key, "added-key"),
    )
    .await?;
    assert_eq!(
        parse_message_header(&response).expect("header").1,
        6,
        "Expected SUCCESS"
    );

    // Operation 3: REQUEST_IDENTITIES again. The mock is stateless, so this asserts the
    // server still answers correctly on a reused connection rather than that the key stuck.
    println!("Operation 3: REQUEST_IDENTITIES");
    let response = agent_exchange(&mut stream, &build_request_identities()).await?;
    assert_eq!(
        parse_message_header(&response).expect("header").1,
        12,
        "Expected IDENTITIES_ANSWER"
    );
    assert_eq!(identities_count(&response), 1, "Expected 1 key");

    println!("OK All operations completed");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// An agent request the model does not answer must be REFUSED, not ignored.
///
/// This is the SSH-agent shape of the OAuth2 failure mode. Before the fix, an `Ok` LLM result
/// carrying no usable action fell out of the loop having written nothing: the client sat on a
/// read that would never complete, and an operator saw a hung agent rather than a denial. The
/// LLM-error path already sent SSH_AGENT_FAILURE, so silence and refusal were reached by
/// different routes and only one of them answered.
///
/// The mock returns an empty action array — the exact input that became an approval in
/// OAuth2 — and the test asserts the wire answer is SSH_AGENT_FAILURE (5) and never
/// SSH_AGENT_SUCCESS (6) or a fabricated IDENTITIES_ANSWER. `agent_exchange` fails on
/// silence, so a regression to the old behaviour is a timeout failure, not a warning.
#[tokio::test]
async fn unanswered_request_fails_closed() -> E2EResult<()> {
    let socket_path = std::env::temp_dir().join(format!(
        "netget-test-agent-failclosed-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);

    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let prompt = format!("Start SSH Agent server on {}.", socket_path_str);

    let config = NetGetConfig::new(&prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start SSH Agent server")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH Agent",
                    "instruction": "Decide what this agent will do",
                    "startup_params": { "socket_path": socket_path_str }
                }]))
                .expect_calls(1)
                .and()
                .on_event("ssh_agent_connection_opened")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // The model answers, and answers with nothing at all.
                .on_event("ssh_agent_request_identities")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });

    let mut server = helpers::start_netget_server(config).await?;

    let mut stream = connect_to_agent(&socket_path).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = agent_exchange(&mut stream, &build_request_identities()).await?;
    let (_, msg_type) = parse_message_header(&response).expect("Failed to parse response header");

    assert_eq!(
        msg_type, 5,
        "no decision MUST refuse: expected SSH_AGENT_FAILURE (5), got {}. \
         6 would be SUCCESS and 12 an invented identity list; both would mean the server \
         answered on the model's behalf",
        msg_type
    );

    // The token must name the server as the decider. Reporting this as the model's refusal
    // is the conflation that let an LLM outage read as a policy decision in OAuth2.
    let mut seen = false;
    for _ in 0..100 {
        if server
            .output_contains("decision=fail_closed_no_action")
            .await
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        seen,
        "an unanswered request must be logged as decision=fail_closed_no_action. Output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    let _ = std::fs::remove_file(&socket_path);
    server.stop().await?;
    Ok(())
}
