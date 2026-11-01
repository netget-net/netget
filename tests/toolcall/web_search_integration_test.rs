//! Integration tests for web_search tool
//!
//! These tests verify end-to-end web_search functionality by starting NetGet
//! and having the LLM use web_search to gather information.

// Share one death-tie registry with the parent integration test target.
// Loading child_guard twice would give each module a separate watcher registry.
use crate::helpers::child_guard;

use crate::helpers::{start_netget_server, NetGetConfig};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

/// Helper to get the netget binary path from cargo
fn get_netget_binary() -> &'static str {
    env!("CARGO_BIN_EXE_netget")
}

/// Test that HTTP server reads RFC 7168 (HTCPCP-TEA) and accepts message/teapot
///
/// NOTE: This test is ignored by default because:
/// 1. It requires real Ollama to be running (not mocked)
/// 2. It tests experimental HTCPCP feature (April Fools' RFC)
/// 3. It's inherently flaky (depends on LLM understanding obscure RFC)
/// 4. It takes 30+ seconds to run
///
/// To run: cargo test --test integration_toolcall -- --ignored test_htcpcp_tea_accepts_message_teapot
#[tokio::test]
#[ignore = "Requires real Ollama, tests experimental HTCPCP feature, inherently flaky"]
async fn test_htcpcp_tea_accepts_message_teapot() {
    // Discover the port only after the server owns its ephemeral socket.
    let port = 0;

    // Start NetGet HTTP server with RFC 7168 instructions
    // LLM should learn to accept message/teapot
    let prompt = format!(
        "Start an HTTP server on port {}. \
             Implement RFC 7168 (HTCPCP-TEA) by reading https://datatracker.ietf.org/doc/html/rfc7168. \
             This RFC extends HTCPCP to support tea and defines the media type 'message/teapot'. \
             IMPORTANT: When you receive a request, check the Content-Type header: \
             - If Content-Type is 'message/teapot', respond with 200 OK \
             - For ANY other Content-Type, respond with 415 Unsupported Media Type. \
             You can use web_search to verify the RFC, but the key requirement is: accept message/teapot.",
        port
    );

    println!("Starting NetGet with RFC 7168 prompt on port {}...", port);

    let server = start_netget_server(NetGetConfig::new(prompt).with_ollama())
        .await
        .expect("Failed to start netget");
    let port = server.port;

    // 4. Send BREW request with Content-Type: message/teapot
    println!("Sending BREW request with Content-Type: message/teapot...");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", port);

    let result = client
        .request(reqwest::Method::from_bytes(b"BREW").unwrap(), &url)
        .header("Content-Type", "message/teapot")
        .body("start")
        .send()
        .await;

    server.stop().await.expect("Failed to stop netget");

    // 6. Assert the request succeeded and did NOT return 415
    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            println!("✓ BREW request succeeded!");
            println!("Response status: {}", status);

            assert_ne!(
                    status, 415,
                    "Expected message/teapot to be accepted by RFC 7168, but got 415 Unsupported Media Type"
                );

            println!("✓ All assertions passed! LLM correctly learned that RFC 7168 supports message/teapot.");
        }
        Err(e) => {
            panic!(
                "BREW request failed: {}. This could mean:\n\
                    1. Server didn't start (check if Ollama is running)\n\
                    2. LLM didn't read RFC 7168 correctly\n\
                    3. LLM didn't understand the BREW method\n\
                    Error details: {}",
                e, e
            );
        }
    }
}

/// Test that HTTP server reads RFC 2324 (original HTCPCP) and rejects message/teapot
///
/// NOTE: This test is ignored by default because:
/// 1. It requires real Ollama to be running (not mocked)
/// 2. It tests experimental HTCPCP feature (April Fools' RFC)
/// 3. It's inherently flaky (depends on LLM understanding obscure RFC)
/// 4. It takes 30+ seconds to run
///
/// To run: cargo test --test integration_toolcall -- --ignored test_htcpcp_coffeepot_rejects_message_teapot
#[tokio::test]
#[ignore = "Requires real Ollama, tests experimental HTCPCP feature, inherently flaky"]
async fn test_htcpcp_coffeepot_rejects_message_teapot() {
    // Discover the port only after the server owns its ephemeral socket.
    let port = 0;

    // Start NetGet HTTP server with RFC 2324 instructions
    // This should only accept message/coffeepot, not message/teapot
    let prompt = format!(
        "Start an HTTP server on port {}. \
             Implement RFC 2324 (HTCPCP/1.0) by reading https://datatracker.ietf.org/doc/html/rfc2324. \
             This RFC defines ONLY the media type 'message/coffeepot' (NOT message/teapot - that's in a different RFC). \
             IMPORTANT: When you receive a request, check the Content-Type header: \
             - If Content-Type is 'message/coffeepot', respond with 200 OK \
             - For ANY other Content-Type (including message/teapot), respond with 415 Unsupported Media Type. \
             You can use web_search to verify the RFC, but the key requirement is: ONLY accept message/coffeepot.",
        port
    );

    println!("Starting NetGet with RFC 2324 prompt on port {}...", port);

    let server = start_netget_server(NetGetConfig::new(prompt).with_ollama())
        .await
        .expect("Failed to start netget");
    let port = server.port;

    // 4. Send BREW request with Content-Type: message/teapot
    println!("Sending BREW request with Content-Type: message/teapot...");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", port);

    let result = client
        .request(reqwest::Method::from_bytes(b"BREW").unwrap(), &url)
        .header("Content-Type", "message/teapot")
        .body("start")
        .send()
        .await;

    server.stop().await.expect("Failed to stop netget");

    // 6. Assert the request succeeded and DID return 415
    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            println!("✓ BREW request succeeded!");
            println!("Response status: {}", status);

            assert_eq!(
                    status, 415,
                    "Expected message/teapot to be REJECTED by RFC 2324 (which only has message/coffeepot), but got status {}",
                    status
                );

            println!("✓ All assertions passed! LLM correctly learned that RFC 2324 only supports message/coffeepot, not message/teapot.");
        }
        Err(e) => {
            panic!(
                "BREW request failed: {}. This could mean:\n\
                    1. Server didn't start (check if Ollama is running)\n\
                    2. LLM didn't read RFC 2324 correctly\n\
                    3. LLM didn't understand the BREW method\n\
                    Error details: {}",
                e, e
            );
        }
    }
}

/// Integration test: LLM searches for RFC 2324 and extracts media type
///
/// NOTE: This test is ignored by default because:
/// 1. It requires real Ollama to be running (not mocked)
/// 2. It tests web_search integration with obscure RFC content
/// 3. It's inherently flaky (depends on LLM search and extraction capabilities)
/// 4. It takes 45+ seconds to run
///
/// To run: cargo test --test integration_toolcall -- --ignored test_llm_search_and_extract_rfc2324_media_type
#[tokio::test]
#[ignore = "Requires real Ollama, tests web_search integration, inherently flaky"]
async fn test_llm_search_and_extract_rfc2324_media_type() {
    println!("Starting NetGet to search for RFC 2324 and extract media type...");

    // Prompt the LLM to search for RFC 2324 and extract the media type
    // This tests the full search workflow: search query -> find URL -> fetch URL -> extract info
    let prompt = "Use web_search to fetch RFC 2324. \
                  Read the RFC and find what media type (Content-Type) is defined. \
                  Use notify_operator to tell me the exact media type string you found.";

    let mut child = Command::new(get_netget_binary())
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start netget");
    let pid = child.id();
    child_guard::tie_child(pid);

    // Wait for LLM to process (search, read, extract)
    // This involves: search query -> find URL -> fetch URL -> extract info -> respond
    println!("Waiting for LLM to search, read, and extract information...");
    sleep(Duration::from_secs(45)).await;

    // Kill the process and capture output
    let _ = child.kill();
    let output = child.wait_with_output().expect("Failed to get output");
    child_guard::untie_child(pid);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("\n=== STDOUT ===");
    println!("{}", stdout);
    println!("\n=== STDERR ===");
    println!("{}", stderr);

    // Combine stdout and stderr for searching
    let combined_output = format!("{}\n{}", stdout, stderr);

    // Verify the LLM actually used web_search
    assert!(
        combined_output.contains("web_search") || combined_output.contains("Tool 'web_search'"),
        "Expected to see web_search tool being used. Output:\n{}",
        combined_output
    );

    // Verify the LLM used notify_operator to report the media type
    // Look for notify_operator in the LLM response (turn 2), not in the prompt examples
    // The pattern should be: LLM response contains notify_operator action with coffeepot
    let notify_operator_in_response = combined_output.contains("LLM response (turn 2)")
        && combined_output.contains("→ notify_operator")
        && combined_output.contains("coffeepot");

    assert!(
        notify_operator_in_response,
        "Expected LLM to execute notify_operator action in turn 2 to report 'message/coffeepot'. \
         The LLM should extract the media type from RFC 2324 and report it using notify_operator.\n\
         Look for 'LLM response (turn 2)' followed by '→ notify_operator' with 'coffeepot'.\n\
         Current turn 2 shows unknown_action instead of notify_operator.\n\
         Output:\n{}",
        combined_output
    );

    // Verify RFC 2324 was found
    assert!(
        combined_output.contains("2324") || combined_output.contains("rfc2324"),
        "Expected to find reference to RFC 2324. Output:\n{}",
        combined_output
    );

    println!("\n✓ Test passed! LLM successfully searched for RFC 2324, read it, and extracted the media type 'message/coffeepot'.");
}
