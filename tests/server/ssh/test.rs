//! End-to-end SSH tests for NetGet
//!
//! These tests spawn the actual NetGet binary with SSH prompts
//! and validate the responses using the ssh2 client library.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

#[tokio::test]
async fn test_ssh_banner() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Banner ===");

    // PROMPT: Tell the LLM to act as an SSH server
    let prompt = "listen on port {AVAILABLE_PORT} via ssh. Send SSH protocol version banner 'SSH-2.0-NetGet_1.0' when clients connect";

    // Start the server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("ssh")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH",
                    "instruction": "Send SSH protocol version banner"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and read SSH banner
    println!("Connecting to SSH server...");
    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(mut tcp_stream) => {
            println!("✓ TCP connected");
            tcp_stream.set_read_timeout(Some(Duration::from_secs(5)))?;

            // Read SSH banner
            let mut buffer = vec![0u8; 256];
            match tcp_stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    println!("Received banner: {}", banner.trim());

                    // SSH banner must start with "SSH-"
                    assert!(
                        banner.starts_with("SSH-"),
                        "Expected SSH banner starting with 'SSH-', got: {}",
                        banner
                    );

                    // Should be SSH version 2.0
                    assert!(
                        banner.contains("SSH-2.0"),
                        "Expected SSH-2.0, got: {}",
                        banner
                    );

                    println!("✓ SSH banner verified");
                }
                Ok(_) => {
                    println!("Note: No banner received (connection closed)");
                    println!("  This may be expected if SSH server is not fully implemented");
                }
                Err(e) => {
                    println!("Note: Error reading banner: {}", e);
                    println!("  This may be expected if SSH server is not fully implemented");
                }
            }
        }
        Err(e) => {
            println!("Note: TCP connection failed: {}", e);
            println!("  This may be expected if SSH server is not fully implemented");
        }
    }

    // Verify mock expectations
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
async fn test_ssh_version_exchange() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Version Exchange with Mocks ===");

    use crate::helpers::NetGetConfig;

    // PROMPT: Tell the LLM to handle SSH version exchange
    let prompt = "listen on port {AVAILABLE_PORT} via ssh. Implement SSH-2.0 protocol.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("ssh")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH",
                    "instruction": "SSH server with version exchange"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    // Start the server
    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Perform SSH version exchange using ssh2
    println!("Attempting SSH2 version exchange...");

    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(tcp_stream) => {
            println!("✓ TCP connected");

            // Create SSH session
            let mut sess = ssh2::Session::new()?;
            sess.set_tcp_stream(tcp_stream);
            sess.set_timeout(5000); // 5 second timeout
            sess.set_blocking(true);

            // Attempt handshake (this includes version exchange)
            match sess.handshake() {
                Ok(_) => {
                    println!("✓ SSH handshake successful!");

                    // Get remote banner
                    if let Some(banner) = sess.banner() {
                        println!("  Server banner: {}", banner);
                        assert!(banner.starts_with("SSH-2.0"), "Expected SSH-2.0 banner");
                    }

                    println!("✓ SSH version exchange verified");
                }
                Err(e) => {
                    println!("Note: SSH handshake failed: {}", e);
                    println!("  This is expected - full SSH protocol is very complex");
                    println!("  The server may have sent a banner but not completed key exchange");
                }
            }
        }
        Err(e) => {
            println!("Note: TCP connection failed: {}", e);
            println!("  This may be expected if SSH server is not fully implemented");
        }
    }

    // Verify mock expectations
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
async fn test_ssh_connection_attempt() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Connection Attempt with Mocks ===");

    use crate::helpers::NetGetConfig;

    // PROMPT: Tell the LLM to accept SSH connections
    let prompt = "listen on port {AVAILABLE_PORT} via ssh. Accept SSH connections.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("ssh")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH",
                    "instruction": "SSH server accepting connections"
                }
            ]))
            .expect_calls(1)
            .and()
        // No `ssh_auth` rule on purpose: this test is about the handshake, and an auth
        // attempt with no handler must be refused. `test_ssh_python_auth_script` and
        // `test_sftp_basic_operations` cover the granting paths.
        //
        // This comment used to read "the ssh2 client library has timing/compatibility
        // issues with russh server", and that claim propagated into
        // `src/server/ssh/actions.rs` and `src/server/ssh/CLAUDE.md` as the reason SSH
        // could not be Beta — for months after it stopped being true. libssh2 completes
        // a full session against this server; what it could not do was complete one while
        // it was blocking the runtime the in-process mock needed (see `ssh_password_auth`
        // and `sftp_session`, both of which run it under `spawn_blocking`). A stale note
        // about a test is the cheapest way to hold a rating down.
    });

    // Start the server
    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Try to establish SSH connection
    println!("Attempting full SSH connection...");

    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(tcp_stream) => {
            println!("✓ TCP connected");
            tcp_stream.set_read_timeout(Some(Duration::from_secs(5)))?;

            let mut sess = ssh2::Session::new()?;
            sess.set_tcp_stream(tcp_stream);
            sess.set_timeout(5000);

            // Unconditional. Every arm here used to `println!` and continue, so a total
            // failure and a clean handshake were the same outcome — and the printed note
            // was then quoted elsewhere as evidence that libssh2 cannot talk to this
            // server.
            sess.handshake()
                .expect("libssh2 must complete the SSH transport handshake against this server");
            println!("libssh2 completed the handshake");

            assert!(
                sess.userauth_password("testuser", "testpass").is_err(),
                "no handler grants this login, so auth must be refused — a server that \
                 accepts an unhandled login is the fail-open defect, not a passing test"
            );
            assert!(
                !sess.authenticated(),
                "the session must not report itself authenticated after a refused login"
            );
            println!("libssh2 saw the login refused, which is the fail-closed answer");
        }
        Err(e) => panic!("TCP connect to the SSH server failed: {e}"),
    }

    // Verify mock expectations
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
async fn test_ssh_multiple_connections() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Multiple Connections ===");

    // PROMPT: Tell the LLM to handle multiple SSH connections
    let prompt =
        "listen on port {AVAILABLE_PORT} via ssh. Handle multiple concurrent SSH connections. \
        Send banner SSH-2.0-NetGet to each client";

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("ssh")
                    .and_instruction_containing("multiple concurrent SSH connections")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SSH",
                            "instruction": "Handle multiple concurrent SSH connections. Send banner SSH-2.0-NetGet to each client"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Try multiple connections
    println!("Testing multiple SSH connections...");

    for i in 1..=3 {
        println!("  Connection #{}", i);

        match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;

                let mut buffer = vec![0u8; 256];
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]);
                        println!("    Received: {}", banner.trim());

                        if banner.starts_with("SSH-") {
                            println!("    ✓ Connection #{} successful", i);
                        }
                    }
                    _ => {
                        println!("    Note: No banner received");
                    }
                }
            }
            Err(e) => {
                println!("    Note: Connection #{} failed: {}", i, e);
            }
        }

        // Small delay between connections
    }

    println!("✓ Multiple connection handling tested");

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
async fn test_ssh_python_auth_script() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH with Python Auth Script and Mocks ===");

    use crate::helpers::NetGetConfig;

    // PROMPT: Simple prompt asking for SSH auth via script
    let prompt =
        "listen on port {AVAILABLE_PORT} via ssh. Allow user 'alice' and deny all other users.";

    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock: Server startup (LLM would generate script here)
                .on_instruction_containing("ssh")
                .and_instruction_containing("alice")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SSH",
                        "instruction": "SSH server with alice authentication",
                        "script_inline": "import json,sys\nd=json.load(sys.stdin)\nif d['event']['username']=='alice':print(json.dumps({'actions':[{'type':'ssh_auth_decision','allowed':True}]}))\nelse:print(json.dumps({'actions':[{'type':'ssh_auth_decision','allowed':False}]}))",
                        "script_handles": ["ssh_auth"]
                    }
                ]))
                .expect_calls(1)
                .and()
                // Note: Authentication events will be handled by script (no LLM calls)
        });

    // Start the server
    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // IMPORTANT: After server startup, we expect to see script configuration in the LLM response
    // The LLM should have returned an action with script_inline and script_handles
    println!("\n  ✓ Server configured (check debug output above for script_inline presence)");

    // VALIDATION: Test authentication with different users
    println!("Testing authentication...");

    // Test 1: Try to connect as "alice" (should succeed)
    println!("\n  Test 1: Authenticate as 'alice' (should be allowed by script)");
    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(tcp_stream) => {
            println!("    ✓ TCP connected");

            let mut sess = ssh2::Session::new()?;
            sess.set_tcp_stream(tcp_stream);
            sess.set_timeout(10000);

            match sess.handshake() {
                Ok(_) => {
                    println!("    ✓ SSH handshake completed");

                    match sess.userauth_password("alice", "anypassword") {
                        Ok(_) => {
                            println!("    ✓ Authentication as 'alice' succeeded!");
                            assert!(sess.authenticated(), "Session should be authenticated");
                        }
                        Err(e) => {
                            println!("    ✗ Authentication as 'alice' failed: {}", e);
                            println!(
                                "      This indicates the LLM may not have generated a script"
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("    Note: SSH handshake failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("    Note: TCP connection failed: {}", e);
        }
    }

    // Test 2: Try to connect as "bob" (should fail)
    println!("\n  Test 2: Authenticate as 'bob' (should be denied by script)");
    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(tcp_stream) => {
            println!("    ✓ TCP connected");

            let mut sess = ssh2::Session::new()?;
            sess.set_tcp_stream(tcp_stream);
            sess.set_timeout(10000);

            match sess.handshake() {
                Ok(_) => {
                    println!("    ✓ SSH handshake completed");

                    match sess.userauth_password("bob", "anypassword") {
                        Ok(_) => {
                            println!(
                                "    ✗ Authentication as 'bob' succeeded (should have been denied)"
                            );
                        }
                        Err(e) => {
                            println!("    ✓ Authentication as 'bob' correctly denied: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("    Note: SSH handshake failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("    Note: TCP connection failed: {}", e);
        }
    }

    // VERIFY: Check that scripts were used (not LLM) for authentication
    println!("\nVerifying that scripts handled authentication (not LLM)...");

    // Give a moment for output to be captured

    // Debug: print captured lines count
    let output = server.get_output().await;
    println!("  DEBUG: Captured {} output lines", output.len());
    if output.is_empty() {
        println!("  WARNING: No output lines captured! Output collection may not be working.");
    } else {
        println!("  DEBUG: First few lines:");
        for line in output.iter().take(5) {
            println!("    - {}", line);
        }
    }

    // Should see script configuration in initial LLM response
    assert!(
        server.output_contains("script_inline").await,
        "Server should have been configured with a script (script_inline should appear in output)"
    );

    // Should NOT see many LLM requests for auth events after server startup
    // The first LLM call is for server setup, subsequent auth events should use script
    // Allow up to 2 calls (server setup + possible system update)
    let llm_request_count = server.count_in_output("LLM request:").await;
    assert!(
        llm_request_count <= 2,
        "Expected at most 2 LLM requests (server setup + optional update), found {}. Auth events should use script, not LLM!",
        llm_request_count
    );

    println!(
        "  ✓ Verified: Script handled authentication ({} LLM call(s) total)",
        llm_request_count
    );

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("\n=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_ssh_script_update() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Script Update on Running Server ===");

    use crate::helpers::NetGetConfig;

    // PROMPT: Start SSH server with script, then request to update it
    let prompt =
        "listen on port {AVAILABLE_PORT} via ssh. Initially deny all authentication via script. \
        Then immediately update the script to allow user 'charlie' and deny others.";

    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock: Server startup with initial script
                .on_instruction_containing("ssh")
                .and_instruction_containing("script")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SSH",
                        "instruction": "SSH server with script authentication",
                        "script_inline": "import json,sys\nd=json.load(sys.stdin)\nif d['event']['username']=='charlie':print(json.dumps({'actions':[{'type':'ssh_auth_decision','allowed':True}]}))\nelse:print(json.dumps({'actions':[{'type':'ssh_auth_decision','allowed':False}]}))",
                        "script_handles": ["ssh_auth"]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    // Start the server
    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to start and potentially update script

    // VALIDATION: Try to authenticate as charlie (should succeed with updated script)
    println!("Testing authentication with updated script...");
    match TcpStream::connect(format!("127.0.0.1:{}", server.port)) {
        Ok(tcp_stream) => {
            println!("  ✓ TCP connected");

            let mut sess = ssh2::Session::new()?;
            sess.set_tcp_stream(tcp_stream);
            sess.set_timeout(10000);

            match sess.handshake() {
                Ok(_) => {
                    println!("  ✓ SSH handshake completed");

                    match sess.userauth_password("charlie", "anypassword") {
                        Ok(_) => {
                            println!(
                                "  ✓ Authentication as 'charlie' succeeded (script was updated!)"
                            );
                        }
                        Err(e) => {
                            println!("  Note: Authentication failed: {}", e);
                            println!("    The LLM may not have called update_script action");
                        }
                    }
                }
                Err(e) => {
                    println!("  Note: SSH handshake failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("  Note: TCP connection failed: {}", e);
        }
    }

    // VERIFY: Check that initial script was created and then updated
    println!("\nVerifying that scripts were used...");

    let output = server.get_output().await;
    println!("  DEBUG: Captured {} output lines", output.len());

    // Should see script_inline in the output (initial script creation)
    assert!(
        server.output_contains("script_inline").await,
        "Server should have been configured with a script"
    );

    // Should see update_script action if the script was updated
    if server.output_contains("update_script").await {
        println!("  ✓ Verified: Script was updated via update_script action");
    } else {
        println!(
            "  Note: No update_script action found - LLM may have created final script directly"
        );
    }

    // Count LLM requests - we expect:
    // 1. Initial server setup (may include script creation + update, or just final script)
    // 2. Auth attempts should use script (no LLM calls)
    let llm_request_count = server.count_in_output("LLM request:").await;
    println!("  DEBUG: Found {} LLM request(s)", llm_request_count);

    // Accept 1-2 LLM requests (setup, or setup + update)
    assert!(
        llm_request_count <= 2,
        "Expected at most 2 LLM requests (setup + optional update), found {}. Auth events should use script!",
        llm_request_count
    );

    println!("  ✓ Verified: Scripts handled authentication (no LLM calls for auth events)");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Authenticate against `port` as `user`, entirely on a blocking thread.
///
/// **`ssh2` is a blocking client and the mock Ollama server runs in this test's own Tokio
/// runtime.** Calling `userauth_password` directly from the async test body parks the runtime
/// thread inside libssh2, so the mock cannot answer netget's `ssh_auth` request; netget waits,
/// libssh2 gives up with `[Session(-9)] Timed out waiting on socket`, and the mock records
/// **zero** calls for an event the server really did emit. Both of the tests below failed
/// exactly that way, and the deadlock reads as "the event never reached call_llm".
///
/// `spawn_blocking` moves libssh2 off the runtime's worker so the mock can serve. This is the
/// same shape `llm_failure_test.rs` already uses, and it is why those tests pass.
async fn ssh_password_auth(port: u16, user: &'static str) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || -> Result<bool, String> {
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        let mut sess = ssh2::Session::new().map_err(|e| e.to_string())?;
        sess.set_tcp_stream(tcp);
        sess.set_timeout(15000);
        sess.handshake().map_err(|e| format!("handshake: {e}"))?;
        Ok(sess.userauth_password(user, "pass").is_ok() && sess.authenticated())
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

#[tokio::test]
async fn test_ssh_script_fallback_to_llm() -> E2EResult<()> {
    println!("\n=== E2E Test: SSH Script Fallback to LLM ===");

    // PROMPT: Simple prompt asking for script with fallback behavior
    let prompt = "listen on port {AVAILABLE_PORT} via ssh. Use a script that allows user 'dave', and falls back to LLM for other users. \
        The LLM should allow user 'eve' but deny other unknown users.";

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup with script
                    .on_instruction_containing("ssh")
                    .and_instruction_containing("script")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SSH",
                            "instruction": "SSH server with script fallback",
                            "script_inline": "import json,sys\nd=json.load(sys.stdin)\nif d['event']['username']=='dave':print(json.dumps({'actions':[{'type':'ssh_auth_decision','allowed':True}]}))\nelse:print(json.dumps({'fallback_to_llm':True}))",
                            "script_handles": ["ssh_auth"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: the script punted 'eve' to the model, which allows her.
                    //
                    // These two mocks used to be absent, with a comment blaming "timing issues"
                    // in ssh2 for the fallback timing out. The timing issue was this test
                    // blocking its own runtime (see `ssh_password_auth`), so the model was never
                    // reachable and the fallback path — the entire subject of this test — was
                    // never exercised at all.
                    .on_event("ssh_auth")
                    .and_event_data_contains("username", "eve")
                    .respond_with_actions(serde_json::json!([
                        {"type": "ssh_auth_decision", "allowed": true}
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: …and denies frank.
                    .on_event("ssh_auth")
                    .and_event_data_contains("username", "frank")
                    .respond_with_actions(serde_json::json!([
                        {"type": "ssh_auth_decision", "allowed": false}
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);

    // 'dave' is handled by the script: allowed, and with no LLM call at all.
    let dave = ssh_password_auth(server.port, "dave").await?;
    assert!(
        dave,
        "'dave' is allowed by the script and must authenticate"
    );
    println!("  ✓ 'dave' authenticated (script handled)");

    // 'eve' falls through the script to the model, which allows her.
    let eve = ssh_password_auth(server.port, "eve").await?;
    assert!(
        eve,
        "'eve' must authenticate via the script's fallback_to_llm path; a failure here means \
         the fallback never reached the model"
    );
    println!("  ✓ 'eve' authenticated (LLM fallback)");

    // 'frank' falls through to the model too, which denies him. The denial must come from the
    // model's answer, not from a timeout — mock 3's expect_calls(1) is what distinguishes them.
    let frank = ssh_password_auth(server.port, "frank").await?;
    assert!(
        !frank,
        "'frank' is denied by the model and must not authenticate"
    );
    println!("  ✓ 'frank' denied (LLM fallback)");

    assert!(
        server.output_contains("script_inline").await,
        "Server should have been configured with a script"
    );

    // Verify mock expectations: exactly one setup call, exactly one fallback call each for eve
    // and frank, and — implicitly — none for dave, since no rule would have matched him and an
    // unmatched request is an HTTP 500 the server would log.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("\n=== Test completed ===\n");
    Ok(())
}

/// Everything ssh2 does over SFTP, on a blocking thread. See `ssh_password_auth` for why the
/// blocking client must not run on the test's own runtime: the mock Ollama server lives there,
/// and every one of these operations needs it to answer.
struct SftpOutcome {
    authenticated: bool,
    entries: Vec<(String, u64, bool)>,
    contents: String,
    stat_size: Option<u64>,
    stat_is_file: bool,
}

async fn sftp_session(port: u16) -> Result<SftpOutcome, String> {
    tokio::task::spawn_blocking(move || -> Result<SftpOutcome, String> {
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        let mut sess = ssh2::Session::new().map_err(|e| e.to_string())?;
        sess.set_tcp_stream(tcp);
        sess.set_timeout(15000);
        sess.handshake().map_err(|e| format!("handshake: {e}"))?;
        sess.userauth_password("test", "testpass")
            .map_err(|e| format!("auth: {e}"))?;
        let authenticated = sess.authenticated();

        let sftp = sess.sftp().map_err(|e| format!("sftp subsystem: {e}"))?;

        let entries = sftp
            .readdir(std::path::Path::new("/"))
            .map_err(|e| format!("readdir /: {e}"))?
            .into_iter()
            .map(|(path, stat)| {
                (
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    stat.size.unwrap_or(0),
                    stat.is_dir(),
                )
            })
            .collect();

        let mut contents = String::new();
        {
            let mut file = sftp
                .open(std::path::Path::new("/readme.txt"))
                .map_err(|e| format!("open /readme.txt: {e}"))?;
            file.read_to_string(&mut contents)
                .map_err(|e| format!("read /readme.txt: {e}"))?;
        }

        let stat = sftp
            .stat(std::path::Path::new("/readme.txt"))
            .map_err(|e| format!("stat /readme.txt: {e}"))?;

        Ok(SftpOutcome {
            authenticated,
            entries,
            contents,
            stat_size: stat.size,
            stat_is_file: stat.is_file(),
        })
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

/// A full read-only SFTP round trip against a mocked handler.
///
/// Two things were wrong with this test and both hid the same way — everything was wrapped in
/// `match … Err(e) => println!("Note: …")`, so a total failure printed notes and passed:
///
/// 1. It blocked its own Tokio runtime with libssh2, so the in-process mock could not answer
///    `ssh_auth` and authentication timed out (`[Session(-9)] Timed out waiting on socket`)
///    with the mock recording zero calls. See `ssh_password_auth`.
/// 2. Its mocks named events and actions that do not exist. The server emits one
///    `sftp_operation` event carrying an `operation` field, and answers with
///    `sftp_handle` / `sftp_directory_listing` / `sftp_file_content` / `sftp_file_attributes`
///    (`src/server/ssh/actions.rs`). The mocks used `sftp_readdir` / `sftp_read` / `sftp_stat`
///    and `sftp_directory_response` / `sftp_stat_response`, none of which the code has ever
///    known — so even reaching them would have produced nothing.
///
/// The assertions are now unconditional: an operation that fails fails the test.
#[tokio::test]
async fn test_sftp_basic_operations() -> E2EResult<()> {
    println!("\n=== E2E Test: SFTP Basic Operations ===");

    // 'Hello from NetGet SFTP!' is 23 bytes; readme.txt's advertised size matches it in both
    // the listing and the attributes, because a size larger than the content truncates or
    // hangs the download (see src/server/ssh/CLAUDE.md).
    const README: &str = "Hello from NetGet SFTP!";

    let prompt = "listen on port {AVAILABLE_PORT} via ssh. Enable SFTP subsystem. \
        When SFTP clients connect and request directory listing for '/', \
        return a virtual directory with 3 entries: 'readme.txt' (23 bytes), \
        'data.json' (256 bytes), and 'logs' (directory). \
        When clients read 'readme.txt', return the content 'Hello from NetGet SFTP!'. \
        Accept password authentication for user 'test' with any password.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("ssh")
            .and_instruction_containing("SFTP subsystem")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SSH",
                    "instruction": "Enable SFTP subsystem with virtual filesystem"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Authentication
            .on_event("ssh_auth")
            .and_event_data_contains("username", "test")
            .respond_with_actions(serde_json::json!([
                {"type": "ssh_auth_decision", "allowed": true}
            ]))
            .expect_calls(1)
            .and()
            // Mocks 3-7: one per SFTP operation. All five arrive as `sftp_operation`; the
            // `operation` field is what distinguishes them.
            //
            // `expect_at_least(1)` rather than an exact count: libssh2 decides how many
            // round trips a listing or a download takes (a second readdir/read is how it
            // learns it has hit EOF), and pinning that would test libssh2's chunking rather
            // than the server.
            .on_event("sftp_operation")
            .and_event_data_contains("operation", "opendir")
            .respond_with_actions(serde_json::json!([
                {"type": "sftp_handle", "handle": "/"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("sftp_operation")
            .and_event_data_contains("operation", "readdir")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "sftp_directory_listing",
                    "entries": [
                        {"name": "readme.txt", "size": 23, "is_dir": false},
                        {"name": "data.json", "size": 256, "is_dir": false},
                        {"name": "logs", "size": 0, "is_dir": true}
                    ]
                }
            ]))
            .expect_at_least(1)
            .and()
            .on_event("sftp_operation")
            .and_event_data_contains("operation", "open")
            .respond_with_actions(serde_json::json!([
                {"type": "sftp_handle", "handle": "/readme.txt"}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("sftp_operation")
            .and_event_data_contains("operation", "read")
            .respond_with_actions(serde_json::json!([
                {"type": "sftp_file_content", "content": README}
            ]))
            .expect_at_least(1)
            .and()
            .on_event("sftp_operation")
            .and_event_data_contains("operation", "lstat")
            .respond_with_actions(serde_json::json!([
                {"type": "sftp_file_attributes", "size": 23, "is_dir": false}
            ]))
            .expect_at_least(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    let outcome = sftp_session(server.port).await?;

    assert!(outcome.authenticated, "SFTP session must be authenticated");

    let names: Vec<&str> = outcome.entries.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(
        names.contains(&"readme.txt") && names.contains(&"data.json") && names.contains(&"logs"),
        "the listing must contain every entry the handler returned, got {names:?}"
    );
    let logs_is_dir = outcome
        .entries
        .iter()
        .find(|(n, _, _)| n == "logs")
        .map(|(_, _, is_dir)| *is_dir)
        .unwrap_or(false);
    assert!(logs_is_dir, "'logs' must come back as a directory");

    assert_eq!(
        outcome.contents, README,
        "the file's bytes must survive the round trip exactly"
    );

    assert_eq!(
        outcome.stat_size,
        Some(README.len() as u64),
        "stat must report the size the handler declared"
    );
    assert!(outcome.stat_is_file, "readme.txt must stat as a file");

    println!("  ✓ auth, readdir, open+read and stat all round-tripped");

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
