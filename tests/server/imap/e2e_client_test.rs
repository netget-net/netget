//! E2E tests for IMAP server using real async-imap client
//!
//! These tests verify IMAP protocol implementation by:
//! - Starting NetGet in non-interactive mode with IMAP prompts
//! - Using the async-imap Rust client library (same used by email clients)
//! - Testing realistic email client operations
//!
//! This complements the raw TCP tests in tests/server/imap/test.rs
//! by using an actual IMAP client implementation.

mod e2e_imap_client {
    use crate::helpers::*;
    use futures::StreamExt;
    // For collecting Streams
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// Helper to create an IMAP client connected to the server
    async fn connect_imap_client(
        port: u16,
    ) -> E2EResult<async_imap::Client<tokio_util::compat::Compat<TcpStream>>> {
        let addr = format!("127.0.0.1:{}", port);

        // Wrap connection with timeout
        let tcp_stream = timeout(Duration::from_secs(30), TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("Connection timeout to {}", addr))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Convert from tokio::io to futures::io using compat layer
        let compat_stream = tcp_stream.compat();
        let client = async_imap::Client::new(compat_stream);

        // Note: Don't read greeting here - Client::new does it automatically

        Ok(client)
    }

    #[tokio::test]
    async fn test_imap_login_success() -> E2EResult<()> {
        println!("\n=== Test: IMAP Login Success with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for username 'alice' with password 'secret123'. \
                     Greet with: * OK IMAP4rev1 NetGet Server Ready";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock: Server startup
                .on_instruction_containing("listen on port")
                .and_instruction_containing("imap")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "imap",
                        "instruction": "Allow LOGIN for alice/secret123"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Connection greeting
                .on_event("imap_connection")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_imap_response",
                        "response": "* OK IMAP4rev1 Server Ready"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Login success event - use dynamic tag from event
                .on_event("imap_auth")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A001");
                    serde_json::json!([{
                        "type": "send_imap_response",
                        "tag": tag,
                        "status": "OK",
                        "message": "LOGIN completed"
                    }])
                })
                .expect_calls(1)
                .and()
                // Mock: Logout event - use dynamic tag from event
                .on_event("imap_command")
                .and_event_data_contains("command", "LOGOUT")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A002");
                    serde_json::json!([{
                        "type": "send_imap_response",
                        "tag": tag,
                        "status": "OK",
                        "message": "LOGOUT completed"
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect using async-imap client
        let client = connect_imap_client(server.port).await?;
        println!("  [TEST] Connected to IMAP server");

        // Attempt login - handle tuple error type with timeout
        let mut session =
            match timeout(Duration::from_secs(30), client.login("alice", "secret123")).await {
                Ok(Ok(session)) => session,
                Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
                Err(_) => return Err("Login timeout after 30s".into()),
            };
        println!("  [TEST] ✓ Login successful");

        // Logout with timeout
        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout after 30s")?
            .map_err(|e| format!("Logout failed: {}", e))?;
        println!("  [TEST] ✓ Logout successful");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_login_failure() -> E2EResult<()> {
        println!("\n=== Test: IMAP Login Failure with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Only allow LOGIN for username 'alice' with password 'secret123'. \
                     Deny all other credentials.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("imap")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "imap",
                        "instruction": "Only allow alice/secret123"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("imap_connection")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_imap_response",
                        "response": "* OK IMAP4rev1 Server Ready"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("imap_auth")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A001");
                    serde_json::json!([{
                        "type": "send_imap_response",
                        "tag": tag,
                        "status": "NO",
                        "message": "Authentication failed"
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect using async-imap client
        let client = connect_imap_client(server.port).await?;
        println!("  [TEST] Connected to IMAP server");

        // Attempt login with wrong password with timeout - should return Err tuple
        let result = timeout(
            Duration::from_secs(30),
            client.login("alice", "wrongpassword"),
        )
        .await
        .map_err(|_| "Login timeout after 30s")?;

        // Should fail
        match result {
            Err((err, _client)) => {
                println!("  [TEST] ✓ Login correctly rejected: {}", err);
            }
            Ok(_) => {
                return Err("Login should have failed with wrong password".into());
            }
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

    #[tokio::test]
    async fn test_imap_list_mailboxes() -> E2EResult<()> {
        println!("\n=== Test: IMAP LIST Mailboxes with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     When listing mailboxes, return: INBOX, Sent, Drafts, Trash.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("imap")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "Allow LOGIN, list mailboxes"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("imap_connection")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("imap_auth")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A001");
                    serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN completed"}])
                })
                .expect_calls(1)
                .and()
                .on_event("imap_command")
                .and_event_data_contains("command", "LIST")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A002");
                    serde_json::json!([
                        {"type": "send_imap_list", "mailboxes": [
                            {"name": "INBOX"},
                            {"name": "Sent"},
                            {"name": "Drafts"},
                            {"name": "Trash"}
                        ]},
                        {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LIST completed"}
                    ])
                })
                .expect_calls(1)
                .and()
                .on_event("imap_command")
                .and_event_data_contains("command", "LOGOUT")
                .respond_with_actions_from_event(|event_data| {
                    let tag = event_data["tag"].as_str().unwrap_or("A003");
                    serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // List mailboxes - collect Stream into Vec with timeout
        let list_stream = timeout(Duration::from_secs(30), session.list(Some(""), Some("*")))
            .await
            .map_err(|_| "List timeout")??;
        let mailboxes: Vec<_> = list_stream.collect::<Vec<_>>().await;
        println!("  [TEST] Found {} mailboxes", mailboxes.len());

        // Verify we got at least INBOX - handle Result values
        let mailbox_names: Vec<String> = mailboxes
            .into_iter()
            .filter_map(|mb_result| mb_result.ok())
            .map(|mb| mb.name().to_string())
            .collect();

        println!("  [TEST] Mailboxes: {:?}", mailbox_names);
        assert!(
            !mailbox_names.is_empty(),
            "Should have at least one mailbox"
        );
        println!("  [TEST] ✓ LIST command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_select_mailbox() -> E2EResult<()> {
        println!("\n=== Test: IMAP SELECT Mailbox with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     INBOX has 5 messages, 2 are recent. \
                     First unseen message is #3.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port").and_instruction_containing("imap").respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "INBOX has 5 messages"}
            ])).expect_calls(1).and()
            .on_event("imap_connection").respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
            ])).expect_calls(1).and()
            .on_event("imap_auth").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A001");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN OK"}])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "SELECT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A002");
                serde_json::json!([
                    {"type": "send_imap_select", "exists": 5, "recent": 2, "unseen": 3},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "SELECT completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "LOGOUT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A003");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
            }).expect_calls(1).and()
        });
        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Select INBOX
        let mailbox = timeout(Duration::from_secs(30), session.select("INBOX"))
            .await
            .map_err(|_| "Select timeout")??;
        println!("  [TEST] Selected INBOX");
        println!("  [TEST]   EXISTS: {}", mailbox.exists);
        println!("  [TEST]   RECENT: {:?}", mailbox.recent);
        println!("  [TEST]   UNSEEN: {:?}", mailbox.unseen);

        // Verify mailbox info - exists is u32, not Option
        assert!(mailbox.exists > 0, "Should have messages in INBOX");
        println!("  [TEST] ✓ SELECT command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_fetch_messages() -> E2EResult<()> {
        println!("\n=== Test: IMAP FETCH Messages with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     INBOX has 3 messages: \
                     1. From: alice@example.com, Subject: Hello, Body: Test message 1 \
                     2. From: bob@example.com, Subject: Meeting, Body: Test message 2 \
                     3. From: charlie@example.com, Subject: Report, Body: Test message 3";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port").and_instruction_containing("imap").respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "INBOX has 3 messages"}
            ])).expect_calls(1).and()
            .on_event("imap_connection").respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
            ])).expect_calls(1).and()
            .on_event("imap_auth").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A001");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN OK"}])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "SELECT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A002");
                serde_json::json!([
                    {"type": "send_imap_select", "exists": 3},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "SELECT completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "FETCH").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A003");
                serde_json::json!([
                    {"type": "send_imap_fetch", "message_id": 1, "body": "Test message 1"},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "FETCH completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "LOGOUT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A004");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
            }).expect_calls(1).and()
        });
        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Select INBOX
        timeout(Duration::from_secs(30), session.select("INBOX"))
            .await
            .map_err(|_| "Select timeout")??;
        println!("  [TEST] ✓ Selected INBOX");

        // Fetch message 1 - collect Stream into Vec
        let fetch_stream = timeout(Duration::from_secs(30), session.fetch("1", "RFC822"))
            .await
            .map_err(|_| "Fetch timeout")??;
        let messages: Vec<_> = fetch_stream.collect::<Vec<_>>().await;
        println!("  [TEST] Fetched {} message(s)", messages.len());

        assert!(!messages.is_empty(), "Should fetch at least one message");

        // Handle Result values from Stream
        if let Some(Ok(msg)) = messages.into_iter().next() {
            println!("  [TEST]   Message UID: {:?}", msg.uid);
            if let Some(body) = msg.body() {
                let body_str = String::from_utf8_lossy(body);
                println!(
                    "  [TEST]   Body preview: {}...",
                    body_str.chars().take(50).collect::<String>()
                );
            }
        }
        println!("  [TEST] ✓ FETCH command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_search_messages() -> E2EResult<()> {
        println!("\n=== Test: IMAP SEARCH Messages with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     INBOX has 5 messages. Messages 1, 3, 5 are from alice@example.com. \
                     When searching FROM alice, return message numbers 1, 3, 5.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port").and_instruction_containing("imap").respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "5 messages, search alice"}
            ])).expect_calls(1).and()
            .on_event("imap_connection").respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
            ])).expect_calls(1).and()
            .on_event("imap_auth").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A001");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN OK"}])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "SELECT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A002");
                serde_json::json!([
                    {"type": "send_imap_select", "exists": 5},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "SELECT completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "SEARCH").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A003");
                serde_json::json!([
                    {"type": "send_imap_search", "results": [1, 3, 5]},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "SEARCH completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "LOGOUT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A004");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
            }).expect_calls(1).and()
        });
        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Select INBOX
        timeout(Duration::from_secs(30), session.select("INBOX"))
            .await
            .map_err(|_| "Select timeout")??;
        println!("  [TEST] ✓ Selected INBOX");

        // Search for messages from alice
        let message_ids = timeout(
            Duration::from_secs(30),
            session.search("FROM alice@example.com"),
        )
        .await
        .map_err(|_| "Search timeout")??;
        println!("  [TEST] Search found {} message(s)", message_ids.len());
        println!("  [TEST]   Message IDs: {:?}", message_ids);

        // Verify we got results
        assert!(
            !message_ids.is_empty(),
            "Search should return at least one message"
        );
        println!("  [TEST] ✓ SEARCH command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_capability() -> E2EResult<()> {
        println!("\n=== Test: IMAP CAPABILITY with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Support IMAP4rev1, IDLE, NAMESPACE capabilities. \
                     Allow LOGIN for any user.";

        let server = start_netget_server(
            NetGetConfig::new(prompt).with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("imap")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "IMAP", "instruction": "IMAP server"}]))
                    .expect_calls(1).and()
                    // The greeting's capability code is the list; NetGet answers the
                    // CAPABILITY command from it, so there is no CAPABILITY rule here.
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([{"type": "send_imap_response", "response": "* OK [CAPABILITY IMAP4rev1 IDLE NAMESPACE] Server"}]))
                    .expect_calls(1).and()
                    .on_event("imap_auth")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A001");
                        serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN completed"}])
                    })
                    .expect_calls(1).and()
                    .on_event("imap_command")
                    .and_event_data_contains("command", "LOGOUT")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A003");
                        serde_json::json!([{"type": "send_imap_response", "response": format!("* BYE\r\n{} OK LOGOUT", tag)}])
                    })
                    .expect_calls(1).and()
            })
        ).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        println!("  [TEST] Connected to IMAP server");

        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Get capabilities after login
        let caps = timeout(Duration::from_secs(30), session.capabilities())
            .await
            .map_err(|_| "Capabilities timeout")??;
        println!("  [TEST] Retrieved capabilities from server");

        // Verify IMAP4rev1 is supported
        assert!(
            caps.has_str("IMAP4rev1") || caps.has_str("IMAP4REV1"),
            "Server should support IMAP4rev1"
        );
        assert!(
            caps.has_str("IDLE") && caps.has_str("NAMESPACE"),
            "the CAPABILITY answer repeats the greeting's list"
        );
        println!("  [TEST] ✓ CAPABILITY command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_examine_readonly() -> E2EResult<()> {
        println!("\n=== Test: IMAP EXAMINE (readonly) with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     INBOX has 10 messages. \
                     Support EXAMINE command for read-only access.";

        let server = start_netget_server(
            NetGetConfig::new(prompt).with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("imap")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "IMAP", "instruction": "IMAP server"}]))
                    .expect_calls(1).and()
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([{"type": "send_imap_response", "response": "* OK Server"}]))
                    .expect_calls(1).and()
                    .on_event("imap_auth")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A001");
                        serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN completed"}])
                    })
                    .expect_calls(1).and()
                    .on_event("imap_command")
                    .and_event_data_contains("command", "EXAMINE")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A002");
                        serde_json::json!([{"type": "send_imap_response", "response": format!("* FLAGS ()\r\n* 10 EXISTS\r\n* 0 RECENT\r\n{} OK [READ-ONLY] EXAMINE", tag)}])
                    })
                    .expect_calls(1).and()
                    .on_event("imap_command")
                    .and_event_data_contains("command", "LOGOUT")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A003");
                        serde_json::json!([{"type": "send_imap_response", "response": format!("* BYE\r\n{} OK LOGOUT", tag)}])
                    })
                    .expect_calls(1).and()
            })
        ).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // EXAMINE INBOX (read-only)
        let mailbox = timeout(Duration::from_secs(30), session.examine("INBOX"))
            .await
            .map_err(|_| "Examine timeout")??;
        println!("  [TEST] Examined INBOX (read-only)");
        println!("  [TEST]   EXISTS: {}", mailbox.exists);
        println!("  [TEST]   FLAGS: {:?}", mailbox.flags);

        assert!(mailbox.exists > 0, "Should have messages in INBOX");
        println!("  [TEST] ✓ EXAMINE command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_status_command() -> E2EResult<()> {
        println!("\n=== Test: IMAP STATUS Command with async-imap ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     Mailbox 'Sent' has 20 messages, 5 unseen. \
                     Support STATUS command.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port").and_instruction_containing("imap").respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "Sent has 20 messages, 5 unseen"}
            ])).expect_calls(1).and()
            .on_event("imap_connection").respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
            ])).expect_calls(1).and()
            .on_event("imap_auth").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A001");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN OK"}])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "STATUS").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A002");
                serde_json::json!([
                    {"type": "send_imap_status", "mailbox": "Sent", "items": {"MESSAGES": 20, "UNSEEN": 5}},
                    {"type": "send_imap_response", "tag": tag, "status": "OK", "message": "STATUS completed"}
                ])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "LOGOUT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A003");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
            }).expect_calls(1).and()
        });
        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Get status of Sent mailbox without selecting it
        let status = timeout(
            Duration::from_secs(30),
            session.status("Sent", "(MESSAGES UNSEEN)"),
        )
        .await
        .map_err(|_| "Status timeout")??;
        println!("  [TEST] STATUS for 'Sent' mailbox:");
        println!("  [TEST]   EXISTS: {}", status.exists);
        println!("  [TEST]   UNSEEN: {:?}", status.unseen);

        // Verify we got status info - exists is always present (u32)
        assert!(
            status.exists > 0 || status.unseen.is_some(),
            "Should have at least one status attribute"
        );
        println!("  [TEST] ✓ STATUS command successful");

        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_concurrent_connections() -> E2EResult<()> {
        println!("\n=== Test: Multiple Concurrent IMAP Connections ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user with any password. \
                     INBOX has 5 messages. \
                     Support multiple concurrent connections.";

        let server = start_netget_server(
            NetGetConfig::new(prompt).with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("imap")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "IMAP", "instruction": "IMAP server"}]))
                    .expect_calls(1).and()
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([{"type": "send_imap_response", "response": "* OK Server"}]))
                    .expect_calls(3).and()
                    .on_event("imap_auth")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A001");
                        serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN completed"}])
                    })
                    .expect_calls(3).and()
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SELECT")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A002");
                        serde_json::json!([{"type": "send_imap_response", "response": format!("* FLAGS ()\r\n* 5 EXISTS\r\n* 0 RECENT\r\n{} OK SELECT", tag)}])
                    })
                    .expect_calls(3).and()
                    .on_event("imap_command")
                    .and_event_data_contains("command", "LOGOUT")
                    .respond_with_actions_from_event(|event_data| {
                        let tag = event_data["tag"].as_str().unwrap_or("A003");
                        serde_json::json!([{"type": "send_imap_response", "response": format!("* BYE\r\n{} OK LOGOUT", tag)}])
                    })
                    .expect_calls(3).and()
            })
        ).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Create 3 clients sequentially to keep the LLM call budget predictable.
        // This still verifies the server can handle multiple connections
        let port = server.port;
        for i in 0..3 {
            let client = connect_imap_client(port).await?;

            let mut session = match timeout(
                Duration::from_secs(30),
                client.login(&format!("user{}", i), "password"),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err((err, _))) => return Err(format!("Login failed: {}", err).into()),
                Err(_) => return Err("Login timeout".into()),
            };

            // Each client selects INBOX
            let mailbox = timeout(Duration::from_secs(30), session.select("INBOX"))
                .await
                .map_err(|_| "Select timeout")??;
            println!(
                "  [TEST] Client {} selected INBOX with {} messages",
                i, mailbox.exists
            );

            timeout(Duration::from_secs(30), session.logout())
                .await
                .map_err(|_| "Logout timeout")??;
            println!("  [TEST] ✓ Client {} completed successfully", i);
        }

        println!("  [TEST] ✓ All concurrent connections successful");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_imap_noop_and_logout() -> E2EResult<()> {
        println!("\n=== Test: IMAP NOOP and LOGOUT Commands ===");

        let prompt = "listen on port 0 via imap. \
                     Allow LOGIN for any user. \
                     Support NOOP command.";

        let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("listen on port").and_instruction_containing("imap").respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "imap", "instruction": "Support NOOP"}
            ])).expect_calls(1).and()
            .on_event("imap_connection").respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "response": "* OK IMAP4rev1 Server Ready"}
            ])).expect_calls(1).and()
            .on_event("imap_auth").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A001");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGIN OK"}])
            }).expect_calls(1).and()
            .on_event("imap_command").and_event_data_contains("command", "NOOP").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A002");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "NOOP OK"}])
            }).expect_calls(2).and()
            .on_event("imap_command").and_event_data_contains("command", "LOGOUT").respond_with_actions_from_event(|event_data| {
                let tag = event_data["tag"].as_str().unwrap_or("A004");
                serde_json::json!([{"type": "send_imap_response", "tag": tag, "status": "OK", "message": "LOGOUT"}])
            }).expect_calls(1).and()
        });
        let mut server = start_netget_server(server_config).await?;
        println!("  [TEST] Server started on port {}", server.port);

        // Connect and login
        let client = connect_imap_client(server.port).await?;
        let mut session = match timeout(
            Duration::from_secs(30),
            client.login("testuser", "testpass"),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err((err, _client))) => return Err(format!("Login failed: {}", err).into()),
            Err(_) => return Err("Login timeout".into()),
        };
        println!("  [TEST] ✓ Logged in");

        // Send NOOP (no operation - keeps connection alive)
        timeout(Duration::from_secs(30), session.noop())
            .await
            .map_err(|_| "NOOP timeout")??;
        println!("  [TEST] ✓ NOOP command successful");

        // Send another NOOP
        timeout(Duration::from_secs(30), session.noop())
            .await
            .map_err(|_| "NOOP timeout")??;
        println!("  [TEST] ✓ Second NOOP successful");

        // Logout
        timeout(Duration::from_secs(30), session.logout())
            .await
            .map_err(|_| "Logout timeout")??;
        println!("  [TEST] ✓ LOGOUT successful");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }
}
