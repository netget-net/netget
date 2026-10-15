//! E2E tests for IMAP client
//!
//! These tests verify IMAP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod imap_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test IMAP client connection and authentication
    /// LLM calls: 6 (server startup, server greeting, server login response, client startup, client connected, client authenticated)
    #[tokio::test]
    async fn test_imap_client_connect_and_authenticate() -> E2EResult<()> {
        // Start an IMAP server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IMAP. Accept username 'testuser' and password 'testpass'.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "IMAP",
                            "instruction": "Accept username 'testuser' and password 'testpass'"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server connection accepted (imap_connection event)
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": "* OK [CAPABILITY IMAP4rev1] IMAP server ready"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Server authenticates the LOGIN (imap_auth event)
                    .on_event("imap_auth")
                    // LOGIN raises imap_auth, not imap_command -- the server's own action
                    // docs say so ("LOGIN is not delivered here - it raises imap_auth
                    // instead"), so a rule on imap_command could never match and the
                    // LOGIN fell through to the LLM, which refused it with NO [SERVERBUG].
                    // async-imap picks its own tags (a1, a2, ...). A hardcoded "A001"
                    // tags the reply to a command the client never sent, so async-imap
                    // discards it as unsolicited and stays parked on LOGIN until the
                    // test gives up -- reported as "the client never connected".
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "tag": e["tag"].as_str().unwrap_or_default(),
                            "status": "OK",
                            "message": "LOGIN completed"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: Server SELECT response. The client's connected-event answer is
                    // `select_mailbox INBOX`, so without this the server has nothing to say
                    // to the SELECT and the client never reaches imap_mailbox_selected.
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SELECT")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* 5 EXISTS\r\n* 0 RECENT\r\n{} OK [READ-WRITE] SELECT completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an IMAP client that connects and authenticates with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via IMAP. Select INBOX and check for messages.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("IMAP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "IMAP",
                        "instruction": "Authenticate and select INBOX",
                        "startup_params": {
                            "username": "testuser",
                            "password": "testpass",
                            "use_tls": false
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (imap_connected event)
                .on_event("imap_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        // The client authenticates inside connect() from
                        // startup_params; `authenticate_imap` is not one of its
                        // verbs. Selecting INBOX is the next real step.
                        "type": "select_mailbox",
                        "mailbox": "INBOX"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client selected the mailbox (imap_mailbox_selected event)
                .on_event("imap_mailbox_selected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and authenticate

        // Verify client output shows connection
        client
            .wait_for_any(&["connected", "authenticated"], 30)
            .await;
        assert!(
            client.output_contains("connected").await
                || client.output_contains("authenticated").await,
            "Client should show connection/authentication message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ IMAP client connected and authenticated successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test IMAP client mailbox selection
    /// LLM calls: 7 (server startup, server greeting, server login, server select, client startup, client connected, client authenticated)
    #[tokio::test]
    async fn test_imap_client_select_mailbox() -> E2EResult<()> {
        // Start IMAP server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IMAP. Provide a mailbox 'INBOX' with 5 messages.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "IMAP",
                            "instruction": "Provide INBOX with 5 messages"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server greeting
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": "* OK [CAPABILITY IMAP4rev1] IMAP server ready"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Server LOGIN response
                    .on_event("imap_auth")
                    // LOGIN raises imap_auth, not imap_command -- the server's own action
                    // docs say so ("LOGIN is not delivered here - it raises imap_auth
                    // instead"), so a rule on imap_command could never match and the
                    // LOGIN fell through to the LLM, which refused it with NO [SERVERBUG].
                    // async-imap picks its own tags (a1, a2, ...). A hardcoded "A001"
                    // tags the reply to a command the client never sent, so async-imap
                    // discards it as unsolicited and stays parked on LOGIN until the
                    // test gives up -- reported as "the client never connected".
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "tag": e["tag"].as_str().unwrap_or_default(),
                            "status": "OK",
                            "message": "LOGIN completed"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: Server SELECT response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SELECT")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* 5 EXISTS\r\n* 0 RECENT\r\n{} OK [READ-WRITE] SELECT completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that selects a specific mailbox with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via IMAP. Select the INBOX mailbox and report the number of messages.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "IMAP",
                            "instruction": "Authenticate and select INBOX",
                            "startup_params": {
                                "username": "testuser",
                                "password": "testpass",
                                "use_tls": false
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected
                    .on_event("imap_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                        // The client authenticates inside connect() from
                        // startup_params; `authenticate_imap` is not one of its
                        // verbs. Selecting INBOX is the next real step.
                        "type": "select_mailbox",
                        "mailbox": "INBOX"
                    }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Client authenticated
                    .on_event("imap_mailbox_selected")
                    .respond_with_actions(serde_json::json!([
                        {
                        "type": "wait_for_more"
                    }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify the client is IMAP protocol
        assert_eq!(client.protocol, "IMAP", "Client should be IMAP protocol");

        println!("✅ IMAP client selected mailbox successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test IMAP client search functionality
    /// LLM calls: 8 (server: startup, greeting, login, select, search; client: startup, connected, authenticated)
    #[tokio::test]
    async fn test_imap_client_search_messages() -> E2EResult<()> {
        // Start IMAP server with some test messages and mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IMAP. Provide INBOX with 3 unread messages and 2 read messages.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "IMAP",
                            "instruction": "Provide INBOX with 3 unread and 2 read messages"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server greeting
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": "* OK [CAPABILITY IMAP4rev1] IMAP server ready"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Server LOGIN response
                    .on_event("imap_auth")
                    // LOGIN raises imap_auth, not imap_command -- the server's own action
                    // docs say so ("LOGIN is not delivered here - it raises imap_auth
                    // instead"), so a rule on imap_command could never match and the
                    // LOGIN fell through to the LLM, which refused it with NO [SERVERBUG].
                    // async-imap picks its own tags (a1, a2, ...). A hardcoded "A001"
                    // tags the reply to a command the client never sent, so async-imap
                    // discards it as unsolicited and stays parked on LOGIN until the
                    // test gives up -- reported as "the client never connected".
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "tag": e["tag"].as_str().unwrap_or_default(),
                            "status": "OK",
                            "message": "LOGIN completed"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: Server SELECT response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SELECT")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* 5 EXISTS\r\n* 3 RECENT\r\n{} OK [READ-WRITE] SELECT completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 5: Server SEARCH response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SEARCH")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* SEARCH 1 2 3\r\n{} OK SEARCH completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that searches for unread messages with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via IMAP. Select INBOX and search for UNSEEN messages.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("IMAP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "IMAP",
                        "instruction": "Authenticate, select INBOX, search UNSEEN",
                        "startup_params": {
                            "username": "testuser",
                            "password": "testpass",
                            "use_tls": false
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("imap_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        // The client authenticates inside connect() from
                        // startup_params; `authenticate_imap` is not one of its
                        // verbs. Selecting INBOX is the next real step.
                        "type": "select_mailbox",
                        "mailbox": "INBOX"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client authenticated
                .on_event("imap_mailbox_selected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    },
                    {
                        "type": "search_messages",
                        "criteria": "UNSEEN"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify client performed search
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("search"))
                || output.iter().any(|l| l.contains("UNSEEN")),
            "Client should show search operation. Output: {:?}",
            output
        );

        println!("✅ IMAP client searched messages successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test IMAP client fetch message functionality
    /// LLM calls: 9 (server: startup, greeting, login, select, search, fetch; client: startup, connected, authenticated)
    #[tokio::test]
    async fn test_imap_client_fetch_message() -> E2EResult<()> {
        // Start IMAP server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IMAP. Provide INBOX with a message from alice@example.com with subject 'Test Message'.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "IMAP",
                            "instruction": "Provide INBOX with message from alice@example.com"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server greeting
                    .on_event("imap_connection")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": "* OK [CAPABILITY IMAP4rev1] IMAP server ready"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Server LOGIN response
                    .on_event("imap_auth")
                    // LOGIN raises imap_auth, not imap_command -- the server's own action
                    // docs say so ("LOGIN is not delivered here - it raises imap_auth
                    // instead"), so a rule on imap_command could never match and the
                    // LOGIN fell through to the LLM, which refused it with NO [SERVERBUG].
                    // async-imap picks its own tags (a1, a2, ...). A hardcoded "A001"
                    // tags the reply to a command the client never sent, so async-imap
                    // discards it as unsolicited and stays parked on LOGIN until the
                    // test gives up -- reported as "the client never connected".
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "tag": e["tag"].as_str().unwrap_or_default(),
                            "status": "OK",
                            "message": "LOGIN completed"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: Server SELECT response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SELECT")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* 1 EXISTS\r\n* 1 RECENT\r\n{} OK [READ-WRITE] SELECT completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 5: Server SEARCH response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "SEARCH")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* SEARCH 1\r\n{} OK SEARCH completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 6: Server FETCH response
                    .on_event("imap_command")
                    .and_event_data_contains("command", "FETCH")
                    .respond_with_actions_from_event(|e| serde_json::json!([
                        {
                            "type": "send_imap_response",
                            "response": format!("* 1 FETCH (FLAGS (\\Seen) BODY[] {{54}}\r\nFrom: alice@example.com\r\nSubject: Test Message\r\n\r\nBody)\r\n{} OK FETCH completed", e["tag"].as_str().unwrap_or_default())
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that fetches a specific message with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via IMAP. Select INBOX, search for all messages, and fetch the first one.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("IMAP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "IMAP",
                            "instruction": "Authenticate, select INBOX, search and fetch messages",
                            "startup_params": {
                                "username": "testuser",
                                "password": "testpass",
                                "use_tls": false
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected
                    .on_event("imap_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                        // The client authenticates inside connect() from
                        // startup_params; `authenticate_imap` is not one of its
                        // verbs. Selecting INBOX is the next real step.
                        "type": "select_mailbox",
                        "mailbox": "INBOX"
                    }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Client authenticated
                    .on_event("imap_mailbox_selected")
                    .respond_with_actions(serde_json::json!([
                        {
                        "type": "wait_for_more"
                    },
                        {
                            "type": "search_messages",
                            "criteria": "ALL"
                        },
                        {
                            "type": "fetch_message",
                            "message_id": "1",
                            "parts": "BODY[]"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify client fetched message
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("fetch"))
                || output.iter().any(|l| l.contains("message")),
            "Client should show message fetch operation. Output: {:?}",
            output
        );

        println!("✅ IMAP client fetched message successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}
