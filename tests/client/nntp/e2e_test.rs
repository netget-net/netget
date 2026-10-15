//! E2E tests for NNTP client
//!
//! These tests verify NNTP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//!
//! **The `nntp_response_received` rules assert `expect_calls(1)`, not `expect_at_most(1)`.**
//! They used to be `at_most`, which is satisfied by *zero* calls — so the only thing these
//! tests proved was that the client could connect. That mattered: the client held a
//! `client_data` mutex guard borrowed out of a `match` scrutinee across every arm and then
//! re-locked it inside `apply_action`, so it deadlocked the instant it executed the model's
//! first command. The command still reached the wire, so the *server's* expectations passed;
//! the client then never read the reply and the `at_most` rule quietly recorded 0. Requiring
//! exactly one call is what makes the reply-reading path observable.

mod nntp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test NNTP client connection and basic command
    /// LLM calls: 4 (server startup, greeting, client connection, command)
    #[tokio::test]
    async fn test_nntp_client_connect_and_list() -> E2EResult<()> {
        // Start an NNTP server listening on an available port
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via NNTP. Respond to LIST commands with a test newsgroup 'test.misc'.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NNTP",
                        "instruction": "NNTP server - respond to LIST commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: greeting (the server asks the LLM for it as command "GREETING")
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "GREETING")
                .respond_with_actions(serde_json::json!([
                    { "type": "send_nntp_response", "code": 200, "text": "netget ready" }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: LIST command received
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "LIST")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_nntp_list",
                        "groups": [ { "name": "test.misc", "high": 100, "low": 1, "status": "y" } ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an NNTP client that connects and sends LIST command
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via NNTP. Send LIST command to get available newsgroups.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "NNTP",
                        "instruction": "Send LIST command"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connected - send LIST
                .on_event("nntp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "nntp_list"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: LIST response received
                .on_event("nntp_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and execute command

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ NNTP client connected and executed LIST command successfully");

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

    /// Test NNTP client can select a newsgroup
    /// LLM calls: 4 (server startup, greeting, client connection, command)
    #[tokio::test]
    async fn test_nntp_client_select_group() -> E2EResult<()> {
        // Start an NNTP server
        let server_config = NetGetConfig::new(
            "Listen on port {} via NNTP. Respond to GROUP commands. For group 'comp.lang.rust', respond with '211 10 1 10 comp.lang.rust'.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NNTP",
                        "instruction": "NNTP server - respond to GROUP commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: greeting (the server asks the LLM for it as command "GREETING")
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "GREETING")
                .respond_with_actions(serde_json::json!([
                    { "type": "send_nntp_response", "code": 200, "text": "netget ready" }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: GROUP command received
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "GROUP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_nntp_group",
                        "name": "comp.lang.rust",
                        "count": 10,
                        "low": 1,
                        "high": 10
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that selects a newsgroup
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via NNTP. Select the newsgroup 'comp.lang.rust' using GROUP command.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "NNTP",
                        "instruction": "Select newsgroup comp.lang.rust"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connected - send GROUP command
                .on_event("nntp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "nntp_group",
                        "group_name": "comp.lang.rust"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: GROUP response received
                .on_event("nntp_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Verify the client is NNTP protocol
        assert_eq!(client.protocol, "NNTP", "Client should be NNTP protocol");

        // Verify client shows connection
        client.wait_for_any(&["connected", "NNTP"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("NNTP").await,
            "Client should show NNTP connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ NNTP client selected newsgroup successfully");

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

    /// Test NNTP client can retrieve articles
    /// LLM calls: 4 (server startup, greeting, client connection, command)
    #[tokio::test]
    async fn test_nntp_client_retrieve_article() -> E2EResult<()> {
        // Start an NNTP server
        let server_config = NetGetConfig::new(
            "Listen on port {} via NNTP. Respond to ARTICLE commands with a test article containing headers and body.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NNTP",
                        "instruction": "NNTP server - respond to ARTICLE commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: greeting (the server asks the LLM for it as command "GREETING")
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "GREETING")
                .respond_with_actions(serde_json::json!([
                    { "type": "send_nntp_response", "code": 200, "text": "netget ready" }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: ARTICLE command received
                .on_event("nntp_command_received")
                .and_event_data_contains("command", "ARTICLE")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_nntp_article",
                        "code": 220,
                        "message_id": "<1@example.com>",
                        "headers": "Subject: Test Article\r\nFrom: test@example.com",
                        "body": "This is the article body."
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that retrieves an article
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via NNTP. Retrieve article 1 using ARTICLE command.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("NNTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "NNTP",
                        "instruction": "Retrieve article 1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connected - send ARTICLE command
                .on_event("nntp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "nntp_article",
                        "article_id": "1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: ARTICLE response received
                .on_event("nntp_response_received")
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

        // Verify the client is NNTP protocol
        assert_eq!(client.protocol, "NNTP", "Client should be NNTP protocol");

        println!("✅ NNTP client retrieved article successfully");

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
