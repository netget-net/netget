//! E2E tests for SIP client
//!
//! These tests verify SIP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.

mod sip_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test SIP client REGISTER with server
    /// LLM calls: 4 (server startup script + client connection + REGISTER response + final state)
    #[tokio::test]
    async fn test_sip_client_register() -> E2EResult<()> {
        // Start a SIP server that accepts REGISTER requests with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SIP. \
             Accept all REGISTER requests with 200 OK, expires 3600. \
             Use scripting mode for fast responses.",
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup with scripting
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("SIP")
                .and_instruction_containing("REGISTER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SIP",
                        "instruction": "Accept REGISTER with 200 OK",
                        "scripting": true
                    }
                ]))
                .expect_calls(1)
                .and()
                // The server had no rule for the request event at all, so every
                // request fell through to a real LLM call, the server answered 503,
                // and the client's rule -- which waits for a 200 -- reported zero
                // calls. The response verb is named after the request method.
                .on_event("sip_register")
                .respond_with_actions(serde_json::json!([
                    { "type": "sip_register", "status_code": 200, "reason_phrase": "OK", "expires": 3600 }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start a SIP client that registers with this server with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SIP. \
             Send REGISTER request for sip:alice@localhost with contact sip:alice@127.0.0.1:5060. \
             Request expires 3600. \
             Log the response status code.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("SIP")
                .and_instruction_containing("REGISTER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "SIP",
                        "instruction": "Send REGISTER for alice@localhost"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Client connected - send REGISTER
                .on_event("sip_client_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "sip_register",
                        "from": "sip:alice@localhost",
                        "to": "sip:alice@localhost",
                        "request_uri": format!("sip:127.0.0.1:{}", server.port),
                        "contact": "sip:alice@127.0.0.1:5060",
                        "expires": 3600
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Response received (200 OK) - wait for more
                .on_event("sip_client_response_received")
                .and_event_data_contains("status_code", "200")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and REGISTER
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected", "SIP"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("SIP").await,
            "Client should show SIP connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SIP client registered with server successfully");

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

    /// Test SIP client OPTIONS query
    /// LLM calls: 4 (server startup script + client connection + OPTIONS response + final state)
    #[tokio::test]
    async fn test_sip_client_options() -> E2EResult<()> {
        // Start a SIP server that responds to OPTIONS with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SIP. \
             Respond to OPTIONS requests with 200 OK and Allow: INVITE, ACK, BYE, REGISTER, OPTIONS. \
             Use scripting mode for fast responses."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup with scripting
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("SIP")
                .and_instruction_containing("OPTIONS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SIP",
                        "instruction": "Respond to OPTIONS with 200 OK and Allow header",
                        "scripting": true
                    }
                ]))
                .expect_calls(1)
                .and()
                // The server had no rule for the request event at all, so every request
                // fell through to a real LLM call, the server answered 503, and the
                // client's rule -- which waits for a 200 -- reported zero calls. The
                // response verb is named after the request method.
                .on_event("sip_options")
                .respond_with_actions(serde_json::json!([
                    { "type": "sip_options", "status_code": 200, "allow_methods": "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER" }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start a SIP client that queries server capabilities with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SIP. \
             Send OPTIONS request to sip:server@localhost. \
             Log the Allow header from the response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("SIP")
                .and_instruction_containing("OPTIONS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "SIP",
                        "instruction": "Send OPTIONS to query capabilities"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Client connected - send OPTIONS
                .on_event("sip_client_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "sip_options",
                        "from": "sip:client@localhost",
                        "to": "sip:server@localhost",
                        "request_uri": format!("sip:127.0.0.1:{}", server.port)
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Response received (200 OK) - wait for more
                .on_event("sip_client_response_received")
                .and_event_data_contains("status_code", "200")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Verify client initiated SIP connection
        assert_eq!(client.protocol, "SIP", "Client should be SIP protocol");

        println!("✅ SIP client OPTIONS query successful");

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

    /// Test SIP client INVITE call attempt
    /// LLM calls: 4-5 (server startup script + client connection + INVITE response + possible ACK + final state)
    #[tokio::test]
    async fn test_sip_client_invite() -> E2EResult<()> {
        // Start a SIP server that accepts INVITE requests with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SIP. \
             Accept all INVITE requests with 200 OK and SDP: v=0 o=server 0 0 IN IP4 127.0.0.1 s=Call c=IN IP4 127.0.0.1 t=0 0 m=audio 8000 RTP/AVP 0. \
             Use scripting mode for fast responses."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup with scripting
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("SIP")
                .and_instruction_containing("INVITE")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SIP",
                        "instruction": "Accept INVITE with 200 OK and SDP",
                        "scripting": true
                    }
                ]))
                .expect_calls(1)
                .and()
                // The server had no rule for the request event at all, so every request
                // fell through to a real LLM call, the server answered 503, and the
                // client's rule -- which waits for a 200 -- reported zero calls. The
                // response verb is named after the request method.
                .on_event("sip_invite")
                .respond_with_actions(serde_json::json!([
                    { "type": "sip_invite", "status_code": 200, "reason_phrase": "OK" }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start a SIP client that initiates a call with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SIP. \
             Send INVITE to sip:bob@localhost with SDP: v=0 o=alice 0 0 IN IP4 127.0.0.1 s=Call c=IN IP4 127.0.0.1 t=0 0 m=audio 49170 RTP/AVP 0. \
             Wait for 200 OK response and log the SDP body.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("SIP")
                .and_instruction_containing("INVITE")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "SIP",
                        "instruction": "Send INVITE to bob@localhost"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Client connected - send INVITE
                .on_event("sip_client_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "sip_invite",
                        "from": "sip:alice@localhost",
                        "to": "sip:bob@localhost",
                        "request_uri": format!("sip:127.0.0.1:{}", server.port),
                        "contact": "sip:alice@127.0.0.1:5060",
                        "sdp": "v=0\r\no=alice 0 0 IN IP4 127.0.0.1\r\ns=Call\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\n"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Response received (200 OK) - wait for more
                .on_event("sip_client_response_received")
                .and_event_data_contains("status_code", "200")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Verify client shows INVITE interaction
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("SIP"))
                || output.iter().any(|l| l.contains("INVITE"))
                || output.iter().any(|l| l.contains("200")),
            "Client should show SIP INVITE interaction. Output: {:?}",
            output
        );

        println!("✅ SIP client INVITE successful");

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
