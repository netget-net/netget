//! E2E tests for UDP client
//!
//! These tests verify UDP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.
//!
//! All four tests here used to fail. The mocks were wrong in three independent ways and
//! nothing ever started:
//!
//! 1. `on_instruction_containing("udp")` is a case-sensitive substring match, and every
//!    instruction says "via UDP". No rule ever matched, so each run ended in
//!    "LLM failed to generate valid response after retries".
//! 2. The rule that was supposed to start the *server* answered with `open_client`. Even
//!    matching, it would not have opened a listener.
//! 3. The client configs carried no mock at all, yet called `verify_mocks()` on them.
//!
//! They follow the shape in `tests/client/tcp/e2e_test.rs` now: server mock answers
//! `open_server`, client mock answers `open_client`, and each mocks the protocol event its
//! assertion depends on.

mod udp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test UDP client connection to a local server
    /// LLM calls: 2 (server startup, client startup)
    #[tokio::test]
    async fn test_udp_client_connect_to_server() -> E2EResult<()> {
        // Start a UDP server listening on an available port
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. Echo received datagrams back to sender.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Echo server - respond with exactly what is received"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a UDP client that connects to this server
        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via UDP. Send 'HELLO' datagram and wait for response."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "UDP",
                    "instruction": "Send HELLO and wait for response"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to bind
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection (socket bound)
        client.wait_for_any(&["ready", "bound"], 30).await;
        assert!(
            client.output_contains("ready").await || client.output_contains("bound").await,
            "Client should show ready/bound message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ UDP client connected to server successfully");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test UDP client sends a datagram the server actually receives
    /// LLM calls: 4 (server startup, server datagram, client startup, client connected)
    #[tokio::test]
    async fn test_udp_client_send_datagram() -> E2EResult<()> {
        // Server logs every datagram and answers it, which is what proves the send arrived
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. Log all incoming datagrams.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Log every datagram and acknowledge it"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_udp_response",
                    "data": "ACK",
                    "encoding": "text"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client sends PING on connect. "PING" is 50494e47 in hex.
        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via UDP and send the string 'PING' then wait for response."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "UDP",
                    "instruction": "Send PING and wait for response"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_connected")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_udp_datagram",
                    "data_hex": "50494e47"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        assert_eq!(client.protocol, "UDP", "Client should be UDP protocol");

        println!("✅ UDP client sent a datagram the server received");

        // The server mock asserts udp_datagram_received fired exactly once, which is the
        // real check that the client's datagram arrived.
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test UDP client can receive and respond to datagrams
    /// LLM calls: 5 (server startup, server datagram, client startup, client connected,
    /// client datagram received)
    #[tokio::test]
    async fn test_udp_client_receive_and_respond() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. When you receive a datagram, send 'PONG' back.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Reply PONG to every datagram"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_udp_response",
                    "data": "PONG",
                    "encoding": "text"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client sends PING (50494e47) and must observe the PONG coming back
        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via UDP. Send 'PING' and display any response you receive."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "UDP",
                    "instruction": "Send PING and show the response"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_connected")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_udp_datagram",
                    "data_hex": "50494e47"
                }]))
                .expect_calls(1)
                .and()
                // Firing at all is the assertion: it only happens if PONG arrived.
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "show_message",
                    "message": "Received PONG from server"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("datagram"))
                || output.iter().any(|l| l.contains("received"))
                || output.iter().any(|l| l.contains("PONG")),
            "Client should show received datagram. Output: {output:?}"
        );

        println!("✅ UDP client received and processed response");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test UDP client can change target address
    /// LLM calls: 5 (two server startups, client startup, client connected, one datagram)
    #[tokio::test]
    async fn test_udp_client_change_target() -> E2EResult<()> {
        // Two servers. The client sends to the first, retargets, then sends to the second;
        // each server's udp_datagram_received mock asserts it got exactly one datagram, which
        // is what proves change_target moved the traffic.
        let server1_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. Log 'SERVER1' for each datagram.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Log SERVER1 for each datagram"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ignore_datagram"
                }]))
                .expect_calls(1)
                .and()
        });
        let mut server1 = start_netget_server(server1_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let server2_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. Log 'SERVER2' for each datagram.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("UDP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Log SERVER2 for each datagram"
                }]))
                .expect_calls(1)
                .and()
                .on_event("udp_datagram_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "ignore_datagram"
                }]))
                .expect_calls(1)
                .and()
        });
        let mut server2 = start_netget_server(server2_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // HELLO1 is 48454c4c4f31, HELLO2 is 48454c4c4f32
        let remote1 = format!("127.0.0.1:{}", server1.port);
        let remote2 = format!("127.0.0.1:{}", server2.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote1} via UDP. Send 'HELLO1'. Then change target to {remote2} and send 'HELLO2'."
        ))
        .with_mock({
            let remote1 = remote1.clone();
            let remote2 = remote2.clone();
            move |mock| {
                mock.on_instruction_containing("Connect to")
                    .and_instruction_containing("UDP")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_client",
                        "remote_addr": remote1,
                        "protocol": "UDP",
                        "instruction": "Send HELLO1, retarget, send HELLO2"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("udp_connected")
                    .respond_with_actions(serde_json::json!([
                        {"type": "send_udp_datagram", "data_hex": "48454c4c4f31"},
                        {"type": "change_target", "new_target": remote2},
                        {"type": "send_udp_datagram", "data_hex": "48454c4c4f32"}
                    ]))
                    .expect_calls(1)
                    .and()
            }
        });

        let mut client = start_netget_client(client_config).await?;

        server1.wait_for_mocks(30).await;

        assert_eq!(client.protocol, "UDP", "Client should be UDP protocol");

        println!("✅ UDP client successfully changed target address");

        // Each server saw exactly one datagram — the retarget worked.
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server1.wait_for_mocks(30).await;
        server1.verify_mocks().await?;
        server1.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server2.wait_for_mocks(30).await;
        server2.verify_mocks().await?;
        server2.stop().await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
