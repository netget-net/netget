//! E2E tests for the AMQP client
//!
//! A mocked NetGet **broker** and a mocked NetGet **client** (lapin) over a real socket.
//!
//! ## What these replace
//!
//! `test_amqp_client_connect` could not run at all. Two mocks were stale and one was
//! impossible:
//!
//! 1. The broker rule answered `amqp_connection_received` with `send_amqp_frame`. Neither the
//!    event nor the action exists on the rewritten AMQP broker, whose handshake event is
//!    `amqp_connection_open` and whose reply is `amqp_connection_open_ok`. Nothing matched, so
//!    the broker never let the client in and `lapin::Connection::connect` never returned.
//! 2. The client rule answered `amqp_connected` with `wait_for_more`, which is not an AMQP
//!    client action — the client's whole vocabulary is `open_channel` and `disconnect` — so
//!    `mock_action_names` panicked while the test was being configured.
//! 3. Every `expect_calls` was commented out, so `verify_mocks()` asserted nothing.

mod amqp_client_tests {
    use crate::helpers::client::start_netget_client;
    use crate::helpers::netget::NetGetConfig;
    use crate::helpers::*;
    use std::time::Duration;

    /// The client completes an AMQP 0-9-1 handshake against the NetGet broker.
    ///
    /// The assertion is the broker's `amqp_connection_open`: it fires only after the protocol
    /// header, `Connection.Start`/`Start-Ok` and `Tune`/`Tune-Ok` have all crossed the wire and
    /// the client has asked for a vhost. The client's `amqp_connected` then fires only if the
    /// broker's `Connection.Open-Ok` came back, so the pair pins both directions.
    ///
    /// LLM calls: 4 (broker startup + amqp_connection_open, client startup + amqp_connected).
    #[tokio::test]
    async fn test_amqp_client_connect() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via AMQP. Accept all client connections.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("AMQP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "AMQP",
                    "instruction": "Accept all client connections"
                }]))
                .expect_calls(1)
                .and()
                // Fires when the handshake finished and the client asked for a vhost.
                // Answering with anything else (or nothing) refuses the connection.
                .on_event("amqp_connection_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "amqp_connection_open_ok"
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✓ AMQP broker started on port {}", server.port);

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via AMQP. Open a channel once the connection is established."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("AMQP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "AMQP",
                    "instruction": "Open a channel once connected"
                }]))
                .expect_calls(1)
                .and()
                // `open_channel` is one of the two actions this client can execute; the other
                // is `disconnect`. Reaching this event at all is the assertion — it fires only
                // after lapin's connect() returned, which needs the broker's Open-Ok.
                .on_event("amqp_connected")
                .respond_with_actions(serde_json::json!([{ "type": "open_channel" }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        assert_eq!(client.protocol, "AMQP", "Client should be AMQP protocol");

        println!("✓ AMQP client completed the handshake against the NetGet broker");

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

    /// AMQP is detected from several phrasings of the same request.
    ///
    /// No broker is started, so `open_client` fails to connect and `start_netget_client`
    /// returns `Err`. That is fine and is what the `Err` arm asserts on: the failure must be a
    /// connection failure, not "unknown protocol". If a broker does happen to be listening on
    /// 5672, the `Ok` arm asserts the client came up as AMQP and that the startup rule was
    /// used exactly once.
    ///
    /// LLM calls: 1 per prompt, 3 total.
    #[tokio::test]
    async fn test_amqp_client_protocol_detection() -> E2EResult<()> {
        let amqp_prompts = [
            "Connect to localhost:5672 via AMQP",
            "Connect to RabbitMQ at localhost:5672",
            "Connect via AMQP broker at localhost:5672",
        ];

        for prompt in amqp_prompts {
            println!("Testing client prompt: {prompt}");

            let client_config = NetGetConfig::new(prompt).with_mock(|mock| {
                mock.on_any()
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_client",
                        "remote_addr": "localhost:5672",
                        "protocol": "AMQP",
                        "instruction": "Connect to AMQP broker"
                    }]))
                    .expect_calls(1)
                    .and()
            });

            match start_netget_client(client_config).await {
                Ok(client) => {
                    assert_eq!(
                        client.protocol, "AMQP",
                        "AMQP protocol should be detected from prompt '{prompt}'"
                    );
                    println!("  ✓ AMQP client detected from: {prompt}");

                    // Wait for the exchange the mocks describe, rather than trusting a fixed
                    // sleep to have covered it. Under load the last response routinely lands
                    // after the sleep expires, and the test reports it as never having happened.
                    client.wait_for_mocks(30).await;
                    client.verify_mocks().await?;
                    client.stop().await?;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    assert!(
                        !error_msg.to_lowercase().contains("unknown"),
                        "AMQP should be detected from prompt '{prompt}', got: {error_msg}"
                    );
                    println!("  ✓ AMQP detected (connection failed as expected)");
                }
            }
        }

        println!("✓ AMQP client keyword detection working");
        Ok(())
    }
}
