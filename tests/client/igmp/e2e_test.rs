//! E2E tests for IGMP client
//!
//! These tests verify IGMP client functionality by spawning the actual NetGet binary
//! and testing multicast group join/leave behavior as a black-box.
//! Test strategy: Use netget binary to start IGMP client, < 10 LLM calls total.

#[cfg(unix)]
mod igmp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// Test IGMP client can join a multicast group and receive data
    /// LLM calls: 2 (client startup, multicast join)
    #[tokio::test]
    async fn test_igmp_client_join_and_receive() -> E2EResult<()> {
        // Start IGMP client and instruct it to join a multicast group
        let multicast_group = "239.255.1.1";
        // Learn the UDP port from the connected event, while the client keeps
        // the actual socket bound; a released TCP reservation cannot protect it.
        let bound_port = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0));
        let event_port = bound_port.clone();
        let multicast_port = 0;

        let client_config = NetGetConfig::new(format!(
            "Start IGMP client on port {}. Join multicast group {} and log all received data.",
            multicast_port, multicast_group
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Start IGMP client")
                .and_instruction_containing("239.255.1.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        // The IGMP client binds whatever address it is opened with, and
                        // maps the placeholder "igmp" to 0.0.0.0:0 -- an ephemeral port.
                        // The test then sent its packet to :15000, where nothing was
                        // listening, so `igmp_data_received` could never fire.
                        "remote_addr": format!("0.0.0.0:{}", multicast_port),
                        "protocol": "igmp",
                        "instruction": "Join multicast group 239.255.1.1 and listen"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (igmp_connected event)
                .on_event("igmp_connected")
                .respond_with_actions_from_event(move |event| {
                    let address: std::net::SocketAddr =
                        event["local_addr"].as_str().unwrap().parse().unwrap();
                    event_port.store(address.port(), std::sync::atomic::Ordering::SeqCst);
                    serde_json::json!([
                        {
                            "type": "join_multicast_group",
                            "multicast_addr": "239.255.1.1",
                            "interface_addr": "0.0.0.0"
                        }
                    ])
                })
                .expect_calls(1)
                .and()
                // Mock 3: Data received (igmp_data_received event)
                .on_event("igmp_data_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to start and join the group

        // Verify client shows it's ready
        client.wait_for_any(&["IGMP"], 30).await;
        assert!(
            client.output_contains("IGMP").await,
            "Client should show IGMP initialization. Output: {:?}",
            client.get_output().await
        );

        println!("✅ IGMP client initialized");

        client.wait_for_any(&["Joined multicast group"], 30).await;
        let multicast_port = bound_port.load(std::sync::atomic::Ordering::SeqCst);
        assert_ne!(
            multicast_port, 0,
            "connected event must report the bound UDP port"
        );

        // Send a multicast packet to the group
        let sender = UdpSocket::bind("0.0.0.0:0").await?;
        let test_data = b"HELLO_MULTICAST";
        let dest = format!("{}:{}", multicast_group, multicast_port);
        sender.send_to(test_data, &dest).await?;

        println!("✅ Sent multicast packet to {}", dest);

        // Give client time to receive and process

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test IGMP client can join and leave multicast groups
    /// LLM calls: 3 (client startup, join, leave)
    #[tokio::test]
    async fn test_igmp_client_join_and_leave() -> E2EResult<()> {
        let multicast_group = "239.255.1.2";

        let client_config = NetGetConfig::new(format!(
            "Start IGMP client. Join multicast group {}, then immediately leave it.",
            multicast_group
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Start IGMP client")
                .and_instruction_containing("239.255.1.2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "igmp",
                        "protocol": "igmp",
                        "instruction": "Join and then leave multicast group"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (igmp_connected event)
                .on_event("igmp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "join_multicast_group",
                        "multicast_addr": "239.255.1.2",
                        "interface_addr": "0.0.0.0"
                    },
                    {
                        "type": "leave_multicast_group",
                        "multicast_addr": "239.255.1.2",
                        "interface_addr": "0.0.0.0"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to process
        client.wait_for_mocks(30).await;

        // Verify client processed the instructions
        assert_eq!(client.protocol, "igmp", "Client should be IGMP protocol");

        println!("✅ IGMP client joined and left multicast group");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test IGMP client can send multicast data
    /// LLM calls: 2 (client startup, send)
    ///
    /// The send is asserted on the wire, against a real receiver. This test used to mock the
    /// connected event with a `"data"` field where the action declares `"data_hex"`, so
    /// `execute_action` refused it with "Missing data_hex", the datagram was never sent, and
    /// the only assertions left — `client.protocol == "igmp"` and the mock call counts — were
    /// satisfied by the *request* rather than by anything the client did with the answer. It
    /// passed for exactly as long as it proved nothing.
    ///
    /// The destination is a loopback socket rather than a real group: `send_multicast` is a
    /// plain `send_to` on the client's own socket, so this exercises the whole path, while a
    /// real group would make the test depend on the host having a multicast-capable interface
    /// and on IGMP snooping.
    #[tokio::test]
    async fn test_igmp_client_send_multicast() -> E2EResult<()> {
        let multicast_group = "239.255.1.3";
        let sink = UdpSocket::bind("127.0.0.1:0").await?;
        let sink_addr = sink.local_addr()?;
        let multicast_port = sink_addr.port();

        let client_config = NetGetConfig::new(format!(
            "Start IGMP client. Send the string 'TEST' to multicast group {} port {}.",
            multicast_group, multicast_port
        ))
        .with_mock(move |mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Start IGMP client")
                .and_instruction_containing("239.255.1.3")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "igmp",
                        "protocol": "igmp",
                        "instruction": "Send TEST to multicast group"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (igmp_connected event)
                .on_event("igmp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_multicast",
                        // The parameter is `data_hex`, and the executor decodes it. A `data`
                        // key here is silently not the field the action declares.
                        "multicast_addr": sink_addr.ip().to_string(),
                        "port": multicast_port,
                        "data_hex": "54455354" // "TEST" in hex
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for the bytes, not for a sleep. Four bytes of "TEST" have to arrive at a
        // socket this test owns; nothing else in this file proves the send happened.
        let mut buf = vec![0u8; 64];
        let received = tokio::time::timeout(Duration::from_secs(30), sink.recv_from(&mut buf))
            .await
            .is_ok();
        assert!(
            received,
            "the IGMP client never sent its datagram. Output: {:?}",
            client.get_output().await
        );
        assert_eq!(&buf[..4], b"TEST", "the decoded hex must reach the wire");

        // Verify client is IGMP protocol
        assert_eq!(client.protocol, "igmp", "Client should be IGMP protocol");

        println!("✅ IGMP client sent multicast data");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }
}
