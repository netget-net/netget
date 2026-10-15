//! E2E tests for the DataLink client: the real NetGet binary, driven by a mock model,
//! opening a **real libpcap handle on loopback** and putting **real frames** on it.
//!
//! # These tests need layer-2 capture access, and say so instead of skipping
//!
//! Nothing here is mocked below the model. `open_client` opens `lo0`/`lo` through libpcap,
//! `inject_frame` reaches `pcap::sendpacket`, and `datalink_frame_captured` fires for traffic
//! this test generates on loopback. That has always been true - the docs used to claim the
//! opposite ("No actual network traffic", "No root privileges required") while depending on
//! exactly that access, so on a host without it the failure arrived as a mock expectation that
//! never fired, several steps from the cause.
//!
//! `require_capture` now states the requirement up front and fails on it. It is deliberately
//! **not** a skip: a silent pass on a runner without BPF access would leave this client's only
//! end-to-end evidence resting on nothing.
//!
//! Test strategy: mock model, < 10 LLM calls total.

#[cfg(all(unix, feature = "libpcap"))]
mod datalink_client_tests {
    use crate::helpers::*;
    use ::netget::privilege::SystemCapabilities;
    use std::time::Duration;

    /// Fail - loudly, and before anything else - on a host that cannot open a capture.
    fn require_capture(test: &str) {
        assert!(
            SystemCapabilities::detect().has_packet_capture_access,
            "{test} opens a real libpcap handle on loopback and injects real frames, and this \
             process has no layer-2 capture access (macOS/BSD: read access to /dev/bpf*, via \
             sudo or Wireshark's ChmodBPF; Linux: root or `setcap cap_net_raw+ep`). Skipping \
             would report a pass for a test that exercised nothing."
        );
    }

    /// Test DataLink client frame injection
    /// LLM calls: 2 (client startup, frame injected event)
    #[tokio::test]
    async fn test_datalink_client_inject_frame_with_mocks() -> E2EResult<()> {
        require_capture("test_datalink_client_inject_frame_with_mocks");

        // Start a DataLink client that injects an ARP frame
        let client_config =
            NetGetConfig::new("Connect to lo0 via DataLink. Inject an ARP request for 10.0.0.2")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Client startup (user command)
                        // Matches the initial user command only. It used to be `.on_any()`,
                        // which -- being the first rule, and rules are first-match-wins --
                        // also swallowed every network event: once this client started
                        // raising a connected event, that event was answered with another
                        // `open_client` and the mock counted eleven calls.
                        .on_instruction_containing("DataLink")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": "lo0",
                                "protocol": "DataLink",
                                "startup_params": {
                                    "interface": "lo0",
                                    "promiscuous": false
                                },
                                "instruction": "Inject ARP request for 10.0.0.2"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: the capture is open -- inject the frame the
                        // instruction asks for. Nothing else triggers an injection.
                        .on_event("datalink_connected")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "inject_frame",
                                "frame_hex": "ffffffffffff001122334455080600010800060400010011223344550a0000010000000000000a000002"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 3: Frame injected event
                        .on_event("datalink_frame_injected")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "wait_for_more"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        // Give client time to start and inject frame
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["DataLink", "datalink"], 30).await;
        assert!(
            client.output_contains("DataLink").await || client.output_contains("datalink").await,
            "Client should show DataLink protocol. Output: {:?}",
            client.get_output().await
        );

        println!("✅ DataLink client injected frame successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DataLink client with promiscuous mode capture
    /// LLM calls: 3 (client startup, frame injected, frame captured)
    #[tokio::test]
    async fn test_datalink_client_promiscuous_capture_with_mocks() -> E2EResult<()> {
        require_capture("test_datalink_client_promiscuous_capture_with_mocks");

        // Start a DataLink client in promiscuous mode
        let client_config = NetGetConfig::new(
            "Connect to lo0 via DataLink with promiscuous mode. Monitor all frames.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                // Matches the initial user command only; see the note in the first test
                // for why `.on_any()` cannot be used now that a connected event exists.
                .on_instruction_containing("DataLink")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "lo0",
                        "protocol": "DataLink",
                        "startup_params": {
                            "interface": "lo0",
                            "promiscuous": true
                        },
                        "instruction": "Monitor all frames on lo0"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: the capture is open. Nothing to inject here -- this test is
                // about the receive side.
                .on_event("datalink_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Frame captured event
                .on_event("datalink_frame_captured")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_at_least(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give the capture handle time to open before generating anything to capture.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Put some traffic on lo0. The test asserted that a frame was captured while
        // generating no frames at all, so it was waiting on whatever happened to cross
        // the loopback interface. A connection to a listener we own is deterministic.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"datalink capture probe").await;
            }
        });
        for _ in 0..5 {
            if let Ok(mut sock) = tokio::net::TcpStream::connect(addr).await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"datalink capture probe").await;
                let _ = sock.flush().await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("✅ DataLink client in promiscuous mode processed mocked capture");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DataLink client inject and respond pattern
    /// LLM calls: 3 (client startup, frame injected, frame captured with response)
    #[tokio::test]
    async fn test_datalink_client_inject_and_respond_with_mocks() -> E2EResult<()> {
        require_capture("test_datalink_client_inject_and_respond_with_mocks");

        // Both directions on one client: inject a frame, and capture one.
        //
        // This used to open `eth0` and wait for a real ARP reply from 192.168.1.1. There
        // is no eth0 on macOS and no host at that address in a test environment, so it
        // could not pass anywhere this suite runs -- it was a live-network test wearing a
        // mock's clothes. It runs on lo0 now, and the frame it captures is loopback
        // traffic this test generates rather than an ARP reply. What that still asserts is
        // the thing the client is responsible for: raising `datalink_frame_injected` for
        // what it sends and `datalink_frame_captured` for what arrives.
        let client_config = NetGetConfig::new(
            "Connect to lo0 via DataLink with promiscuous mode. Send a frame and watch for replies."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                // Matches the initial user command only; see the note in the first test
                // for why `.on_any()` cannot be used now that a connected event exists.
                .on_instruction_containing("DataLink")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "lo0",
                        "protocol": "DataLink",
                        "startup_params": {
                            "interface": "lo0",
                            "promiscuous": true
                        },
                        "instruction": "Send a frame and watch for replies"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: capture is open -- send the frame.
                .on_event("datalink_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "inject_frame",
                        "frame_hex": "ffffffffffff001122334455080600010800060400010011223344550a0000010000000000000a000002"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Frame injected
                .on_event("datalink_frame_injected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_at_least(1)
                .and()
                // Mock 4: Frame captured
                .on_event("datalink_frame_captured")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_at_least(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Let the capture handle open before generating anything to capture.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Traffic for the capture side to see.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"datalink capture probe").await;
            }
        });
        for _ in 0..5 {
            if let Ok(mut sock) = tokio::net::TcpStream::connect(addr).await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"datalink capture probe").await;
                let _ = sock.flush().await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("✅ DataLink client completed inject-and-respond pattern");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DataLink client disconnect
    /// LLM calls: 2 (client startup, disconnect action)
    #[tokio::test]
    async fn test_datalink_client_disconnect_with_mocks() -> E2EResult<()> {
        require_capture("test_datalink_client_disconnect_with_mocks");

        // Start a DataLink client and disconnect gracefully
        let client_config =
            NetGetConfig::new("Connect to lo0 via DataLink. Inject one frame then disconnect.")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Client startup
                        // Matches the initial user command only. It used to be `.on_any()`,
                        // which -- being the first rule, and rules are first-match-wins --
                        // also swallowed every network event: once this client started
                        // raising a connected event, that event was answered with another
                        // `open_client` and the mock counted eleven calls.
                        .on_instruction_containing("DataLink")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": "lo0",
                                "protocol": "DataLink",
                                "startup_params": {
                                    "interface": "lo0",
                                    "promiscuous": false
                                },
                                "instruction": "Inject one frame then disconnect"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: the capture is open -- inject the frame.
                        .on_event("datalink_connected")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "inject_frame",
                                "frame_hex": "ffffffffffff001122334455080600010800060400010011223344550a0000010000000000000a000002"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 3: Frame injected, then disconnect
                        .on_event("datalink_frame_injected")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "disconnect"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        // Give client time to inject and disconnect
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ DataLink client injected frame and disconnected gracefully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
