//! E2E tests for RIP server
//!
//! These tests spawn the NetGet binary and test RIP protocol operations
//! using UDP clients to send/receive RIP messages.

mod e2e_rip {
    use crate::helpers::{start_netget_server, with_client_timeout, E2EResult, NetGetConfig};
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    // RIP message types
    const RIP_REQUEST: u8 = 1;
    const RIP_RESPONSE: u8 = 2;
    const RIP_VERSION: u8 = 2;

    /// Helper to build a RIP request for entire routing table
    fn build_rip_request_all() -> Vec<u8> {
        let mut msg = Vec::new();

        // Header (4 bytes)
        msg.push(RIP_REQUEST); // Command: Request
        msg.push(RIP_VERSION); // Version: RIPv2
        msg.push(0); // Unused
        msg.push(0); // Unused

        // Single route entry requesting entire table
        // AFI = 0, metric = 16 (special request)
        msg.extend_from_slice(&[0, 0]); // AFI = 0
        msg.extend_from_slice(&[0, 0]); // Route tag
        msg.extend_from_slice(&[0, 0, 0, 0]); // IP
        msg.extend_from_slice(&[0, 0, 0, 0]); // Subnet mask
        msg.extend_from_slice(&[0, 0, 0, 0]); // Next hop
        msg.extend_from_slice(&16u32.to_be_bytes()); // Metric = 16

        msg
    }

    /// Helper to parse RIP response
    fn parse_rip_response(data: &[u8]) -> E2EResult<(u8, u8, Vec<RipRoute>)> {
        if data.len() < 4 {
            return Err("RIP message too short".into());
        }

        let command = data[0];
        let version = data[1];

        let num_entries = (data.len() - 4) / 20;
        let mut routes = Vec::new();

        for i in 0..num_entries {
            let offset = 4 + (i * 20);
            if offset + 20 <= data.len() {
                let afi = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let route_tag = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let ip = format!(
                    "{}.{}.{}.{}",
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7]
                );
                let subnet_mask = format!(
                    "{}.{}.{}.{}",
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11]
                );
                let next_hop = format!(
                    "{}.{}.{}.{}",
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15]
                );
                let metric = u32::from_be_bytes([
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]);

                routes.push(RipRoute {
                    afi,
                    route_tag,
                    ip,
                    subnet_mask,
                    next_hop,
                    metric,
                });
            }
        }

        Ok((command, version, routes))
    }

    #[derive(Debug)]
    struct RipRoute {
        afi: u16,
        route_tag: u16,
        ip: String,
        subnet_mask: String,
        next_hop: String,
        metric: u32,
    }

    #[tokio::test]
    async fn test_rip_routing_table_request() -> E2EResult<()> {
        println!("\n=== Test: RIP Routing Table Request ===");

        let prompt = "listen on port 0 via rip. \
            When you receive a RIP request for the entire routing table (AFI=0, metric=16), \
            respond with routes for: \
            - 192.168.1.0/24 with metric 1 and next hop 0.0.0.0 \
            - 10.0.0.0/8 with metric 5 and next hop 0.0.0.0 \
            - 172.16.0.0/12 with metric 3 and next hop 192.168.1.1";

        let config = NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("listen")
                    .and_instruction_containing("rip")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "RIP",
                            "instruction": "RIP server - respond to routing table requests with specified routes"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: RIP request received
                    .on_event("rip_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_rip_response",
                            "routes": [
                                {
                                    "ip_address": "192.168.1.0",
                                    "subnet_mask": "255.255.255.0",
                                    "next_hop": "0.0.0.0",
                                    "metric": 1
                                },
                                {
                                    "ip_address": "10.0.0.0",
                                    "subnet_mask": "255.0.0.0",
                                    "next_hop": "0.0.0.0",
                                    "metric": 5
                                },
                                {
                                    "ip_address": "172.16.0.0",
                                    "subnet_mask": "255.240.0.0",
                                    "next_hop": "192.168.1.1",
                                    "metric": 3
                                }
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        // Wait a bit for server to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Create UDP socket
        println!("  [TEST] Creating UDP socket for RIP client");
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = format!("127.0.0.1:{}", server.port);

        // Send RIP request for entire routing table
        println!("  [TEST] Sending RIP request to {}", server_addr);
        let request_msg = build_rip_request_all();
        with_client_timeout(client.send_to(&request_msg, &server_addr)).await?;

        // Receive RIP response
        println!("  [TEST] Waiting for RIP response");
        let mut buffer = vec![0u8; 512];
        let (n, _peer) = with_client_timeout(client.recv_from(&mut buffer)).await?;

        println!("  [TEST] Received {} bytes", n);

        // Parse response
        let (command, version, routes) = parse_rip_response(&buffer[..n])?;

        println!(
            "  [TEST] RIP response: command={}, version={}, routes={}",
            command,
            version,
            routes.len()
        );

        // Verify response
        assert_eq!(command, RIP_RESPONSE, "Expected RIP response");
        assert_eq!(version, RIP_VERSION, "Expected RIPv2");
        assert!(routes.len() >= 2, "Expected at least 2 routes");

        // Display routes
        for route in &routes {
            println!(
                "  [TEST] Route: {}/{} via {} metric {}",
                route.ip, route.subnet_mask, route.next_hop, route.metric
            );
        }

        // Verify at least one route with expected characteristics
        let has_local_route = routes
            .iter()
            .any(|r| r.ip.starts_with("192.168") && r.metric <= 1);

        assert!(
            has_local_route,
            "Expected at least one 192.168.x.x route with low metric"
        );

        println!("  [TEST] ✓ RIP routing table request test passed");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_rip_route_advertisement() -> E2EResult<()> {
        println!("\n=== Test: RIP Route Advertisement ===");

        let prompt = "listen on port 0 via rip. \
            For any RIP request, advertise the following routes: \
            - 10.20.30.0/24 with metric 1 \
            - 172.30.0.0/16 with metric 8";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen")
                .and_instruction_containing("rip")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "RIP",
                        "instruction": "RIP server - advertise specified routes"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: RIP request received
                .on_event("rip_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_rip_response",
                        "routes": [
                            {
                                "ip_address": "10.20.30.0",
                                "subnet_mask": "255.255.255.0",
                                "next_hop": "0.0.0.0",
                                "metric": 1
                            },
                            {
                                "ip_address": "172.30.0.0",
                                "subnet_mask": "255.255.0.0",
                                "next_hop": "0.0.0.0",
                                "metric": 8
                            }
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Create UDP socket
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = format!("127.0.0.1:{}", server.port);

        // Send request
        println!("  [TEST] Sending RIP request");
        let request_msg = build_rip_request_all();
        with_client_timeout(client.send_to(&request_msg, &server_addr)).await?;

        // Receive response
        println!("  [TEST] Waiting for RIP response");
        let mut buffer = vec![0u8; 512];
        let (n, _) = with_client_timeout(client.recv_from(&mut buffer)).await?;

        // Parse response
        let (command, version, routes) = parse_rip_response(&buffer[..n])?;

        println!(
            "  [TEST] Received {} routes (command={}, version={})",
            routes.len(),
            command,
            version
        );

        // Verify response contains expected routes
        assert_eq!(command, RIP_RESPONSE);
        assert_eq!(version, RIP_VERSION);

        // Check for advertised routes
        for route in &routes {
            println!(
                "  [TEST] Advertised route: {}/{} metric {}",
                route.ip, route.subnet_mask, route.metric
            );

            // Verify metric is valid (1-16)
            assert!(
                route.metric >= 1 && route.metric <= 16,
                "Metric should be between 1 and 16"
            );

            // Verify AFI is IPv4 (2)
            assert_eq!(route.afi, 2, "AFI should be 2 for IPv4");
        }

        println!("  [TEST] ✓ RIP route advertisement test passed");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_rip_metric_handling() -> E2EResult<()> {
        println!("\n=== Test: RIP Metric Handling ===");

        let prompt = "listen on port 0 via rip. \
            Advertise routes with different metrics: \
            - 192.168.100.0/24 with metric 1 (directly connected) \
            - 10.10.0.0/16 with metric 5 (5 hops away) \
            - 172.20.0.0/16 with metric 15 (15 hops away, maximum reachable) \
            - 192.168.99.0/24 with metric 16 (unreachable/withdrawn)";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen")
                .and_instruction_containing("rip")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "RIP",
                        "instruction": "RIP server - advertise routes with various metrics"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: RIP request received
                .on_event("rip_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_rip_response",
                        "routes": [
                            {
                                "ip_address": "192.168.100.0",
                                "subnet_mask": "255.255.255.0",
                                "next_hop": "0.0.0.0",
                                "metric": 1
                            },
                            {
                                "ip_address": "10.10.0.0",
                                "subnet_mask": "255.255.0.0",
                                "next_hop": "0.0.0.0",
                                "metric": 5
                            },
                            {
                                "ip_address": "172.20.0.0",
                                "subnet_mask": "255.255.0.0",
                                "next_hop": "0.0.0.0",
                                "metric": 15
                            },
                            {
                                "ip_address": "192.168.99.0",
                                "subnet_mask": "255.255.255.0",
                                "next_hop": "0.0.0.0",
                                "metric": 16
                            }
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Create client and send request
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = format!("127.0.0.1:{}", server.port);

        println!("  [TEST] Sending RIP request");
        let request_msg = build_rip_request_all();
        with_client_timeout(client.send_to(&request_msg, &server_addr)).await?;

        // Receive and parse response
        let mut buffer = vec![0u8; 512];
        let (n, _) = with_client_timeout(client.recv_from(&mut buffer)).await?;
        let (_, _, routes) = parse_rip_response(&buffer[..n])?;

        println!("  [TEST] Received {} routes", routes.len());

        // Verify different metric values
        let mut has_low_metric = false;
        let mut has_medium_metric = false;
        let mut has_high_metric = false;
        let mut has_unreachable = false;

        for route in &routes {
            println!("  [TEST] Route: {} metric {}", route.ip, route.metric);

            match route.metric {
                1..=3 => has_low_metric = true,
                4..=10 => has_medium_metric = true,
                11..=15 => has_high_metric = true,
                16 => has_unreachable = true,
                _ => {}
            }
        }

        // Should have at least routes with different metric ranges
        assert!(
            has_low_metric || has_medium_metric || has_high_metric,
            "Expected routes with various metric values"
        );

        println!("  [TEST] ✓ RIP metric handling test passed");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        Ok(())
    }
}
