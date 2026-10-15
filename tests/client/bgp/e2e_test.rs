//! E2E tests for the BGP client
//!
//! A mocked NetGet **server** speaks BGP to a mocked NetGet **client** over a real socket.
//! Every assertion is an event that only fires if bytes crossed the wire and parsed:
//!
//! * the server's `bgp_open` fires only if the client's OPEN arrived and decoded;
//! * the client's `bgp_connected` fires only if the server's OPEN *and* KEEPALIVE arrived and
//!   the session reached Established;
//! * the client's `bgp_update_received` with `nlri` matching fires only if the server's UPDATE
//!   arrived and was decoded into structured fields.
//!
//! ## What these replace
//!
//! The previous three tests could not pass and could not fail for a useful reason:
//!
//! 1. Every rule mocked `bgp_open_received` and `bgp_keepalive_received`. Neither event has
//!    ever existed on the rewritten BGP server, whose events are `bgp_open`,
//!    `bgp_established`, `bgp_update` and `bgp_notification`. No rule matched.
//! 2. The client rules answered `bgp_connected` with `send_bgp_open`, which is a *server*
//!    action. The BGP client cannot execute it, so `mock_action_names` panics while the test
//!    is being configured.
//! 3. Every assertion was `output_contains("BGP")` — satisfied by a log line saying the
//!    connection had failed.

mod bgp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Full session, then routes: the server advertises 10.0.0.0/24 once the peer is up and the
    /// client must decode it into structured fields.
    ///
    /// LLM calls: 6 (server startup + bgp_open + bgp_established, client startup +
    /// bgp_connected + bgp_update_received).
    #[tokio::test]
    async fn test_bgp_client_establishes_session_and_receives_routes() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Start BGP server on port {AVAILABLE_PORT} with AS 65000 and router ID 192.168.1.1. \
             Advertise 10.0.0.0/24 to any peer that comes up.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Start BGP server")
                .and_instruction_containing("AS 65000")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BGP",
                    "instruction": "BGP router AS 65000, advertise 10.0.0.0/24 once established",
                    "startup_params": { "as_number": 65000, "router_id": "192.168.1.1" }
                }]))
                .expect_calls(1)
                .and()
                // Fires only when the client's OPEN arrived and parsed. Accepting the peer
                // sends our OPEN back.
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65000,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_calls(1)
                .and()
                // Fires only when the client's KEEPALIVE arrived, i.e. the session is up.
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_update",
                    "nlri": ["10.0.0.0/24"],
                    "next_hop": "192.168.1.1",
                    "as_path": [65000],
                    "origin": "IGP"
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via BGP with AS 65001 and router ID 192.168.1.100. \
             Establish the session and report any routes the peer announces."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("BGP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "BGP",
                    "instruction": "Establish BGP session with AS 65001 and report routes",
                    "startup_params": {
                        "local_as": 65001,
                        "router_id": "192.168.1.100",
                        "hold_time": 180
                    }
                }]))
                .expect_calls(1)
                .and()
                // Established: the peer's OPEN and KEEPALIVE both arrived.
                .on_event("bgp_connected")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
                // The assertion that matters: the UPDATE arrived and reached the handler as
                // decoded fields. This used to be delivered as `update_data_hex`, so matching
                // on `nlri` would have found nothing.
                .on_event("bgp_update_received")
                .and_event_data_contains("nlri", "10.0.0.0/24")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // OPEN -> OPEN -> KEEPALIVE -> KEEPALIVE -> UPDATE, with an LLM round trip at three of
        // those steps.
        server.wait_for_mocks(30).await;

        assert_eq!(client.protocol, "BGP", "Client should be BGP protocol");

        println!("✅ BGP client established a session and decoded the peer's routes");

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

    /// A 32-bit ASN survives the OPEN.
    ///
    /// This is the regression test for the defect the server half had fixed and the client
    /// still carried: `local_as as u16` turned AS 4200000000 into AS 60416 — a different,
    /// entirely valid-looking ASN, with no four-octet-AS capability and no diagnostic. The
    /// server's `bgp_open` event reports `peer_as` from the peer's capability, so this rule
    /// matches only if the real ASN travelled; against the old client it would have seen
    /// 60416 and the rule would never fire.
    ///
    /// LLM calls: 5 (server startup + bgp_open + bgp_established, client startup +
    /// bgp_connected).
    #[tokio::test]
    async fn test_bgp_client_sends_four_octet_asn() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Start BGP server on port {AVAILABLE_PORT} with AS 65000 and router ID 192.168.1.1. \
             Peer with four-octet AS neighbours.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Start BGP server")
                .and_instruction_containing("AS 65000")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BGP",
                    "instruction": "BGP router AS 65000, accept four-octet AS peers",
                    "startup_params": { "as_number": 65000, "router_id": "192.168.1.1" }
                }]))
                .expect_calls(1)
                .and()
                // 4200000000 truncated to 16 bits is 60416, so this never matches a client
                // that puts `local_as as u16` on the wire.
                .on_event("bgp_open")
                .and_event_data_contains("peer_as", "4200000000")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65000,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_calls(1)
                .and()
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via BGP using four-octet AS 4200000000 and router ID 10.0.0.1."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("BGP")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "BGP",
                    "instruction": "Peer as AS 4200000000",
                    "startup_params": {
                        "local_as": 4200000000u32,
                        "router_id": "10.0.0.1",
                        "hold_time": 180
                    }
                }]))
                .expect_calls(1)
                .and()
                // The session still reaches Established, so the AS_TRANS substitution in the
                // two-octet field is accepted rather than merely tolerated.
                .on_event("bgp_connected")
                .and_event_data_contains("peer_supports_four_octet_as", "true")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        assert_eq!(client.protocol, "BGP", "Client should be BGP protocol");

        println!("✅ BGP client advertised its real 32-bit ASN");

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
}
