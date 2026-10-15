//! E2E tests for the WebRTC Signaling server
//!
//! This is a WebSocket SDP relay: a peer sends `register` with a peer id, then `offer`,
//! `answer`, `ice_candidate` or `relay` frames addressed `to` another peer, and the server
//! forwards them. Relaying needs no LLM call; the model is consulted only on connect/disconnect.
//!
//! The previous suite could not fail. Every test started a server, slept, printed a ✅ and
//! returned — **no peer ever connected** — and none called `verify_mocks()`, so the
//! `expect_calls(1)` on the peer-connected rules asserted nothing at all. Its own CLAUDE.md said
//! so outright: "No Real WebSocket Connections: Tests use mocks, don't establish actual
//! WebSocket connections."
//!
//! It also mocked four actions that do not exist — `broadcast_message`, `list_signaling_peers`,
//! `wait_for_more`, `announcement` — which the server would have rejected as unknown; the
//! mock-action-name guard is what finally surfaced that. And `"port": "{AVAILABLE_PORT}"` was a
//! string where a number is required, so `open_server` was rejected as malformed and nothing
//! started.
//!
//! These connect real WebSocket peers and assert on the frames that come back. This protocol has
//! exactly two actions, `send_signaling_message` and `disconnect_peer`, and nothing else is
//! mocked here.

mod webrtc_signaling_server_tests {
    use crate::helpers::*;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    type PeerSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Read one frame as JSON, failing rather than hanging.
    async fn next_json(ws: &mut PeerSocket, who: &str) -> E2EResult<serde_json::Value> {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .map_err(|_| format!("{who}: timed out waiting for a frame"))?
            .ok_or_else(|| format!("{who}: stream closed unexpectedly"))?
            .map_err(|e| format!("{who}: {e}"))?;
        let text = frame.into_text().map_err(|e| e.to_string())?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("{who}: {e} in {text}"))?)
    }

    /// Connect a WebSocket peer and register it. The `registered` reply is the assertion.
    async fn connect_and_register(port: u16, peer_id: &str) -> E2EResult<PeerSocket> {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .map_err(|e| format!("connect as {peer_id}: {e}"))?;

        ws.send(Message::Text(
            serde_json::json!({"type": "register", "peer_id": peer_id}).to_string(),
        ))
        .await
        .map_err(|e| format!("register {peer_id}: {e}"))?;

        let json = next_json(&mut ws, peer_id).await?;
        assert_eq!(json["type"], "registered", "expected `registered`: {json}");
        assert_eq!(json["peer_id"], peer_id);
        Ok(ws)
    }

    /// A signaling server whose peer-connected event is acknowledged with a common action.
    fn signaling_server(expect_connections: usize) -> NetGetConfig {
        NetGetConfig::new("Open a WebRTC signaling server and relay between peers").with_mock(
            move |mock| {
                mock.on_instruction_containing("signaling")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "WebRTC Signaling",
                        "instruction": "Relay signaling between peers"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("webrtc_signaling_peer_connected")
                    .respond_with_actions(serde_json::json!([{
                        "type": "append_to_log",
                        "message": "peer connected"
                    }]))
                    .expect_calls(expect_connections)
                    .and()
            },
        )
    }

    /// A peer can register, and the model is told it connected.
    #[tokio::test]
    async fn test_signaling_peer_registration_with_mocks() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(1)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = connect_and_register(server.port, "alice").await?;
        alice.close(None).await.ok();

        tokio::time::sleep(Duration::from_millis(300)).await;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// An offer addressed to another peer reaches that peer, body intact.
    #[tokio::test]
    async fn test_signaling_message_forwarding_with_mocks() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(2)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = connect_and_register(server.port, "alice").await?;
        let mut bob = connect_and_register(server.port, "bob").await?;

        alice
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "alice",
                    "to": "bob",
                    "sdp": {"type": "offer", "sdp": "v=0 test-session"}
                })
                .to_string(),
            ))
            .await
            .map_err(|e| e.to_string())?;

        let json = next_json(&mut bob, "bob").await?;
        assert_eq!(json["type"], "offer", "got {json}");
        assert_eq!(json["from"], "alice");
        assert_eq!(json["to"], "bob");
        assert_eq!(
            json["sdp"]["sdp"], "v=0 test-session",
            "the SDP body must survive the relay unchanged: {json}"
        );

        alice.close(None).await.ok();
        bob.close(None).await.ok();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A frame addressed to an unknown peer is reported, not silently dropped.
    #[tokio::test]
    async fn test_signaling_unknown_peer_is_reported() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(1)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = connect_and_register(server.port, "alice").await?;
        alice
            .send(Message::Text(
                serde_json::json!({
                    "type": "relay",
                    "from": "alice",
                    "to": "nobody",
                    "data": {"hello": "world"}
                })
                .to_string(),
            ))
            .await
            .map_err(|e| e.to_string())?;

        let json = next_json(&mut alice, "alice").await?;
        assert_eq!(
            json["type"], "error",
            "an unroutable relay must be reported to the sender: {json}"
        );

        alice.close(None).await.ok();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Disconnecting releases the peer id, so it can be registered again.
    ///
    /// This is the regression guard for the bug that made this protocol relay nothing:
    /// `register_peer` took ownership of the write half, so the read loop exited immediately and
    /// ran the disconnect cleanup on the peer it had just registered. With that bug present the
    /// second registration below would succeed for the wrong reason — but the forwarding test
    /// above would fail, because no peer stays registered long enough to receive anything.
    #[tokio::test]
    async fn test_signaling_peer_disconnect_with_mocks() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(2)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = connect_and_register(server.port, "alice").await?;
        alice.close(None).await.ok();
        drop(alice);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice_again = connect_and_register(server.port, "alice").await?;
        alice_again.close(None).await.ok();

        tokio::time::sleep(Duration::from_millis(300)).await;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
