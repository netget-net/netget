//! The signalling relay's two admission rules, which did not exist.
//!
//! This server has no authentication by design — it is a honeypot-shaped SDP relay and any
//! client may claim any unused peer id. That is stated in `metadata().notes` and is not what
//! these tests are about. They are about the two things "no authentication" was quietly doing
//! on top of that, neither of which is implied by it:
//!
//! * **An unregistered socket could relay.** The offer/answer/ice_candidate/relay arm had no
//!   registration guard, so a connection that never sent `register` could inject frames —
//!   including a `relay` carrying arbitrary JSON — at any registered peer. A relay with no
//!   identity at all on the sending side is an open injection point, and the recipient has no
//!   way to tell such a frame from a real one.
//! * **`from` was taken verbatim from the frame.** Any registered peer could send an offer
//!   that both the recipient *and* the `webrtc_signaling_message_received` event attributed
//!   to somebody else. The recipient answers whoever `from` names, so this splices a stranger
//!   into a session it is not part of.
//!
//! Both are now enforced in `handle_connection`, and the honest half — that any peer id is
//! available to anyone — is asserted here too, so a later change that quietly adds
//! authentication does not leave the documentation wrong in the other direction.

mod relay_abuse_tests {
    use crate::helpers::*;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    type PeerSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn next_json(ws: &mut PeerSocket, who: &str) -> E2EResult<serde_json::Value> {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .map_err(|_| format!("{who}: timed out waiting for a frame"))?
            .ok_or_else(|| format!("{who}: stream closed unexpectedly"))?
            .map_err(|e| format!("{who}: {e}"))?;
        let text = frame.into_text().map_err(|e| e.to_string())?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("{who}: {e} in {text}"))?)
    }

    /// Assert nothing arrives within `secs`. Used where the point is silence.
    async fn expect_no_frame(ws: &mut PeerSocket, who: &str, secs: u64) -> E2EResult<()> {
        match tokio::time::timeout(Duration::from_secs(secs), ws.next()).await {
            Err(_) => Ok(()),
            Ok(None) => Ok(()),
            Ok(Some(Ok(frame))) => {
                Err(format!("{who} should have received nothing, got {frame:?}"))?
            }
            Ok(Some(Err(e))) => Err(format!("{who}: {e}"))?,
        }
    }

    async fn connect(port: u16) -> E2EResult<PeerSocket> {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        Ok(ws)
    }

    async fn connect_and_register(port: u16, peer_id: &str) -> E2EResult<PeerSocket> {
        let mut ws = connect(port).await?;
        ws.send(Message::Text(
            serde_json::json!({"type": "register", "peer_id": peer_id}).to_string(),
        ))
        .await
        .map_err(|e| format!("register {peer_id}: {e}"))?;
        let json = next_json(&mut ws, peer_id).await?;
        assert_eq!(json["type"], "registered", "expected `registered`: {json}");
        Ok(ws)
    }

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
                        "type": "show_message",
                        "message": "peer connected"
                    }]))
                    .expect_calls(expect_connections)
                    .and()
            },
        )
    }

    /// A socket that never registered cannot put a frame in front of a registered peer.
    #[tokio::test]
    async fn an_unregistered_socket_cannot_relay() -> E2EResult<()> {
        // One connection event: only alice registers.
        let mut server = start_netget_server(signaling_server(1)).await?;
        server
            .wait_for_log("WebRTC Signaling server listening", 10)
            .await?;

        let mut alice = connect_and_register(server.port, "alice").await?;

        // An anonymous socket tries every relayable shape at alice.
        let mut intruder = connect(server.port).await?;
        for frame in [
            serde_json::json!({"type": "offer", "from": "mallory", "to": "alice",
                               "sdp": {"type": "offer", "sdp": "v=0"}}),
            serde_json::json!({"type": "answer", "from": "mallory", "to": "alice",
                               "sdp": {"type": "answer", "sdp": "v=0"}}),
            serde_json::json!({"type": "ice_candidate", "from": "mallory", "to": "alice",
                               "candidate": {"candidate": "candidate:1 1 udp 1 127.0.0.1 1 typ host"}}),
            serde_json::json!({"type": "relay", "from": "mallory", "to": "alice",
                               "data": {"anything": "at all"}}),
        ] {
            intruder
                .send(Message::Text(frame.to_string()))
                .await
                .map_err(|e| format!("intruder send: {e}"))?;

            // The sender is told why, so this is a refusal and not a silent drop.
            let reply = next_json(&mut intruder, "intruder").await?;
            assert_eq!(
                reply["type"], "error",
                "an unregistered sender must get an error, got {reply}"
            );
            let message = reply["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("register"),
                "the error should say what is missing, got {message:?}"
            );
        }

        // Alice received none of it. This is the assertion that matters: four
        // forged frames went in and nothing came out the other side.
        expect_no_frame(&mut alice, "alice", 2).await?;

        alice.close(None).await.ok();
        intruder.close(None).await.ok();
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A registered peer cannot make a frame look as if it came from someone else.
    #[tokio::test]
    async fn a_forged_from_is_rewritten_to_the_real_sender() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(2)).await?;
        server
            .wait_for_log("WebRTC Signaling server listening", 10)
            .await?;

        let mut alice = connect_and_register(server.port, "alice").await?;
        let mut mallory = connect_and_register(server.port, "mallory").await?;

        // Mallory sends alice an offer claiming to be bob.
        mallory
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "bob",
                    "to": "alice",
                    "sdp": {"type": "offer", "sdp": "v=0\r\no=mallory 0 0 IN IP4 127.0.0.1\r\n"}
                })
                .to_string(),
            ))
            .await
            .map_err(|e| format!("mallory send: {e}"))?;

        let received = next_json(&mut alice, "alice").await?;
        assert_eq!(received["type"], "offer");
        assert_eq!(
            received["from"], "mallory",
            "the relayed `from` must be the sender's registered id, not the one it typed. \
             If this says \"bob\", alice will answer bob and mallory has spliced a third \
             party into the session. Got: {received}"
        );
        assert_eq!(received["to"], "alice");
        // The body is untouched: rewriting identity must not corrupt the payload.
        assert_eq!(
            received["sdp"]["sdp"], "v=0\r\no=mallory 0 0 IN IP4 127.0.0.1\r\n",
            "the SDP body must be relayed verbatim"
        );

        alice.close(None).await.ok();
        mallory.close(None).await.ok();
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The honest half, asserted so it cannot drift: there is no authentication, any peer id
    /// is available to anyone, and `metadata().notes` says so.
    #[tokio::test]
    async fn any_peer_id_is_available_to_anyone_and_a_taken_one_is_refused() -> E2EResult<()> {
        let mut server = start_netget_server(signaling_server(1)).await?;
        server
            .wait_for_log("WebRTC Signaling server listening", 10)
            .await?;

        // No credential of any kind is offered, and registration succeeds.
        let mut alice = connect_and_register(server.port, "alice").await?;

        // A second socket claiming the same id is refused — first come, first served,
        // which is the only thing standing between two peers and each other's traffic.
        let mut impostor = connect(server.port).await?;
        impostor
            .send(Message::Text(
                serde_json::json!({"type": "register", "peer_id": "alice"}).to_string(),
            ))
            .await
            .map_err(|e| format!("impostor register: {e}"))?;
        let reply = next_json(&mut impostor, "impostor").await?;
        assert_eq!(
            reply["type"], "error",
            "a duplicate peer id must be refused, got {reply}"
        );

        // And the refusal did not disturb the real alice.
        expect_no_frame(&mut alice, "alice", 1).await?;

        alice.close(None).await.ok();
        impostor.close(None).await.ok();
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
