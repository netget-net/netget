//! What a signaling peer gets when the LLM backend fails.
//!
//! The failure is forced the way `tests/server/dns/llm_failure_test.rs` forces it: a mock is
//! configured for the *startup* instruction only, so every signaling event matches no rule,
//! the mock Ollama server answers HTTP 500, and `call_llm` returns `Err`.
//!
//! All three call sites used to swallow that with `if let Ok(..)` / `let _ =`. Only one of the
//! three can honestly answer the peer, and the difference is the point of this file:
//!
//! - **`webrtc_signaling_peer_connected`** is the one event carrying actions the model can act
//!   on (`send_signaling_message`, `disconnect_peer`), so a peer may be waiting on what the
//!   model decides. It now gets `{"type": "error", ...}` — the protocol's own vocabulary, and
//!   a message this protocol already sends for duplicate ids and undeliverable targets.
//! - **`webrtc_signaling_message_received`** fires *after* the relay has already happened and
//!   is declared `.with_no_actions()`, so the model cannot speak to the peer even when it
//!   succeeds. Silence is the only correct answer, and an error frame here would announce a
//!   failure the peer's signaling did not suffer. The test asserts that silence, and that the
//!   relay itself is untouched.
//! - **`webrtc_signaling_peer_disconnected`** fires because the socket has already gone. There
//!   is nobody to answer.
//!
//! Nothing here may be answered with a *successful-looking* frame: an `error` is the only
//! thing the server may invent on the model's behalf.

mod webrtc_signaling_llm_failure_tests {
    use crate::helpers::*;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    type PeerSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Read one frame as JSON, failing rather than hanging.
    async fn next_json(ws: &mut PeerSocket, who: &str) -> E2EResult<serde_json::Value> {
        let frame = tokio::time::timeout(Duration::from_secs(20), ws.next())
            .await
            .map_err(|_| format!("{who}: timed out waiting for a frame"))?
            .ok_or_else(|| format!("{who}: stream closed unexpectedly"))?
            .map_err(|e| format!("{who}: {e}"))?;
        let text = frame.into_text().map_err(|e| e.to_string())?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("{who}: {e} in {text}"))?)
    }

    /// A signaling server with a mock for the startup instruction and nothing else, so every
    /// signaling event drives `call_llm` into its error path.
    fn failing_signaling_server() -> NetGetConfig {
        NetGetConfig::new_no_scripts("Open a WebRTC signaling server and relay between peers")
            .with_mock(|mock| {
                mock.on_instruction_containing("signaling")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "WebRTC Signaling",
                        "instruction": "Relay signaling between peers"
                    }]))
                    .expect_calls(1)
                    .and()
                // Deliberately NO rule for any `webrtc_signaling_*` event.
            })
    }

    /// Register and return the `registered` frame plus whatever follows it.
    async fn register(port: u16, peer_id: &str) -> E2EResult<PeerSocket> {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .map_err(|e| format!("connect as {peer_id}: {e}"))?;
        ws.send(Message::Text(
            serde_json::json!({"type": "register", "peer_id": peer_id}).to_string(),
        ))
        .await
        .map_err(|e| format!("register {peer_id}: {e}"))?;

        let json = next_json(&mut ws, peer_id).await?;
        assert_eq!(
            json["type"], "registered",
            "registration itself does not depend on the model and must still be confirmed: \
             {json}"
        );
        assert_eq!(json["peer_id"], peer_id);
        Ok(ws)
    }

    /// A peer whose connect event the model could not answer is told so, in the protocol's
    /// own vocabulary, instead of waiting for a frame that never comes.
    #[tokio::test]
    async fn test_signaling_peer_connected_llm_failure_sends_error_frame() -> E2EResult<()> {
        let server = start_netget_server(failing_signaling_server()).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = register(server.port, "alice").await?;

        let json = next_json(&mut alice, "alice").await.map_err(|e| {
            format!(
                "no frame followed `registered` ({e}) — the server swallowed the LLM failure \
                 and left the peer waiting, which is the exact defect this test exists to catch"
            )
        })?;
        assert_eq!(
            json["type"], "error",
            "an LLM failure on peer_connected must be reported as a signaling `error` frame, \
             got {json}"
        );
        let message = json["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("alice"),
            "the error must name the peer it concerns: {json}"
        );
        assert!(
            !message.is_empty(),
            "an `error` frame with no message tells the peer nothing: {json}"
        );

        // Fail closed: nothing may be dressed up as a successful signaling exchange.
        for forbidden in ["offer", "answer", "ice_candidate", "relay"] {
            assert_ne!(
                json["type"], forbidden,
                "an LLM failure must never be answered with a {forbidden} frame"
            );
        }

        // The error frame is what the peer sees. The log is where the *reason* lives, and it
        // has to say which of three things happened: the model refused, the model said
        // nothing, or the backend never answered. `llm_error_peer_admitted` is this
        // protocol's own token for the last one — deliberately not `fail_closed_*`, because
        // nothing was closed: registration completed and the `registered` frame went out
        // before the model was ever consulted, so the peer keeps every capability it had.
        server
            .wait_for_any(&["decision=llm_error_peer_admitted"], 30)
            .await;
        let lines = server.get_output().await;
        assert!(
            lines
                .iter()
                .any(|l| l.contains("decision=llm_error_peer_admitted")),
            "a backend failure on webrtc_signaling_peer_connected must be tagged so it is \
             distinguishable from a model that chose to say nothing. Output was:\n{}",
            lines.join("\n")
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("WebRTC signaling") && l.contains("decision=model_")),
            "the model never answered, so nothing may be logged as a decision it took. \
             Output was:\n{}",
            lines.join("\n")
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

    /// The relay is decided in Rust and reported to the sender before the model is told about
    /// it, so a failing `webrtc_signaling_message_received` call must change nothing on the
    /// wire: the offer still arrives, and the sender gets no spurious error.
    #[tokio::test]
    async fn test_signaling_relay_survives_llm_failure_silently() -> E2EResult<()> {
        let server = start_netget_server(failing_signaling_server()).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut alice = register(server.port, "alice").await?;
        let mut bob = register(server.port, "bob").await?;

        // Each registration's peer_connected call failed, so each peer has one error frame
        // queued behind its `registered`. Drain them before testing the relay.
        for (ws, who) in [(&mut alice, "alice"), (&mut bob, "bob")] {
            let json = next_json(ws, who).await?;
            assert_eq!(
                json["type"], "error",
                "{who} expected the connect-event error"
            );
        }

        alice
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "alice",
                    "to": "bob",
                    "sdp": {"type": "offer", "sdp": "v=0 llm-failure-session"}
                })
                .to_string(),
            ))
            .await
            .map_err(|e| format!("alice offer: {e}"))?;

        let relayed = next_json(&mut bob, "bob").await?;
        assert_eq!(
            relayed["type"], "offer",
            "the relay does not depend on the model and must still deliver: {relayed}"
        );
        assert_eq!(relayed["from"], "alice");
        assert_eq!(
            relayed["sdp"]["sdp"], "v=0 llm-failure-session",
            "the SDP body must arrive unchanged"
        );

        // The observation call for that offer fails. It must stay silent: an error frame here
        // would tell alice her signaling failed when it did not, and a real peer would abort a
        // negotiation that in fact succeeded.
        match tokio::time::timeout(Duration::from_secs(2), alice.next()).await {
            Err(_) => {}
            Ok(Some(Ok(frame))) => panic!(
                "the sender received {:?} after a successful relay; a failing \
                 webrtc_signaling_message_received call must not put anything on the wire",
                frame
            ),
            Ok(other) => panic!("alice's signaling socket closed unexpectedly: {other:?}"),
        }

        // The wire carries nothing here by design, so the log is the *only* place this
        // failure can exist. Both halves of that contract are asserted: the silence above,
        // and the tag here.
        server
            .wait_for_any(&["decision=llm_error_notice_only"], 30)
            .await;
        let lines = server.get_output().await;
        assert!(
            lines
                .iter()
                .any(|l| l.contains("webrtc_signaling_message_received")
                    && l.contains("decision=llm_error_notice_only")),
            "a failed observation call is silent on the wire, so it must be loud in the log — \
             and tagged as a failure that refused nothing, since the relay already happened. \
             Output was:\n{}",
            lines.join("\n")
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
}
