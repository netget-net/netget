//! E2E tests for the WebRTC server.
//!
//! These are **not** "did the process start" tests. The peer is a real `webrtc` (webrtc-rs)
//! `RTCPeerConnection`: it creates a data channel, produces an SDP offer, exchanges it with
//! NetGet over the server's built-in WebSocket signalling endpoint, completes ICE and DTLS,
//! and then a message is asserted to have crossed the data channel in both directions.
//!
//! LLM budget across the file: 10 mocked calls (plus one deliberately unmatched
//! request in the backend-failure test, which the mock answers with HTTP 500).

mod webrtc_server_tests {
    use crate::helpers::*;
    use futures::{SinkExt, StreamExt};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;
    use webrtc::api::interceptor_registry::register_default_interceptors;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::api::APIBuilder;
    use webrtc::data_channel::data_channel_message::DataChannelMessage;
    use webrtc::interceptor::registry::Registry;
    use webrtc::peer_connection::configuration::RTCConfiguration;
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
    use webrtc::peer_connection::RTCPeerConnection;

    /// ICE + DTLS + SCTP on loopback is fast, but a loaded machine is not. Everything the
    /// tests wait on uses this budget so a slow box fails slowly rather than flakily.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

    /// The socket type `connect_async` hands back for a `ws://` URL.
    type ClientSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// A webrtc-rs peer with one data channel, ready to offer.
    struct TestPeer {
        peer_connection: Arc<RTCPeerConnection>,
        /// Everything the peer received on the data channel.
        inbox: mpsc::UnboundedReceiver<String>,
    }

    impl TestPeer {
        /// Build a peer that opens a data channel and records what arrives on it.
        ///
        /// `greeting`, if set, is sent by the peer as soon as the channel opens — which is
        /// the moment the channel is genuinely usable, so it doubles as proof the transport
        /// came up.
        async fn new(channel_label: &str, greeting: Option<String>) -> E2EResult<Self> {
            // webrtc-dtls builds its DTLS config through rustls 0.23, which panics unless a
            // process-level CryptoProvider is installed. The test binary is not `main`, so
            // nothing installs one for us — and when this was missing, the test passed only
            // when some *other* suite in the same binary (tls, dot, quic) happened to run
            // first and install it. Under a filtered run it panicked every time. Install it
            // here so the test stands on its own.
            let _ = rustls::crypto::ring::default_provider().install_default();

            let mut media_engine = MediaEngine::default();
            let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
            let api = APIBuilder::new()
                .with_media_engine(media_engine)
                .with_interceptor_registry(registry)
                .build();

            // No ICE servers: host candidates on loopback, and no external endpoint is
            // contacted by the test.
            let peer_connection =
                Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
            let data_channel = peer_connection
                .create_data_channel(channel_label, None)
                .await?;

            let (inbox_tx, inbox) = mpsc::unbounded_channel::<String>();
            data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
                let inbox_tx = inbox_tx.clone();
                Box::pin(async move {
                    let text = String::from_utf8_lossy(&msg.data).to_string();
                    println!("[peer] data channel <- {}", text);
                    let _ = inbox_tx.send(text);
                })
            }));

            if let Some(greeting) = greeting {
                let channel = Arc::clone(&data_channel);
                data_channel.on_open(Box::new(move || {
                    let channel = Arc::clone(&channel);
                    let greeting = greeting.clone();
                    Box::pin(async move {
                        println!("[peer] data channel open, sending: {}", greeting);
                        if let Err(e) = channel.send_text(greeting).await {
                            eprintln!("[peer] failed to send on data channel: {}", e);
                        }
                    })
                }));
            }

            Ok(Self {
                peer_connection,
                inbox,
            })
        }

        /// Produce an offer with ICE gathering already complete (this server does not
        /// trickle candidates).
        async fn gathered_offer(&self) -> E2EResult<RTCSessionDescription> {
            let offer = self.peer_connection.create_offer(None).await?;
            let mut gather_complete = self.peer_connection.gathering_complete_promise().await;
            self.peer_connection.set_local_description(offer).await?;
            let _ = gather_complete.recv().await;
            match self.peer_connection.local_description().await {
                Some(description) => Ok(description),
                None => Err("peer produced no local description".into()),
            }
        }

        async fn accept_answer(&self, answer: RTCSessionDescription) -> E2EResult<()> {
            self.peer_connection.set_remote_description(answer).await?;
            Ok(())
        }

        /// Wait for one data-channel message.
        async fn recv(&mut self) -> E2EResult<String> {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.inbox.recv()).await {
                Ok(Some(text)) => Ok(text),
                Ok(None) => Err("peer data channel closed before a message arrived".into()),
                Err(_) => Err(format!(
                    "no data channel message reached the peer within {:?}",
                    HANDSHAKE_TIMEOUT
                )
                .into()),
            }
        }
    }

    /// Signalling client: one WebSocket, one peer.
    struct Signalling {
        socket: ClientSocket,
    }

    impl Signalling {
        async fn connect(port: u16) -> E2EResult<Self> {
            let url = format!("ws://127.0.0.1:{}/", port);
            let connect = tokio_tungstenite::connect_async(url.clone());
            let (socket, _) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connect).await {
                Ok(result) => result?,
                Err(_) => return Err(format!("signalling connect to {} timed out", url).into()),
            };
            Ok(Self { socket })
        }

        async fn send_json(&mut self, value: serde_json::Value) -> E2EResult<()> {
            self.socket.send(Message::Text(value.to_string())).await?;
            Ok(())
        }

        async fn send_offer(
            &mut self,
            peer_id: &str,
            offer: &RTCSessionDescription,
        ) -> E2EResult<()> {
            self.send_json(serde_json::json!({
                "type": "offer",
                "peer_id": peer_id,
                "sdp": offer,
            }))
            .await
        }

        /// Read the next JSON text frame from the server.
        async fn next_frame(&mut self) -> E2EResult<serde_json::Value> {
            loop {
                let frame = match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.socket.next()).await
                {
                    Ok(frame) => frame,
                    Err(_) => {
                        return Err(
                            format!("no signalling frame within {:?}", HANDSHAKE_TIMEOUT).into(),
                        )
                    }
                };
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        println!("[peer] signalling <- {}", text);
                        return Ok(serde_json::from_str(&text)?);
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err("signalling connection closed by server".into())
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(format!("signalling read error: {}", e).into()),
                }
            }
        }
    }

    /// The load-bearing test: a real peer connection is established through the server's
    /// signalling endpoint and a message crosses the data channel in **both** directions.
    ///
    /// LLM calls: 4 (startup, offer decision, peer connected, message received)
    #[tokio::test]
    async fn test_webrtc_data_channel_message_round_trip() -> E2EResult<()> {
        println!("\n=== E2E Test: WebRTC data channel round trip ===");

        let server = start_netget_server(
            NetGetConfig::new(
                "Open a webrtc data channel server on port {AVAILABLE_PORT} that admits peers \
                 and echoes their messages",
            )
            .with_mock(|mock| {
                mock.on_instruction_containing("webrtc")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "webrtc",
                            "instruction": "Admit peers and answer their data channel messages"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("webrtc_offer_received")
                    .and_event_data_contains("peer_id", "e2e-peer")
                    .respond_with_actions(serde_json::json!([{ "type": "accept_offer" }]))
                    .expect_calls(1)
                    .and()
                    .on_event("webrtc_peer_connected")
                    .and_event_data_contains("peer_id", "e2e-peer")
                    .respond_with_actions(serde_json::json!([
                        { "type": "send_message", "message": "welcome e2e-peer" }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("webrtc_message_received")
                    .and_event_data_contains("message", "ping from peer")
                    .respond_with_actions(serde_json::json!([
                        { "type": "send_message", "message": "pong from netget" }
                    ]))
                    .expect_calls(1)
                    .and()
            }),
        )
        .await?;
        println!("Server listening on port {}", server.port);

        let mut peer = TestPeer::new("netget", Some("ping from peer".to_string())).await?;
        let offer = peer.gathered_offer().await?;
        assert!(
            offer.sdp.contains("m=application"),
            "peer offer should contain a data channel m-line"
        );

        // Keep the signalling socket alive for the whole test: the server ties the peer
        // connection's lifetime to it.
        let mut signalling = Signalling::connect(server.port).await?;
        signalling.send_offer("e2e-peer", &offer).await?;

        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("answer"),
            "expected an SDP answer, got: {}",
            frame
        );
        let answer: RTCSessionDescription = serde_json::from_value(
            frame
                .get("sdp")
                .cloned()
                .ok_or("answer frame carried no 'sdp' field")?,
        )?;
        assert!(
            answer.sdp.contains("m=application"),
            "answer should carry the data channel: {}",
            answer.sdp
        );
        peer.accept_answer(answer).await?;

        // THE assertion this suite exists for: the data channel actually carries bytes.
        // The welcome is produced by the peer-connected event, the pong by the message the
        // peer sent when its channel opened.
        let first = peer.recv().await?;
        let second = peer.recv().await?;
        let mut received = vec![first, second];
        received.sort();
        assert_eq!(
            received,
            vec![
                "pong from netget".to_string(),
                "welcome e2e-peer".to_string()
            ],
            "peer did not receive both server messages over the data channel"
        );
        // The peer's own send is what triggered the pong, so receiving the pong proves the
        // server received "ping from peer" over the same data channel.
        println!("✓ data channel carried messages in both directions");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test passed ===\n");
        Ok(())
    }

    /// An explicit `reject_offer` must refuse the peer and say why.
    ///
    /// LLM calls: 2 (startup, offer decision)
    #[tokio::test]
    async fn test_webrtc_offer_rejected_by_model() -> E2EResult<()> {
        println!("\n=== E2E Test: WebRTC offer rejected by model ===");

        let server = start_netget_server(
            NetGetConfig::new(
                "Open a webrtc server on port {AVAILABLE_PORT} and refuse unknown peers",
            )
            .with_mock(|mock| {
                mock.on_instruction_containing("webrtc")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "webrtc",
                            "instruction": "Refuse peers that are not on the guest list"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("webrtc_offer_received")
                    .respond_with_actions(serde_json::json!([
                        { "type": "reject_offer", "reason": "not on the guest list" }
                    ]))
                    .expect_calls(1)
                    .and()
            }),
        )
        .await?;

        let peer = TestPeer::new("netget", None).await?;
        let offer = peer.gathered_offer().await?;

        let mut signalling = Signalling::connect(server.port).await?;
        signalling.send_offer("stranger", &offer).await?;

        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("rejected"),
            "expected the offer to be rejected, got: {}",
            frame
        );
        assert_eq!(
            frame.get("peer_id").and_then(|v| v.as_str()),
            Some("stranger")
        );
        let reason = frame
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            reason.contains("guest list"),
            "rejection should carry the model's reason, got: {}",
            reason
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test passed ===\n");
        Ok(())
    }

    /// A backend failure must refuse the offer with a *category*, never with the error.
    ///
    /// The mock has no rule for `webrtc_offer_received`, so the request comes back HTTP 500
    /// and `call_llm` errors — the same shape as a real backend outage. The peer must still
    /// get a `rejected` frame (silence would leave it waiting on its own timeout), and that
    /// frame must not carry netget's internal error text. See `src/utils/wire_failure.rs`.
    ///
    /// LLM calls: 1 asserted (startup); the offer decision deliberately matches no rule.
    #[tokio::test]
    async fn test_webrtc_offer_backend_failure_rejects_without_leaking() -> E2EResult<()> {
        println!("\n=== E2E Test: WebRTC offer rejected on backend failure ===");

        let server = start_netget_server(
            NetGetConfig::new("Open a webrtc server on port {AVAILABLE_PORT}").with_mock(|mock| {
                mock.on_instruction_containing("webrtc")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "webrtc",
                            "instruction": "Admit peers"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            }),
        )
        .await?;

        let peer = TestPeer::new("netget", None).await?;
        let offer = peer.gathered_offer().await?;

        let mut signalling = Signalling::connect(server.port).await?;
        signalling.send_offer("stranger", &offer).await?;

        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("rejected"),
            "a backend failure must fail closed with a rejection, not silence: {}",
            frame
        );
        let reason = frame
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Exactly one of the two categories, and nothing else.
        assert!(
            reason == "netget: request could not be processed"
                || reason == "netget: backend at capacity, retry later",
            "rejection reason must be a WireFailure category, got: {}",
            reason
        );
        for token in [
            "\u{2717}",
            "retries",
            "http://",
            "127.0.0.1",
            "11434",
            "LLM",
            "ollama",
            "Ollama",
            "/Users/",
        ] {
            assert!(
                !reason.contains(token),
                "rejection reason leaked `{}`: {}",
                token,
                reason
            );
        }

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test passed ===\n");
        Ok(())
    }

    /// Fail-closed: a reply that contains no admission decision must refuse, not admit.
    ///
    /// This is the OAuth2-shaped defect the codebase has been bitten by — silence from the
    /// model must never read as approval.
    ///
    /// LLM calls: 2 (startup, offer decision)
    #[tokio::test]
    async fn test_webrtc_offer_without_decision_is_refused() -> E2EResult<()> {
        println!("\n=== E2E Test: WebRTC offer with no decision is refused ===");

        let server = start_netget_server(
            NetGetConfig::new("Open a webrtc server on port {AVAILABLE_PORT} for peer testing")
                .with_mock(|mock| {
                    mock.on_instruction_containing("webrtc")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "webrtc",
                                "instruction": "Peer testing server"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // A well-formed but decision-free reply: the model told the operator
                        // something and said nothing about admission. (This used to send
                        // append_to_log with a `message` field, which is malformed and slipped
                        // through only while common actions went unvalidated.)
                        .on_event("webrtc_offer_received")
                        .respond_with_actions(serde_json::json!([
                            { "type": "show_message", "message": "saw an offer" }
                        ]))
                        .expect_calls(1)
                        .and()
                }),
        )
        .await?;

        let peer = TestPeer::new("netget", None).await?;
        let offer = peer.gathered_offer().await?;

        let mut signalling = Signalling::connect(server.port).await?;
        signalling.send_offer("undecided-peer", &offer).await?;

        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("rejected"),
            "an offer with no decision must be refused, got: {}",
            frame
        );
        let reason = frame
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            reason.contains("no accept_offer"),
            "refusal reason should say the model gave no decision, got: {}",
            reason
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test passed ===\n");
        Ok(())
    }

    /// Peer-controlled garbage must produce an error frame, not a panic and not silence.
    ///
    /// LLM calls: 1 (startup only — none of these frames reaches the model)
    #[tokio::test]
    async fn test_webrtc_malformed_signalling_is_rejected_without_panic() -> E2EResult<()> {
        println!("\n=== E2E Test: WebRTC malformed signalling ===");

        let server = start_netget_server(
            NetGetConfig::new(
                "Open a webrtc server on port {AVAILABLE_PORT} for signalling checks",
            )
            .with_mock(|mock| {
                mock.on_instruction_containing("webrtc")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "webrtc",
                            "instruction": "Signalling validation server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            }),
        )
        .await?;

        let mut signalling = Signalling::connect(server.port).await?;

        // Not JSON at all.
        signalling
            .socket
            .send(Message::Text("this is not json".to_string()))
            .await?;
        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "malformed JSON should produce an error frame, got: {}",
            frame
        );

        // Valid JSON, wrong frame type.
        signalling
            .send_json(serde_json::json!({ "type": "answer", "peer_id": "x", "sdp": {} }))
            .await?;
        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "an 'answer' frame from a peer should be refused, got: {}",
            frame
        );

        // An offer whose SDP is nonsense.
        signalling
            .send_json(serde_json::json!({
                "type": "offer",
                "peer_id": "bad-sdp",
                "sdp": { "type": "offer", "sdp": "not an sdp" }
            }))
            .await?;
        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "an unusable SDP offer should produce an error frame, got: {}",
            frame
        );

        // An empty peer_id.
        signalling
            .send_json(serde_json::json!({
                "type": "offer",
                "peer_id": "   ",
                "sdp": "v=0\r\n"
            }))
            .await?;
        let frame = signalling.next_frame().await?;
        assert_eq!(
            frame.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "an empty peer_id should produce an error frame, got: {}",
            frame
        );

        // The server survived all of it and still answers.
        assert!(
            !server.output_contains("panicked").await,
            "server logged a panic while handling malformed signalling"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        println!("=== Test passed ===\n");
        Ok(())
    }
}
