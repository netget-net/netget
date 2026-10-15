//! End-to-end tests for the STOMP 1.2 client.
//!
//! # What the peer is, and what that is worth
//!
//! The session test drives this client against **NetGet's own STOMP server**, in a separate
//! process, over a real TCP socket. That is a genuine exchange — CONNECT, CONNECTED,
//! SUBSCRIBE, MESSAGE, SEND, DISCONNECT, RECEIPT — but it is *same-project* evidence: it shows
//! the two halves of this repository agree with each other, not that either matches what a
//! broker in the wild does. A shared misreading of the specification would be invisible to it.
//! That is why the client is rated `Experimental` and not Beta, and
//! `src/client/stomp/CLAUDE.md` records the exact test that would earn Beta.
//!
//! `async-stomp`, which is the Beta evidence for the *server*, cannot help here: it is a
//! client, so it can only ever be our peer's opposite number, never ours.
//!
//! # Why the handshake tests use a hand-written broker
//!
//! The strictness this client applies to `CONNECTED` — refuse the session unless it carries a
//! `version` header naming a version we offered — cannot be exercised against a correct
//! server, because a correct server never gets it wrong. Those four cases each need a peer
//! that answers *badly* on purpose, which only a socket the test owns can do. They spend no
//! LLM calls at all: the refusal happens before any event is raised.
//!
//! **Nothing here can skip.** There is no external binary to detect as missing, no
//! `#[ignore]`, and every failure path is an `assert!`, an `expect` or a `?`.
//!
//! LLM budget: **8 calls**, all in `test_stomp_client_session_against_the_netget_broker`
//! (5 server-side, 3 client-side). Every other test in this file makes zero.

mod stomp_client_tests {
    use crate::helpers::{start_netget_client, start_netget_server, E2EResult, NetGetConfig};
    use netget::client::stomp::StompClient;
    use netget::llm::actions::client_trait::{Client, ClientActionResult};
    use netget::llm::OllamaClient;
    use netget::state::app_state::AppState;
    use netget::state::ClientId;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// A one-shot broker that reads the client's `CONNECT` frame and answers with `reply`.
    ///
    /// Returns the address to point the client at and a handle yielding the exact bytes the
    /// client put on the wire — so the tests below assert the request as well as the reaction
    /// to the response.
    async fn broker_answering(
        reply: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("the client should connect");
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            // A STOMP frame ends at its NUL terminator; CONNECT has no body, so one read is
            // normally enough, but looping costs nothing and removes the assumption.
            loop {
                let n = socket.read(&mut buf).await.expect("read the CONNECT frame");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.contains(&0) {
                    break;
                }
            }
            socket.write_all(reply).await.expect("write the reply");
            socket.flush().await.expect("flush the reply");
            // Hold the socket open so the client's failure is about the frame it read, never
            // about the connection vanishing underneath it.
            tokio::time::sleep(Duration::from_secs(3)).await;
            request
        });

        (addr, handle)
    }

    fn test_state() -> Arc<AppState> {
        // Port 1 is not an Ollama endpoint. No test in this file that uses this state raises an
        // event, so the model is never contacted; a reachable URL would only hide a mistake.
        Arc::new(AppState::new_with_options(
            false,
            "http://127.0.0.1:1".to_string(),
        ))
    }

    async fn connect_to(addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        let (tx, _rx) = mpsc::unbounded_channel();
        StompClient::connect_with_llm_actions(
            addr.to_string(),
            OllamaClient::new("http://127.0.0.1:1".to_string()),
            test_state(),
            tx,
            ClientId::new(1),
            None,
        )
        .await
    }

    /// The happy path of the handshake, and the frame we open with.
    ///
    /// The `CONNECT` assertions matter as much as the success: `accept-version` must name only
    /// what this client implements, and `heart-beat` must be `0,0` because nothing here sends
    /// a heart-beat. A client that advertised `10000,10000` would be torn down by any broker
    /// that believed it.
    #[tokio::test]
    async fn test_connect_frame_is_well_formed_and_a_valid_connected_opens_the_session() {
        let (addr, broker) =
            broker_answering(b"CONNECTED\nversion:1.2\nsession:s-1\nserver:fake/1\n\n\0").await;

        connect_to(addr)
            .await
            .expect("a CONNECTED naming version 1.2 must open the session");

        let request = broker.await.expect("the broker task");
        let text = String::from_utf8_lossy(&request);

        assert!(
            text.starts_with("CONNECT\n"),
            "the session must open with a CONNECT frame, got: {text:?}"
        );
        assert!(
            text.contains("accept-version:1.2\n"),
            "accept-version must name 1.2 and nothing else — offering a dialect this client \
             does not implement is a promise it cannot keep: {text:?}"
        );
        assert!(
            !text.contains("1.0") && !text.contains("1.1"),
            "accept-version must not offer 1.0 or 1.1: {text:?}"
        );
        assert!(
            text.contains("host:127.0.0.1\n"),
            "host must default to the host part of remote_addr: {text:?}"
        );
        assert!(
            text.contains("heart-beat:0,0\n"),
            "heart-beating is not implemented, so it must be negotiated off rather than \
             advertised: {text:?}"
        );
        assert!(
            text.ends_with('\0'),
            "a STOMP frame is NUL-terminated: {text:?}"
        );
        assert!(
            !text.contains("login:") && !text.contains("passcode:"),
            "no credentials were supplied, so no login/passcode headers should be sent: {text:?}"
        );
    }

    /// A `CONNECTED` with no `version` header must be refused.
    ///
    /// This is the negative control the server's own suite records: deleting `version` from
    /// `CONNECTED` makes `async-stomp` fail, and a hand-written peer that never looked at the
    /// header sailed straight past it. This client is on the strict side of that line, so the
    /// test proves the check exists rather than assuming it.
    #[tokio::test]
    async fn test_connected_without_a_version_header_is_refused() {
        let (addr, _broker) = broker_answering(b"CONNECTED\nsession:s-1\n\n\0").await;

        let err = connect_to(addr)
            .await
            .expect_err("a CONNECTED with no version header must not open a session");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("version"),
            "the refusal must name the missing header: {msg}"
        );
    }

    /// A broker that picks a version we never offered must be refused, not humoured.
    ///
    /// STOMP 1.1 and 1.2 disagree about the headers this client's `ACK` uses, so proceeding
    /// would corrupt the session rather than degrade it.
    #[tokio::test]
    async fn test_connected_naming_a_version_we_did_not_offer_is_refused() {
        let (addr, _broker) = broker_answering(b"CONNECTED\nversion:1.1\n\n\0").await;

        let err = connect_to(addr)
            .await
            .expect_err("version 1.1 was never offered and must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("1.1") && msg.contains("1.2"),
            "the refusal must say what the broker chose and what was offered: {msg}"
        );
    }

    /// An `ERROR` in reply to `CONNECT`, and a reply that is not a handshake frame at all.
    #[tokio::test]
    async fn test_a_non_connected_reply_is_refused_and_says_what_arrived() {
        let (addr, _broker) = broker_answering(b"ERROR\nmessage:bad passcode\n\nnot today\0").await;
        let err = connect_to(addr)
            .await
            .expect_err("an ERROR frame must not open a session");
        assert!(
            format!("{err:#}").contains("bad passcode"),
            "the broker's own reason belongs in the log: {err:#}"
        );

        let (addr, _broker) = broker_answering(b"MESSAGE\ndestination:/queue/x\n\nhi\0").await;
        let err = connect_to(addr)
            .await
            .expect_err("a MESSAGE before CONNECTED must not open a session");
        assert!(
            format!("{err:#}").contains("MESSAGE"),
            "the refusal must name the frame that arrived: {err:#}"
        );
    }

    /// A broker that says nothing must not leave the client wedged in `Connecting`.
    #[tokio::test]
    async fn test_a_silent_broker_times_out_rather_than_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _accepted = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            // Never answer, and never close: the timeout is the only thing that can end this.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(socket);
        });

        let (tx, _rx) = mpsc::unbounded_channel();
        let params = {
            use netget::llm::actions::protocol_trait::Protocol;
            let schema = netget::client::stomp::StompClientProtocol::new().get_startup_parameters();
            netget::protocol::StartupParams::new(
                serde_json::json!({"handshake_timeout_secs": 1}),
                schema,
            )
            .expect("handshake_timeout_secs is a declared parameter")
        };

        let started = std::time::Instant::now();
        let err = StompClient::connect_with_llm_actions(
            addr.to_string(),
            OllamaClient::new("http://127.0.0.1:1".to_string()),
            test_state(),
            tx,
            ClientId::new(1),
            Some(params),
        )
        .await
        .expect_err("a broker that never answers must produce an error, not a hang");

        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the handshake timeout must be honoured; waited {:?}",
            started.elapsed()
        );
        assert!(
            format!("{err:#}").contains("no complete frame"),
            "the error must say the broker never answered: {err:#}"
        );
    }

    /// The executor is a pure JSON→frame translator, so every advertised action can be checked
    /// without a socket. These are the shapes the model actually produces.
    #[test]
    fn test_actions_produce_the_frames_the_specification_defines() {
        let protocol = netget::client::stomp::StompClientProtocol::new();

        let bytes = sent_bytes(
            &protocol,
            serde_json::json!({
                "type": "send_stomp_subscribe",
                "destination": "/queue/test",
                "id": "sub-0",
                "ack_mode": "client"
            }),
        );
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.starts_with("SUBSCRIBE\n"), "{text:?}");
        assert!(text.contains("destination:/queue/test\n"), "{text:?}");
        assert!(text.contains("id:sub-0\n"), "{text:?}");
        assert!(
            text.contains("ack:client\n"),
            "ack_mode must become the wire header 'ack': {text:?}"
        );

        // A body given as hex is decoded by the executor, never passed through as text. This
        // is the `send_tcp_data` bug in miniature: "48656c6c6f" is valid as both, so only an
        // explicit encoding can say which was meant.
        let bytes = sent_bytes(
            &protocol,
            serde_json::json!({
                "type": "send_stomp_send",
                "destination": "/queue/bin",
                "body": "00ff41",
                "encoding": "hex"
            }),
        );
        let nul = bytes.iter().rposition(|&b| b == 0).expect("terminator");
        let body_start = bytes
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("header/body separator")
            + 2;
        assert_eq!(
            &bytes[body_start..nul],
            &[0x00, 0xff, 0x41],
            "a hex body must reach the wire as those three bytes, not as six ASCII characters"
        );
        let header_text = String::from_utf8_lossy(&bytes[..body_start]).to_string();
        assert!(
            header_text.contains("content-length:3\n"),
            "content-length must be computed, and it is what lets a body contain NUL: \
             {header_text:?}"
        );

        // ACK/NACK take the delivered frame's `ack` header value as their id.
        let text = String::from_utf8_lossy(&sent_bytes(
            &protocol,
            serde_json::json!({
                "type": "send_stomp_ack", "id": "ack-7"
            }),
        ))
        .to_string();
        assert!(
            text.starts_with("ACK\n") && text.contains("id:ack-7\n"),
            "{text:?}"
        );
        let text = String::from_utf8_lossy(&sent_bytes(
            &protocol,
            serde_json::json!({
                "type": "send_stomp_nack", "id": "ack-7"
            }),
        ))
        .to_string();
        assert!(
            text.starts_with("NACK\n") && text.contains("id:ack-7\n"),
            "{text:?}"
        );

        let text = String::from_utf8_lossy(&sent_bytes(
            &protocol,
            serde_json::json!({
                "type": "send_stomp_unsubscribe", "id": "sub-0"
            }),
        ))
        .to_string();
        assert!(
            text.starts_with("UNSUBSCRIBE\n") && text.contains("id:sub-0\n"),
            "{text:?}"
        );

        // `disconnect` is the specification's graceful shutdown, not a socket close: it must
        // put a DISCONNECT frame carrying a receipt on the wire so the broker can confirm it
        // durably took everything published before it.
        let bytes = sent_bytes(&protocol, serde_json::json!({"type": "disconnect"}));
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.starts_with("DISCONNECT\n"), "{text:?}");
        assert!(
            text.contains("receipt:"),
            "a DISCONNECT without a receipt cannot be acknowledged, which is the whole point \
             of the graceful shutdown: {text:?}"
        );

        assert!(
            matches!(
                protocol
                    .execute_action(serde_json::json!({"type": "wait_for_more"}))
                    .expect("wait_for_more is a real answer"),
                ClientActionResult::WaitForMore
            ),
            "wait_for_more must be distinguishable from having said nothing"
        );
    }

    /// Bad parameters are refused with a reason rather than silently producing a broken frame.
    #[test]
    fn test_invalid_action_parameters_are_refused_with_a_reason() {
        let protocol = netget::client::stomp::StompClientProtocol::new();

        let err = protocol
            .execute_action(serde_json::json!({
                "type": "send_stomp_subscribe",
                "destination": "/queue/test",
                "id": "sub-0",
                "ack_mode": "eventually"
            }))
            .expect_err("an unknown ack mode must be refused");
        assert!(
            err.to_string().contains("client-individual"),
            "the refusal must list the valid modes: {err}"
        );

        let err = protocol
            .execute_action(serde_json::json!({
                "type": "send_stomp_send",
                "destination": "/queue/bin",
                "body": "zzzz",
                "encoding": "hex"
            }))
            .expect_err("a body that is not hex must be refused when encoding says hex");
        assert!(err.to_string().contains("hex"), "{err}");

        let err = protocol
            .execute_action(serde_json::json!({"type": "send_stomp_subscribe", "id": "sub-0"}))
            .expect_err("SUBSCRIBE without a destination is not a frame");
        assert!(err.to_string().contains("destination"), "{err}");

        let err = protocol
            .execute_action(serde_json::json!({
                "type": "send_stomp_send",
                "destination": "/queue/x",
                "headers": {"nested": {"no": "good"}}
            }))
            .expect_err("a STOMP header cannot carry a nested object");
        assert!(err.to_string().contains("nested"), "{err}");
    }

    fn sent_bytes(
        protocol: &netget::client::stomp::StompClientProtocol,
        action: serde_json::Value,
    ) -> Vec<u8> {
        match protocol
            .execute_action(action.clone())
            .unwrap_or_else(|e| panic!("{action} should execute: {e}"))
        {
            ClientActionResult::SendData(bytes) => bytes,
            other => panic!("{action} should produce wire bytes, got {other:?}"),
        }
    }

    /// A whole session against NetGet's own STOMP server, in a separate process.
    ///
    /// CONNECT → CONNECTED → SUBSCRIBE → MESSAGE → SEND → DISCONNECT → RECEIPT → close. Every
    /// step is asserted by a mock expectation on one side or the other: the server's
    /// `stomp_subscribe` rule proves the client subscribed, its `stomp_send` rule proves the
    /// client published in response to a delivery, and its `stomp_disconnect` rule proves the
    /// client left the way the specification says to.
    ///
    /// LLM calls: 5 server-side, 3 client-side.
    #[tokio::test]
    async fn test_stomp_client_session_against_the_netget_broker() -> E2EResult<()> {
        let server_config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via stomp")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("stomp")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "stomp",
                        "instruction": "Broker for the netget STOMP client end-to-end test"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_connect")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_stomp_connected",
                        "version": "1.2",
                        "session": "session-e2e",
                        "server": "netget/stomp"
                    }]))
                    .expect_calls(1)
                    .and()
                    // Deliver one MESSAGE on whatever the client subscribed to, quoting its
                    // own subscription id back — the client's event carries that id, so a
                    // MESSAGE naming any other one would be visibly wrong.
                    .on_event("stomp_subscribe")
                    .respond_with_actions_from_event(|e| {
                        serde_json::json!([{
                            "type": "send_stomp_message",
                            "destination": e["destination"].as_str().unwrap_or("/queue/unknown"),
                            "subscription": e["id"].as_str().unwrap_or("unknown"),
                            "message_id": "msg-e2e-1",
                            "content_type": "text/plain",
                            "body": "ping from the broker",
                            "encoding": "utf8"
                        }])
                    })
                    .expect_calls(1)
                    .and()
                    // The client's echo. A broker that accepts a SEND and says nothing is
                    // behaving normally, so the answer carries no protocol action.
                    .on_event("stomp_send")
                    .respond_with_actions(serde_json::json!([{
                        "type": "show_message",
                        "message": "the STOMP client published its echo"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_disconnect")
                    .respond_with_actions(serde_json::json!([{
                        "type": "show_message",
                        "message": "the STOMP client is leaving"
                    }]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;
        let broker = format!("127.0.0.1:{}", server.port);

        let client_config = NetGetConfig::new(format!(
            "open a stomp client to {broker} and mirror what it receives"
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("open a stomp client to")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": broker,
                    "base_stack": "stomp",
                    "instruction": "Subscribe, echo each delivery, then leave"
                }]))
                .expect_calls(1)
                .and()
                .on_event("stomp_connected")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_stomp_subscribe",
                    "destination": "/queue/e2e",
                    "id": "sub-0",
                    "ack_mode": "auto"
                }]))
                .expect_calls(1)
                .and()
                // One rule, branching on the event, rather than two indistinguishable ones:
                // the echo republishes the delivered body with its own declared encoding, so
                // the exact bytes go back out.
                .on_event("stomp_message_received")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([
                        {
                            "type": "send_stomp_send",
                            "destination": "/queue/echo",
                            "body": e["body"].as_str().unwrap_or(""),
                            "encoding": e["body_encoding"].as_str().unwrap_or("utf8"),
                            "headers": {"echo-of": e["message_id"].as_str().unwrap_or("")}
                        },
                        {"type": "disconnect"}
                    ])
                })
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "the client should report an open session. Output: {:?}",
            client.get_output().await
        );

        // The graceful shutdown completes only when the broker's RECEIPT for our DISCONNECT
        // comes back; the loop then closes and reports it.
        client.wait_for_any(&["disconnected"], 30).await;
        assert!(
            client.output_contains("disconnected").await,
            "the client should close after the broker acknowledged its DISCONNECT. Output: {:?}",
            client.get_output().await
        );

        // Waiting on the mocks waits on the exchange itself: the last call each side makes is
        // exactly the last step of the session.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }
}
