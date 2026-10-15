//! End-to-end STOMP 1.2 tests driven by a **real third-party client**.
//!
//! The peer here is `async-stomp` 0.6.3 — an independent implementation of STOMP 1.2, not a
//! codec this test drives frame by frame. It opens the socket, sends `CONNECT`, and refuses to
//! return a transport unless the reply is a well-formed `CONNECTED`; it then decodes every
//! subsequent frame into typed values (`FromServer::Message`, `FromServer::Receipt`) with its
//! own parser, hard-erroring if a required header is missing. **This is the evidence behind
//! the `Beta` rating.**
//!
//! Nothing in this file touches `netget::server::stomp::frame`. A test that parsed the
//! server's output with the server's own parser would assert only that one module round-trips
//! through itself — the circular-evidence trap the root `CLAUDE.md` records for `rss` and
//! `webrtc_signaling`. `async-stomp` doing the parsing is the entire point.
//!
//! **These tests cannot skip.** `async-stomp` is a crate dependency compiled into this binary,
//! so there is no "is it installed?" question and no code path that turns an absent client
//! into `Ok(())`. Every failure path below is an `assert!`, an `expect`, or a `?` on an error
//! that propagates. That is deliberate, in the spirit of `npm`'s real-client test: a suite that
//! silently skips would leave STOMP's maturity rating resting on nothing.
//!
//! Cases a real client cannot express — a frame sent before the handshake, an unsupported
//! `accept-version`, deliberately broken framing, a body containing NUL — live in
//! `raw_socket_test.rs`, and the codec's own edges in `codec_test.rs`.
//!
//! LLM budget: 7 calls across two tests. See `tests/server/stomp/CLAUDE.md`.

mod stomp_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use async_stomp::client::{ClientTransport, Connector, Subscriber};
    use async_stomp::{FromServer, Message, ToServer};
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;

    /// Read the next frame the server sends, decoded by `async-stomp`'s own parser.
    ///
    /// A timeout here is a failure, never a skip: the mock has already been told what to
    /// answer, so a frame that does not arrive means the server did not send it.
    async fn next_frame(conn: &mut ClientTransport, what: &str) -> Message<FromServer> {
        tokio::time::timeout(Duration::from_secs(20), conn.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("the server closed the connection while {what} was expected"))
            .unwrap_or_else(|e| panic!("async-stomp could not decode {what}: {e}"))
    }

    /// A real STOMP client completes a whole session against this server.
    ///
    /// `Connector::connect()` is itself half the assertion: it sends `CONNECT` and returns
    /// `Err` unless the reply is a `CONNECTED` frame carrying a `version` header. Everything
    /// after it is `async-stomp` decoding our frames and finding the headers it requires.
    #[tokio::test]
    async fn test_stomp_session_against_the_async_stomp_client() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via stomp")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("stomp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "stomp",
                            "instruction": "STOMP broker: accept every CONNECT and echo whatever is published"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_connect")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_stomp_connected",
                            "version": "1.2",
                            "session": "session-1",
                            "server": "netget/stomp"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Quote back the subscription id the client chose. async-stomp surfaces
                    // `subscription` as a typed field, so a MESSAGE naming any other id is
                    // visibly wrong rather than quietly ignored.
                    .on_event("stomp_subscribe")
                    .respond_with_actions_from_event(|e| serde_json::json!([{
                        "type": "send_stomp_message",
                        "destination": e["destination"].as_str().unwrap_or("/queue/unknown"),
                        "subscription": e["id"].as_str().unwrap_or("unknown"),
                        "message_id": "msg-welcome",
                        "content_type": "text/plain",
                        "body": "welcome",
                        "encoding": "utf8"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_send")
                    .respond_with_actions_from_event(|e| serde_json::json!([{
                        "type": "send_stomp_message",
                        "destination": e["destination"].as_str().unwrap_or("/queue/unknown"),
                        "subscription": "sub-0",
                        "message_id": "msg-echo",
                        "body": e["body"].as_str().unwrap_or(""),
                        "encoding": e["body_encoding"].as_str().unwrap_or("utf8")
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_disconnect")
                    .respond_with_actions(serde_json::json!([
                        {"type": "show_message", "message": "STOMP client is leaving"}
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        // --- handshake ------------------------------------------------------------------
        // connect() sends CONNECT and verifies the reply is CONNECTED with a `version`
        // header. If our server got the framing, the escaping or the header set wrong, this
        // is where a real client gives up — and so does this test.
        let mut conn: ClientTransport = Connector::builder()
            .server(addr.clone())
            .virtualhost("localhost")
            .login("guest".to_string())
            .passcode("guest".to_string())
            .connect()
            .await
            .map_err(|e| {
                format!(
                    "async-stomp could not complete the STOMP handshake against netget: {e}. \
                     This is a defect in src/server/stomp, not in the test."
                )
            })?;

        // --- SUBSCRIBE ------------------------------------------------------------------
        conn.send(
            Subscriber::builder()
                .destination("/queue/test")
                .id("sub-0")
                .subscribe(),
        )
        .await
        .map_err(|e| format!("async-stomp could not send SUBSCRIBE: {e}"))?;

        let frame = next_frame(&mut conn, "the MESSAGE answering SUBSCRIBE").await;
        match frame.content {
            FromServer::Message {
                destination,
                message_id,
                subscription,
                body,
                ..
            } => {
                assert_eq!(destination, "/queue/test");
                assert_eq!(message_id, "msg-welcome");
                assert_eq!(
                    subscription, "sub-0",
                    "the MESSAGE must quote the id the client chose, or a real client \
                     discards it"
                );
                assert_eq!(body.as_deref(), Some(&b"welcome"[..]));
            }
            other => panic!("expected a MESSAGE, got {other:?}"),
        }

        // --- SEND, and get it echoed back ----------------------------------------------
        // async-stomp writes no content-length, so this exercises the read-to-NUL path of
        // the server's parser. The content-length path is covered in raw_socket_test.rs,
        // because async-stomp cannot produce a body containing NUL.
        conn.send(Message::from(ToServer::Send {
            destination: "/queue/test".to_string(),
            transaction: None,
            headers: None,
            body: Some(b"hello from async-stomp".to_vec()),
        }))
        .await
        .map_err(|e| format!("async-stomp could not send SEND: {e}"))?;

        let frame = next_frame(&mut conn, "the MESSAGE echoing SEND").await;
        match frame.content {
            FromServer::Message {
                destination,
                message_id,
                body,
                ..
            } => {
                assert_eq!(destination, "/queue/test");
                assert_eq!(message_id, "msg-echo");
                assert_eq!(
                    body.as_deref(),
                    Some(&b"hello from async-stomp"[..]),
                    "the published body did not survive the body/body_encoding round trip"
                );
            }
            other => panic!("expected the echoed MESSAGE, got {other:?}"),
        }

        // --- DISCONNECT with a receipt --------------------------------------------------
        conn.send(Message::from(ToServer::Disconnect {
            receipt: Some("r-bye".to_string()),
        }))
        .await
        .map_err(|e| format!("async-stomp could not send DISCONNECT: {e}"))?;

        let frame = next_frame(&mut conn, "the RECEIPT answering DISCONNECT").await;
        match frame.content {
            FromServer::Receipt { receipt_id } => assert_eq!(receipt_id, "r-bye"),
            other => panic!("expected a RECEIPT, got {other:?}"),
        }

        // The spec has the server close after the DISCONNECT receipt, and the client sees
        // that as the end of the stream rather than as an error.
        let end = tokio::time::timeout(Duration::from_secs(20), conn.next())
            .await
            .map_err(|_| "the server did not close the connection after the DISCONNECT receipt")?;
        assert!(
            end.is_none(),
            "expected the stream to end after DISCONNECT, got {end:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A refusal must reach a real client as a decodable `ERROR`, not as a dropped connection.
    ///
    /// `async-stomp` fails the handshake with the frame it actually received, so asserting on
    /// its error text proves the ERROR frame parsed and its `message` header survived.
    #[tokio::test]
    async fn test_stomp_connect_refusal_is_seen_by_the_async_stomp_client() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via stomp")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("stomp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "stomp",
                            "instruction": "STOMP broker that rejects every login"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("stomp_connect")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_stomp_error",
                            "message": "authentication failed",
                            "body": "The login/passcode pair was not recognised."
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let outcome = Connector::builder()
            .server(addr)
            .virtualhost("localhost")
            .login("nobody".to_string())
            .passcode("wrong".to_string())
            .connect()
            .await;

        let err = match outcome {
            Ok(_) => panic!("the handshake succeeded although the server answered with ERROR"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("authentication failed"),
            "async-stomp did not decode the ERROR frame's message header; it reported: {err}"
        );
        assert!(
            err.contains("not recognised"),
            "async-stomp did not decode the ERROR frame's body; it reported: {err}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
