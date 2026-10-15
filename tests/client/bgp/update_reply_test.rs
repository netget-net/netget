//! A `bgp_update_received` handler's actions must reach the wire.
//!
//! `handle_update_message` used to pass `None` for the write half, on the reasoning that "this
//! client announces nothing, so an UPDATE handler cannot reply on the wire". That conflates
//! announcing *routes* with answering at all: this client's entire vocabulary is
//! `send_keepalive` / `send_notification` / `disconnect` / `wait_for_more`, none of which is a
//! route announcement, and tearing the peering down over a prefix the operator will not accept
//! is the obvious thing a monitor wants to do with an UPDATE.
//!
//! So every action a handler returned for that event was executed nowhere — the
//! "asks the model what to do and then throws the answer away" defect from the root CLAUDE.md,
//! softened only by a `warn!` that said it had been discarded. `tests/client/bgp/CLAUDE.md`
//! listed "the client's `disconnect` and `send_notification` actions reaching a peer" under
//! "Not covered", which is why it survived.
//!
//! ## Shape
//!
//! Like `hold_timer_test.rs` and for the same reasons, this drives
//! `BgpClient::connect_with_llm_actions` directly against a raw `TcpStream` peer that speaks
//! BGP by hand: the assertion is about specific octets (NOTIFICATION 6/2) rather than an event
//! firing, and the peer has to send an UPDATE at a moment of the test's choosing. The small
//! harness below is deliberately a copy of that file's rather than shared — `e2e_test.rs` and
//! `llm_failure_test.rs` in the server suite duplicate their framing helpers the same way.
//!
//! No Ollama is contacted. The reply comes from a **static event handler** registered on the
//! client, which `try_execute_client_event_handler` serves before the LLM budget is debited, so
//! the answer is deterministic and the model is never consulted for this event. (The one call
//! the client does make, on `bgp_connected`, goes to `127.0.0.1:1` and fails — the same path a
//! real client takes when the backend is down.)
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bgp \
//!       --test client -- --test-threads=100 bgp

mod bgp_client_update_reply_tests {
    use netget::client::bgp::{BgpClient, BgpClientProtocol};
    use netget::llm::actions::Protocol;
    use netget::llm::ollama_client::OllamaClient;
    use netget::protocol::StartupParams;
    use netget::scripting::EventHandlerConfig;
    use netget::server::bgp::wire;
    use netget::state::app_state::AppState;
    use netget::state::client::ClientInstance;
    use netget::state::{ClientId, ClientStatus};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    /// RFC 4271 section 4.2 allows 0 or >= 3. Three puts the keepalive cadence at one second,
    /// so the loop below has to filter keepalives out — which is the point: the NOTIFICATION
    /// must be distinguished from the traffic the client generates on its own.
    const HOLD: u16 = 3;

    /// RFC 4271 section 6.7 with the RFC 4486 section 4 subcode: what `disconnect` promises.
    const ERR_CEASE: u8 = 6;
    const SUB_ADMINISTRATIVE_SHUTDOWN: u8 = 2;

    struct Harness {
        state: Arc<AppState>,
        client_id: ClientId,
        _status_rx: mpsc::UnboundedReceiver<String>,
    }

    /// Read one framed BGP message from the peer socket: `(type, whole message with header)`.
    async fn read_bgp<R: tokio::io::AsyncRead + Unpin>(
        sock: &mut R,
    ) -> std::io::Result<(u8, Vec<u8>)> {
        let mut header = [0u8; wire::BGP_HEADER_LEN];
        sock.read_exact(&mut header).await?;
        let (len, msg_type) = wire::parse_header(&header)
            .unwrap_or_else(|e| panic!("client sent an unparseable BGP header: {e:?}"));
        let mut full = vec![0u8; len];
        full[..wire::BGP_HEADER_LEN].copy_from_slice(&header);
        if len > wire::BGP_HEADER_LEN {
            sock.read_exact(&mut full[wire::BGP_HEADER_LEN..]).await?;
        }
        Ok((msg_type, full))
    }

    /// Start a BGP client against `peer_addr` with a static handler for `bgp_update_received`.
    async fn start_client(peer_addr: &str, handler_actions: serde_json::Value) -> Harness {
        let state = Arc::new(AppState::new());
        // Pin the model so `ensure_model_selected` cannot go probing localhost:11434.
        state.set_ollama_model(Some("test-model".to_string())).await;

        let client_id = state
            .add_client(ClientInstance::new(
                ClientId::new(0),
                peer_addr.to_string(),
                "bgp".to_string(),
                "Monitor the peer".to_string(),
            ))
            .await;

        // Built from JSON rather than the enum variants, because this is byte for byte the
        // shape `get_startup_examples` teaches and an `open_client` action carries, so the test
        // exercises the same deserialisation a real caller does.
        let config: EventHandlerConfig = serde_json::from_value(serde_json::json!({
            "handlers": [{
                "event_pattern": "bgp_update_received",
                "handler": { "type": "static", "actions": handler_actions }
            }]
        }))
        .expect("the event handler config should deserialise");

        // Registered before the handshake, so it is in place long before an UPDATE can arrive:
        // the peer below does not send one until it has driven the session to Established.
        state
            .set_client_event_handler_config(client_id, Some(config))
            .await;

        let params = StartupParams::new(
            serde_json::json!({
                "local_as": 65001,
                "router_id": "192.168.1.100",
                "hold_time": HOLD,
            }),
            BgpClientProtocol::new().get_startup_parameters(),
        )
        .expect("BGP client startup parameters should validate");

        let (status_tx, status_rx) = mpsc::unbounded_channel();

        BgpClient::connect_with_llm_actions(
            peer_addr.to_string(),
            OllamaClient::new("http://127.0.0.1:1"),
            state.clone(),
            status_tx,
            client_id,
            Some(params),
        )
        .await
        .expect("BGP client should connect to the peer socket");

        Harness {
            state,
            client_id,
            _status_rx: status_rx,
        }
    }

    /// Play the peer through OPEN / OPEN / KEEPALIVE / KEEPALIVE, leaving the client Established.
    async fn complete_handshake(peer: &mut TcpStream) {
        let (msg_type, _) = read_bgp(peer).await.expect("client should send an OPEN");
        assert_eq!(
            msg_type,
            wire::MSG_OPEN,
            "the client's first message must be an OPEN"
        );

        let open = wire::encode(wire::build_open(65000, HOLD, Ipv4Addr::new(192, 168, 1, 1)))
            .expect("peer OPEN should encode");
        peer.write_all(&open).await.expect("peer should send OPEN");

        let (msg_type, _) = read_bgp(peer)
            .await
            .expect("client should answer our OPEN with a KEEPALIVE");
        assert_eq!(
            msg_type,
            wire::MSG_KEEPALIVE,
            "the client must send a KEEPALIVE after receiving our OPEN"
        );

        peer.write_all(&wire::encode_keepalive())
            .await
            .expect("peer should send KEEPALIVE");
    }

    /// One announcement of 10.0.0.0/24, built through the same encoder the server uses.
    ///
    /// `encode_intent` is used rather than `build_update` so the test needs no netgauze types of
    /// its own: it takes the validated-intent JSON that a `send_bgp_update` action produces.
    /// `peer_asn4` is false because the OPEN above advertises no capabilities, so a two-octet
    /// AS_PATH is what the client is expecting to read.
    fn peer_update() -> Vec<u8> {
        wire::encode_intent(
            &serde_json::json!({
                "kind": "update",
                "nlri": ["10.0.0.0/24"],
                "next_hop": "192.168.1.1",
                "as_path": [65000],
                "origin": "IGP",
            }),
            false,
        )
        .expect("peer UPDATE should encode")
    }

    /// Wait for a NOTIFICATION, ignoring the keepalives the client emits on its own timer.
    ///
    /// The deadline covers the whole wait rather than each read: a per-read timeout is reset by
    /// every keepalive, so a client that keepalives forever would hang the test instead of
    /// failing it.
    async fn read_past_keepalives<R: tokio::io::AsyncRead + Unpin>(
        sock: &mut R,
        within: Duration,
        context: &str,
    ) -> Vec<u8> {
        let give_up_at = Instant::now() + within;
        loop {
            let remaining = give_up_at
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("{context}"));
            let (msg_type, msg) = tokio::time::timeout(remaining, read_bgp(sock))
                .await
                .unwrap_or_else(|_| panic!("{context}"))
                .unwrap_or_else(|e| {
                    panic!("{context} — the client closed the connection instead ({e})")
                });
            match msg_type {
                wire::MSG_KEEPALIVE => continue,
                wire::MSG_NOTIFICATION => return msg,
                other => panic!("unexpected BGP message type {other} while waiting: {msg:02x?}"),
            }
        }
    }

    /// A `disconnect` returned for `bgp_update_received` puts a Cease NOTIFICATION on the wire
    /// and ends the session.
    ///
    /// This is the test that fails without the fix: with `write_half: None` the handler's
    /// answer was logged as discarded, the client kept keepaliving, and no NOTIFICATION ever
    /// arrived.
    #[tokio::test]
    async fn update_handler_disconnect_reaches_the_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = listener.local_addr().expect("local_addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let harness = start_client(
            &addr.to_string(),
            serde_json::json!([{ "type": "disconnect" }]),
        )
        .await;
        let (mut peer, _) = accepted
            .await
            .expect("accept task")
            .expect("peer should accept the client");

        complete_handshake(&mut peer).await;
        peer.write_all(&peer_update())
            .await
            .expect("peer should send an UPDATE");

        let notification = read_past_keepalives(
            &mut peer,
            Duration::from_secs(15),
            "no NOTIFICATION after an UPDATE whose handler answered `disconnect` — the \
             handler's actions are not reaching the wire",
        )
        .await;

        // Decoded field by field against RFC 4271 section 4.5, with the codes written as
        // literals as well as via the constants so a renumbering cannot make this agree with
        // itself.
        assert_eq!(
            notification.len(),
            21,
            "`disconnect` supplies no diagnostic data, so the NOTIFICATION is 19 header octets \
             plus code and subcode; got {} octets: {:02x?}",
            notification.len(),
            notification
        );
        assert_eq!(
            &notification[..16],
            &wire::BGP_MARKER[..],
            "marker must be sixteen 0xff octets"
        );
        assert_eq!(
            notification[18],
            wire::MSG_NOTIFICATION,
            "type octet must be 3 (NOTIFICATION)"
        );
        assert_eq!(
            notification[19], 6,
            "`disconnect` promises Cease (error code 6), got {}",
            notification[19]
        );
        assert_eq!(notification[19], ERR_CEASE);
        assert_eq!(
            notification[20], SUB_ADMINISTRATIVE_SHUTDOWN,
            "Cease subcode 2 is Administrative Shutdown (RFC 4486 section 4), got {}",
            notification[20]
        );

        // RFC 4271 section 6.7: saying goodbye is not enough, the connection closes too.
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => {
                panic!("expected the connection to close after the NOTIFICATION, got {n} byte(s)")
            }
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ),
                "unexpected error while waiting for the close: {e}"
            ),
            Err(_) => panic!(
                "client sent the Cease NOTIFICATION but kept the connection open — \
                 `ClientActionResult::Disconnect` did not stop the read loop"
            ),
        }

        let status = harness
            .state
            .get_client(harness.client_id)
            .await
            .expect("client should still be registered")
            .status;
        assert!(
            matches!(status, ClientStatus::Disconnected),
            "expected Disconnected after the handler tore the session down, got {status:?}"
        );
    }

    /// The negative control, and the reason the test above proves anything.
    ///
    /// Same peer, same UPDATE, same code path — only the handler's answer differs. A
    /// `wait_for_more` must leave the session up, so a client that answered *every* UPDATE with
    /// a teardown (or one whose NOTIFICATION came from somewhere other than the handler, such
    /// as a hold timer misfiring) fails here rather than passing both.
    #[tokio::test]
    async fn update_handler_wait_for_more_leaves_the_session_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = listener.local_addr().expect("local_addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let harness = start_client(
            &addr.to_string(),
            serde_json::json!([{ "type": "wait_for_more" }]),
        )
        .await;
        let (peer, _) = accepted
            .await
            .expect("accept task")
            .expect("peer should accept the client");

        // Split so the peer can keep the session alive while the test reads: with a 3s hold
        // time, going silent would expire the client's hold timer and produce a NOTIFICATION
        // that has nothing to do with the handler.
        let (mut peer_rx, mut peer_tx) = tokio::io::split(peer);
        {
            let (msg_type, _) = read_bgp(&mut peer_rx)
                .await
                .expect("client should send an OPEN");
            assert_eq!(msg_type, wire::MSG_OPEN);
            let open = wire::encode(wire::build_open(65000, HOLD, Ipv4Addr::new(192, 168, 1, 1)))
                .expect("peer OPEN should encode");
            peer_tx.write_all(&open).await.expect("peer OPEN");
            let (msg_type, _) = read_bgp(&mut peer_rx)
                .await
                .expect("client should answer with a KEEPALIVE");
            assert_eq!(msg_type, wire::MSG_KEEPALIVE);
            peer_tx
                .write_all(&wire::encode_keepalive())
                .await
                .expect("peer KEEPALIVE");
            peer_tx
                .write_all(&peer_update())
                .await
                .expect("peer UPDATE");
        }

        let feeder = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if peer_tx.write_all(&wire::encode_keepalive()).await.is_err() {
                    return;
                }
            }
        });

        let watch_until = Instant::now() + Duration::from_secs(7);
        while let Some(remaining) = watch_until.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(remaining, read_bgp(&mut peer_rx)).await {
                // Nothing more before the deadline: that is the good outcome.
                Err(_) => break,
                Ok(Ok((msg_type, msg))) => assert_eq!(
                    msg_type,
                    wire::MSG_KEEPALIVE,
                    "a `wait_for_more` handler must leave the session alone, but the client sent \
                     message type {msg_type}: {msg:02x?}"
                ),
                Ok(Err(e)) => {
                    panic!("client closed the session after a `wait_for_more` handler ({e})")
                }
            }
        }
        feeder.abort();

        let status = harness
            .state
            .get_client(harness.client_id)
            .await
            .expect("client should still be registered")
            .status;
        assert!(
            matches!(status, ClientStatus::Connected),
            "expected the session to still be up after `wait_for_more`, got {status:?}"
        );
    }
}
