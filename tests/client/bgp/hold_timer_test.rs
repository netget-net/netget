//! Hold-timer enforcement for the BGP client (RFC 4271 sections 4.2, 6.5 and 10).
//!
//! A BGP speaker MUST drop the session when its Hold Timer expires — no KEEPALIVE, UPDATE or
//! NOTIFICATION within the negotiated hold time — sending a NOTIFICATION with error code 4
//! (Hold Timer Expired) first. The client used to send keepalives at the negotiated cadence and
//! enforce nothing, so a peer that went silent was noticed only when TCP eventually noticed:
//! many minutes on a live connection, and never on a half-open one with no traffic.
//!
//! ## Why these tests drive the protocol directly
//!
//! `e2e_test.rs` in this directory drives a NetGet BGP *server* through the mock-Ollama harness,
//! which is the right shape for "does the session come up". It is the wrong shape here for two
//! reasons: the peer has to go *deliberately silent*, which a working NetGet server never does,
//! and the assertion is about specific octets — `wire::MSG_NOTIFICATION`, error code 4 — not
//! about an event firing. So the peer is a raw `TcpStream` that speaks BGP by hand, and the
//! assertions are on the bytes it reads.
//!
//! No Ollama is needed or contacted. The model name is pinned in `AppState` so
//! `ensure_model_selected` never probes `localhost:11434`, and the LLM endpoint is
//! `127.0.0.1:1`, so the one model call the client makes (on `bgp_connected`) fails with
//! connection-refused and is logged — the same path a real client takes when the backend is
//! down. That the hold timer still fires *while the read loop is off in a failing LLM call* is
//! part of what is being tested: the timer lives in its own task for exactly that reason.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bgp \
//!       --test client -- --test-threads=100 bgp

mod bgp_client_hold_timer_tests {
    use netget::client::bgp::{BgpClient, BgpClientProtocol};
    use netget::llm::actions::Protocol;
    use netget::llm::ollama_client::OllamaClient;
    use netget::protocol::StartupParams;
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

    /// RFC 4271 section 4.2 allows 0 or >= 3. Three keeps the whole suite to a few seconds and
    /// puts the keepalive cadence at one second (`ceil(3/3)`).
    const HOLD: u16 = 3;

    /// What the client is left holding: the state it was registered in, its id, and the status
    /// channel (kept alive so the client's sends are not dropped on a closed receiver).
    struct Harness {
        state: Arc<AppState>,
        client_id: ClientId,
        _status_rx: mpsc::UnboundedReceiver<String>,
    }

    /// Read one framed BGP message from the peer socket: `(type, whole message with header)`.
    ///
    /// Not cancellation-safe — a dropped `read_exact` loses whatever it had consumed — so it is
    /// never raced against another branch except at a point where the test is finished reading.
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

    /// Start a BGP client against `peer_addr`, proposing `hold_time`.
    async fn start_client(peer_addr: &str, hold_time: u16) -> Harness {
        let state = Arc::new(AppState::new());
        // Pin the model: with none set, `ensure_model_selected` goes looking for Ollama on
        // localhost:11434, so whether this test contacts anything would depend on what the
        // developer happens to be running.
        state.set_ollama_model(Some("test-model".to_string())).await;

        let client_id = state
            .add_client(ClientInstance::new(
                ClientId::new(0),
                peer_addr.to_string(),
                "bgp".to_string(),
                "Monitor the peer".to_string(),
            ))
            .await;

        let params = StartupParams::new(
            serde_json::json!({
                "local_as": 65001,
                "router_id": "192.168.1.100",
                "hold_time": hold_time,
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
    ///
    /// Proposing the same `hold_time` the client did makes the negotiated value exactly that,
    /// so the test knows the deadline it is measuring against.
    async fn complete_handshake(peer: &mut TcpStream, hold_time: u16) {
        let (msg_type, _) = read_bgp(peer).await.expect("client should send an OPEN");
        assert_eq!(
            msg_type,
            wire::MSG_OPEN,
            "the client's first message must be an OPEN"
        );

        let open = wire::encode(wire::build_open(
            65000,
            hold_time,
            Ipv4Addr::new(192, 168, 1, 1),
        ))
        .expect("peer OPEN should encode");
        peer.write_all(&open).await.expect("peer should send OPEN");

        // RFC 4271 section 8.2.2: the client answers our OPEN with a KEEPALIVE and enters
        // OpenConfirm.
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

    /// A peer that goes silent is dropped: NOTIFICATION error code 4, then close.
    ///
    /// This is the test that fails without the fix. The old client had no hold timer at all, so
    /// nothing was ever written after the handshake and this would time out at the 12s bound.
    #[tokio::test]
    async fn silent_peer_earns_hold_timer_expired_notification_and_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = listener.local_addr().expect("local_addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let harness = start_client(&addr.to_string(), HOLD).await;
        let (mut peer, _) = accepted
            .await
            .expect("accept task")
            .expect("peer should accept the client");

        complete_handshake(&mut peer, HOLD).await;
        let silent_since = Instant::now();

        // From here the peer says nothing at all. Everything the client sends is read, so its
        // own keepalives (one per second, at ceil(hold/3)) cannot mask the NOTIFICATION.
        //
        // The deadline is for the whole wait, not per read. A per-read timeout would be reset by
        // every keepalive, so a client that keepalives forever and never expires would hang this
        // test instead of failing it — which is exactly what the mutation check produced.
        let give_up_at = Instant::now() + Duration::from_secs(12);
        let mut keepalives = 0usize;
        let notification = loop {
            let remaining = give_up_at.checked_duration_since(Instant::now()).expect(
                "no NOTIFICATION within 12s of total silence on a 3s hold time — the client is \
                 not enforcing its hold timer",
            );
            let (msg_type, msg) = tokio::time::timeout(remaining, read_bgp(&mut peer))
                .await
                .expect(
                    "no NOTIFICATION within 12s of total silence on a 3s hold time — the client \
                     is not enforcing its hold timer",
                )
                .expect("client closed the connection without sending a NOTIFICATION");
            match msg_type {
                wire::MSG_KEEPALIVE => keepalives += 1,
                wire::MSG_NOTIFICATION => break msg,
                other => panic!("unexpected BGP message type {other} while waiting for expiry"),
            }
        };
        let elapsed = silent_since.elapsed();

        // The bytes, decoded field by field against RFC 4271 section 4.5: 16-octet marker,
        // 2-octet length, 1-octet type, then error code and subcode.
        assert_eq!(
            notification.len(),
            21,
            "a NOTIFICATION with no data is 19 header octets plus code and subcode, got {} \
             octets: {:02x?}",
            notification.len(),
            notification
        );
        assert_eq!(
            &notification[..16],
            &wire::BGP_MARKER[..],
            "marker must be sixteen 0xff octets"
        );
        assert_eq!(
            u16::from_be_bytes([notification[16], notification[17]]),
            21,
            "length field must match the message"
        );
        assert_eq!(
            notification[18],
            wire::MSG_NOTIFICATION,
            "type octet must be 3 (NOTIFICATION)"
        );
        // Written as the literal from the RFC rather than only via the constant, so renaming or
        // renumbering `ERR_HOLD_TIMER_EXPIRED` cannot make this assertion agree with itself.
        assert_eq!(
            notification[19], 4,
            "RFC 4271 section 4.5: error code 4 is Hold Timer Expired, got {}",
            notification[19]
        );
        assert_eq!(notification[19], wire::ERR_HOLD_TIMER_EXPIRED);
        assert_eq!(
            notification[20], 0,
            "Hold Timer Expired defines no subcodes, so the subcode octet must be 0"
        );

        // Timing: tight below, generous above. Below, because dropping the session early would
        // pass a "did it send a NOTIFICATION" check while being a different bug. Above, only to
        // keep the failure message useful — the 12s read timeout is the real ceiling.
        assert!(
            elapsed >= Duration::from_millis(1500),
            "session dropped after only {elapsed:?} on a 3s hold time — that is not the hold \
             timer firing"
        );
        assert!(
            elapsed <= Duration::from_secs(10),
            "hold timer took {elapsed:?} to fire on a 3s hold time"
        );
        assert!(
            keepalives >= 1,
            "expected at least one keepalive at ceil(hold/3) before expiry, got {keepalives}"
        );

        // RFC 4271 section 6.5: the connection is closed, not merely complained about.
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!(
                "expected the connection to close after the NOTIFICATION, got {n} more byte(s)"
            ),
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ),
                "unexpected error while waiting for the close: {e}"
            ),
            Err(_) => panic!(
                "client sent NOTIFICATION 4/0 but kept the connection open — the read loop \
                 outlived the hold-timer teardown"
            ),
        }

        // And the client marks itself down rather than lingering as Connected in the UI.
        let status = harness
            .state
            .get_client(harness.client_id)
            .await
            .expect("client should still be registered")
            .status;
        assert!(
            matches!(status, ClientStatus::Disconnected),
            "expected Disconnected after hold-timer teardown, got {status:?}"
        );
    }

    /// The negative case: a peer that keeps sending KEEPALIVEs is never dropped.
    ///
    /// Without a reset on every received message the timer would fire at three seconds; this
    /// watches for seven, well past two hold times.
    #[tokio::test]
    async fn keepaliving_peer_is_not_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = listener.local_addr().expect("local_addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let harness = start_client(&addr.to_string(), HOLD).await;
        let (mut peer, _) = accepted
            .await
            .expect("accept task")
            .expect("peer should accept the client");

        complete_handshake(&mut peer, HOLD).await;

        // The write half goes to its own task so the read side is never raced against a timer
        // in a `select!` — `read_bgp` is not cancellation-safe.
        let (mut peer_rx, mut peer_tx) = tokio::io::split(peer);
        let feeder = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if peer_tx.write_all(&wire::encode_keepalive()).await.is_err() {
                    return;
                }
            }
        });

        let watch_until = Instant::now() + Duration::from_secs(7);
        let mut from_client = 0usize;
        while let Some(remaining) = watch_until.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(remaining, read_bgp(&mut peer_rx)).await {
                // Nothing more before the deadline: that is the good outcome.
                Err(_) => break,
                Ok(Ok((msg_type, msg))) => {
                    assert_ne!(
                        msg_type,
                        wire::MSG_NOTIFICATION,
                        "client tore the session down while its peer was keepaliving: {:02x?}",
                        msg
                    );
                    assert_eq!(
                        msg_type,
                        wire::MSG_KEEPALIVE,
                        "expected only KEEPALIVEs from a monitoring client, got type {msg_type}"
                    );
                    from_client += 1;
                }
                Ok(Err(e)) => panic!(
                    "client closed the connection ({e}) while its peer was sending KEEPALIVEs"
                ),
            }
        }
        feeder.abort();

        // Seven seconds at one keepalive per second, minus scheduling slack. More to the point,
        // reaching four means the client was still sending them well past the 3s deadline it
        // would have hit had the timer not been reset.
        assert!(
            from_client >= 4,
            "expected the client to keep sending keepalives past two hold times, got \
             {from_client} in 7s"
        );

        // Still Connected: the read loop sets Disconnected on the way out, so this is a direct
        // check that the session is alive rather than an inference from silence.
        let status = harness
            .state
            .get_client(harness.client_id)
            .await
            .expect("client should still be registered")
            .status;
        assert!(
            matches!(status, ClientStatus::Connected),
            "expected the session to still be up, got {status:?}"
        );
    }
}
