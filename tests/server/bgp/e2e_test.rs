//! E2E tests for the BGP server.
//!
//! These drive a real NetGet process over a real TCP socket with a mocked model, and assert on
//! the exact bytes that come back. Where an expected message is fully determined by the mocked
//! action, it is written out octet by octet from RFC 4271 rather than compared against
//! something NetGet produced — see `tests/server/bgp/test.rs` for why that distinction matters.
//!
//! No BGP daemon is installed on the development machine, so none of this is a substitute for
//! peering against BIRD or FRR. What it does cover is the whole path: socket, framing, OPEN
//! validation, negotiation, the FSM, the model round-trip, and route delivery.

mod e2e_bgp {
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    const BGP_MSG_OPEN: u8 = 1;
    const BGP_MSG_UPDATE: u8 = 2;
    const BGP_MSG_NOTIFICATION: u8 = 3;
    const BGP_MSG_KEEPALIVE: u8 = 4;

    const BGP_MARKER: [u8; 16] = [0xff; 16];

    /// How long to wait for a message that depends on a model round-trip.
    const LLM_TIMEOUT: Duration = Duration::from_secs(60);

    /// Build an OPEN (RFC 4271 section 4.2).
    ///
    /// `four_octet_as` adds the RFC 6793 capability, which is what decides whether NetGet may
    /// send four-octet ASNs in AS_PATH. Both cases are exercised below.
    fn build_bgp_open(
        my_as: u16,
        hold_time: u16,
        router_id: [u8; 4],
        four_octet_as: Option<u32>,
    ) -> Vec<u8> {
        let mut params = Vec::new();
        if let Some(asn) = four_octet_as {
            params.push(0x02); // Optional Parameter type 2: Capabilities
            params.push(0x06); // parameter length
            params.push(0x41); // capability code 65: four-octet AS
            params.push(0x04); // capability length
            params.extend_from_slice(&asn.to_be_bytes());
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);
        msg.extend_from_slice(&[0, 0]); // length, patched below
        msg.push(BGP_MSG_OPEN);
        msg.push(4); // version
        msg.extend_from_slice(&my_as.to_be_bytes());
        msg.extend_from_slice(&hold_time.to_be_bytes());
        msg.extend_from_slice(&router_id);
        msg.push(params.len() as u8);
        msg.extend_from_slice(&params);

        let msg_len = msg.len() as u16;
        msg[16..18].copy_from_slice(&msg_len.to_be_bytes());
        msg
    }

    fn build_bgp_keepalive() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);
        msg.extend_from_slice(&19u16.to_be_bytes());
        msg.push(BGP_MSG_KEEPALIVE);
        msg
    }

    fn build_bgp_notification(error_code: u8, error_subcode: u8, data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);
        msg.extend_from_slice(&[0, 0]);
        msg.push(BGP_MSG_NOTIFICATION);
        msg.push(error_code);
        msg.push(error_subcode);
        msg.extend_from_slice(data);
        let msg_len = msg.len() as u16;
        msg[16..18].copy_from_slice(&msg_len.to_be_bytes());
        msg
    }

    /// Announce 192.0.2.0/24 via 198.51.100.1 from AS 65000, two-octet AS_PATH.
    fn build_bgp_update_announcing_test_net() -> Vec<u8> {
        #[rustfmt::skip]
        let body: Vec<u8> = vec![
            0x00, 0x00,                               // Withdrawn Routes Length
            0x00, 0x12,                               // Total Path Attribute Length = 18
            0x40, 0x01, 0x01, 0x00,                   // ORIGIN IGP
            0x40, 0x02, 0x04, 0x02, 0x01, 0xFD, 0xE8, // AS_PATH AS_SEQUENCE [65000]
            0x40, 0x03, 0x04, 198, 51, 100, 1,        // NEXT_HOP 198.51.100.1
            0x18, 192, 0, 2,                          // NLRI 192.0.2.0/24
        ];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);
        msg.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        msg.push(BGP_MSG_UPDATE);
        msg.extend_from_slice(&body);
        msg
    }

    /// Read one framed BGP message, returning `(type, whole message including header)`.
    async fn read_bgp_message(stream: &mut TcpStream) -> E2EResult<(u8, Vec<u8>)> {
        let mut header = [0u8; 19];
        stream.read_exact(&mut header).await?;
        if header[..16] != BGP_MARKER {
            return Err("Invalid BGP marker".into());
        }
        let length = u16::from_be_bytes([header[16], header[17]]) as usize;
        if !(19..=4096).contains(&length) {
            return Err(format!("BGP message length {length} out of range").into());
        }
        let mut full = vec![0u8; length];
        full[..19].copy_from_slice(&header);
        if length > 19 {
            stream.read_exact(&mut full[19..]).await?;
        }
        Ok((header[18], full))
    }

    /// Startup mock shared by every test here.
    fn startup_actions() -> serde_json::Value {
        serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "BGP",
            "instruction": "BGP router AS 65001, router ID 192.168.1.1",
            "startup_params": { "as_number": 65001, "router_id": "192.168.1.1" }
        }])
    }

    /// The whole point of the protocol: a peer establishes a session and receives routes.
    ///
    /// Also pins the two session steps that were missing before. NetGet now sends a KEEPALIVE
    /// straight after its OPEN, which RFC 4271 section 8.2.2 requires to reach OpenConfirm and
    /// which a peer that waits for it before sending its own would otherwise deadlock on. And
    /// reaching Established raises `bgp_established`, the event a handler answers with routes.
    #[tokio::test]
    async fn test_bgp_session_establishes_and_delivers_routes() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1. \
             Peer with anyone and advertise 10.0.0.0/24 once the session is up.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65001,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_calls(1)
                .and()
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_update",
                    "nlri": ["10.0.0.0/24"],
                    "next_hop": "192.168.1.1",
                    "as_path": [65001],
                    "origin": "IGP"
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await??;

        // Peer speaks four-octet AS, so NetGet must answer in kind and may use four-octet
        // ASNs in AS_PATH.
        client
            .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], Some(65000)))
            .await?;
        client.flush().await?;

        // 1. The server's OPEN, fully determined: AS 65001, hold 180, id 192.168.1.1, plus the
        //    four-octet AS capability NetGet always advertises.
        let (msg_type, open) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_OPEN, "expected OPEN, got type {msg_type}");

        #[rustfmt::skip]
        let expected_open: Vec<u8> = [
            BGP_MARKER.as_slice(),
            &[
                0x00, 0x25,             // length 37
                0x01,                   // OPEN
                0x04,                   // version 4
                0xFD, 0xE9,             // My Autonomous System = 65001
                0x00, 0xB4,             // Hold Time = 180
                192, 168, 1, 1,         // BGP Identifier
                0x08,                   // Optional Parameters Length
                0x02, 0x06,             // Capabilities parameter, length 6
                0x41, 0x04,             // four-octet AS capability
                0x00, 0x00, 0xFD, 0xE9, // AS 65001
            ],
        ]
        .concat();
        assert_eq!(open, expected_open, "server OPEN does not match RFC 4271");

        // 2. The KEEPALIVE that completes our side of the OPEN exchange. Reading it here is the
        //    assertion: before this change nothing was sent until the peer spoke again.
        let (msg_type, keepalive) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(
            msg_type, BGP_MSG_KEEPALIVE,
            "RFC 4271 8.2.2 requires a KEEPALIVE right after our OPEN, got type {msg_type}"
        );
        assert_eq!(keepalive.len(), 19);

        // 3. Our KEEPALIVE takes the session to Established, which raises bgp_established.
        client.write_all(&build_bgp_keepalive()).await?;
        client.flush().await?;

        // 4. Routes arrive. Every field is fixed by the mocked action, so this is an exact
        //    comparison against bytes derived from RFC 4271 section 4.3.
        let (msg_type, update) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(
            msg_type, BGP_MSG_UPDATE,
            "expected the advertised routes as an UPDATE, got type {msg_type}"
        );

        #[rustfmt::skip]
        let expected_update: Vec<u8> = [
            BGP_MARKER.as_slice(),
            &[
                0x00, 0x2F,             // length 47
                0x02,                   // UPDATE
                0x00, 0x00,             // Withdrawn Routes Length = 0
                0x00, 0x14,             // Total Path Attribute Length = 20
                0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
                // AS_PATH: four-octet, because the peer advertised the capability
                0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9,
                0x40, 0x03, 0x04, 192, 168, 1, 1, // NEXT_HOP
                0x18, 10, 0, 0,         // NLRI 10.0.0.0/24, length in bits
            ],
        ]
        .concat();
        assert_eq!(update, expected_update, "advertised route is malformed");

        // The pcap oracle, over the whole session at once, and deliberately *after* the
        // exchange rather than inside `read_bgp_message`.
        //
        // The assertions above compare against byte strings this file wrote out of
        // RFC 4271 by hand; Wireshark's `bgp` dissector walks the same messages by
        // their own length fields — an OPEN's optional-parameter list, an UPDATE's
        // withdrawn-routes / path-attribute / NLRI lengths, three nested fields that
        // must sum to the message length exactly.
        //
        // Placing it here rather than in the read helper is not tidiness. The oracle
        // runs tshark, which is tens of milliseconds, and
        // `test_bgp_keepalive_cadence_and_hold_timer_expiry` reads in a loop with a
        // three-second negotiated hold timer: in the read path the oracle pushed the
        // client's KEEPALIVE past the server's hold timer and the session was torn
        // down before it reached Established. An oracle that changes what the test
        // observes is worse than no oracle.
        crate::helpers::pcap_oracle::PcapOracle::tcp("bgp")
            .peer_input_is_context()
            .to_server(&build_bgp_open(65000, 180, [192, 168, 1, 100], Some(65000)))
            .from_server(&open)
            .from_server(&keepalive)
            .to_server(&build_bgp_keepalive())
            .from_server(&update)
            .assert_clean();

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A peer without the four-octet AS capability must be sent a two-octet AS_PATH (RFC 6793).
    /// Getting this wrong earns NOTIFICATION 3/11 from a real router, and the encoder cannot
    /// know it from the action alone — only the session knows what was negotiated.
    #[tokio::test]
    async fn test_bgp_two_octet_peer_gets_two_octet_as_path() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1. \
             Peer with legacy routers.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65001,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_calls(1)
                .and()
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_update",
                    "nlri": ["10.0.0.0/24"],
                    "next_hop": "192.168.1.1",
                    "as_path": [65001],
                    "origin": "IGP"
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        // No capabilities at all: a two-octet-only speaker.
        client
            .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], None))
            .await?;
        client.flush().await?;

        let (msg_type, _) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_OPEN);
        let (msg_type, _) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_KEEPALIVE);

        client.write_all(&build_bgp_keepalive()).await?;
        client.flush().await?;

        let (msg_type, update) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_UPDATE);

        #[rustfmt::skip]
        let expected_update: Vec<u8> = [
            BGP_MARKER.as_slice(),
            &[
                0x00, 0x2D,             // length 45: two octets shorter than the asn4 form
                0x02,
                0x00, 0x00,
                0x00, 0x12,             // Total Path Attribute Length = 18
                0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
                0x40, 0x02, 0x04, 0x02, 0x01, 0xFD, 0xE9, // AS_PATH, TWO-octet 65001
                0x40, 0x03, 0x04, 192, 168, 1, 1,
                0x18, 10, 0, 0,
            ],
        ]
        .concat();
        assert_eq!(
            update, expected_update,
            "a peer without the four-octet AS capability was sent four-octet ASNs"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// An OPEN NetGet cannot accept is refused in Rust, before the model is consulted.
    ///
    /// The old behaviour asked the model what to do about a version-3 OPEN and accepted every
    /// outcome, including sending it an OPEN back. Protocol validity is not a policy question.
    #[tokio::test]
    async fn test_bgp_invalid_open_is_refused_without_consulting_the_model() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                // If this fires at all, an invalid OPEN reached the model.
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65001,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_at_most(0)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        let mut open = build_bgp_open(65000, 180, [192, 168, 1, 100], None);
        open[19] = 3; // version 3
        client.write_all(&open).await?;
        client.flush().await?;

        let (msg_type, msg) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(
            msg_type, BGP_MSG_NOTIFICATION,
            "a version-3 OPEN must earn a NOTIFICATION, got type {msg_type}"
        );
        // RFC 4271 section 6.2: OPEN Message Error / Unsupported Version Number.
        assert_eq!(
            (msg[19], msg[20]),
            (2, 1),
            "expected NOTIFICATION 2/1, got {}/{}",
            msg[19],
            msg[20]
        );

        // And the session ends rather than lingering.
        let mut scratch = [0u8; 1];
        let closed = timeout(Duration::from_secs(10), client.read(&mut scratch)).await;
        assert!(
            matches!(closed, Ok(Ok(0))),
            "connection should close after NOTIFICATION, got {closed:?}"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The model's refusal to peer is honoured, and is structurally distinct from silence:
    /// a NOTIFICATION goes out and no OPEN ever does.
    #[tokio::test]
    async fn test_bgp_model_can_refuse_to_peer() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1. \
             Refuse to peer with AS 65000.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                .on_event("bgp_open")
                .and_event_data_contains("peer_as", "65000")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_notification",
                    "error_code": 6,
                    "error_subcode": 5
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        client
            .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], None))
            .await?;
        client.flush().await?;

        let (msg_type, msg) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(
            msg_type, BGP_MSG_NOTIFICATION,
            "refusal must be a NOTIFICATION, not an OPEN, got type {msg_type}"
        );
        // Cease / Connection Rejected.
        assert_eq!((msg[19], msg[20]), (6, 5));
        assert_eq!(msg.len(), 21, "no diagnostic data was requested");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Keepalives go out on their own at hold/3, and a peer that stops talking is dropped.
    ///
    /// Both were absent: nothing was ever sent unless the peer spoke first, so a peer waiting
    /// for keepalives would time NetGet out, and a peer that went silent held the socket
    /// forever. A hold time of 3 seconds is the RFC 4271 minimum, which puts keepalives at one
    /// second and expiry at three, so this runs in a few seconds rather than three minutes.
    #[tokio::test]
    async fn test_bgp_keepalive_cadence_and_hold_timer_expiry() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65001,
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

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        // Propose the minimum hold time; the negotiated value is min(180, 3) = 3.
        client
            .write_all(&build_bgp_open(65000, 3, [192, 168, 1, 100], None))
            .await?;
        client.flush().await?;

        let (msg_type, open) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_OPEN);
        // The Hold Time field carries our *proposal*, which the handler set to 180. RFC 4271
        // section 4.2 does not ask a speaker to pre-negotiate it; both sides independently take
        // the minimum. So the observable proof of negotiation is not this field but the timing
        // below: the session must run on 3 seconds, not 180.
        assert_eq!(u16::from_be_bytes([open[22], open[23]]), 180);

        let (msg_type, _) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_KEEPALIVE);

        client.write_all(&build_bgp_keepalive()).await?;
        client.flush().await?;

        // Now go silent. Expect unsolicited keepalives, then the hold timer to fire. The peer
        // sent nothing after its own KEEPALIVE, so expiry is due about three seconds later.
        let mut unsolicited_keepalives = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "hold timer never fired after {unsolicited_keepalives} keepalives"
            );
            let (msg_type, msg) = timeout(remaining, read_bgp_message(&mut client)).await??;
            match msg_type {
                BGP_MSG_KEEPALIVE => unsolicited_keepalives += 1,
                BGP_MSG_NOTIFICATION => {
                    // RFC 4271 section 6.5: Hold Timer Expired, subcode 0.
                    assert_eq!(
                        (msg[19], msg[20]),
                        (4, 0),
                        "expected NOTIFICATION 4/0, got {}/{}",
                        msg[19],
                        msg[20]
                    );
                    assert!(
                        unsolicited_keepalives >= 1,
                        "no keepalive was sent before the hold timer fired; the cadence is missing"
                    );
                    break;
                }
                other => panic!("unexpected message type {other} while idle"),
            }
        }

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A peer's UPDATE is decoded into named fields before it reaches the model.
    ///
    /// The body used to be handed over as `hex::encode(body)`, which no model can act on. The
    /// mock matches on `nlri`, so this test fails if the event data regresses to a blob.
    #[tokio::test]
    async fn test_bgp_peer_update_is_decoded_into_structured_event() -> E2EResult<()> {
        let prompt = "listen on port 0 via bgp. You are AS 65001 with router ID 192.168.1.1. \
             Peer and log the routes you learn.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("bgp")
                .and_instruction_containing("AS 65001")
                .respond_with_actions(startup_actions())
                .expect_calls(1)
                .and()
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_bgp_open",
                    "my_as": 65001,
                    "hold_time": 180,
                    "router_id": "192.168.1.1"
                }]))
                .expect_calls(1)
                .and()
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
                // Matching on the decoded prefix, next hop and AS path: if any of the three is
                // missing or wrong this rule never fires and verify_mocks fails.
                .on_event("bgp_update")
                .and_event_data_contains("nlri", "192.0.2.0/24")
                .and_event_data_contains("next_hop", "198.51.100.1")
                .and_event_data_contains("as_path", "65000")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        client
            .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], None))
            .await?;
        client.flush().await?;

        let (msg_type, _) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_OPEN);
        let (msg_type, _) = timeout(LLM_TIMEOUT, read_bgp_message(&mut client)).await??;
        assert_eq!(msg_type, BGP_MSG_KEEPALIVE);

        client.write_all(&build_bgp_keepalive()).await?;
        client.flush().await?;
        client
            .write_all(&build_bgp_update_announcing_test_net())
            .await?;
        client.flush().await?;

        // Then shut the session down cleanly. RFC 4271 forbids answering a NOTIFICATION, so
        // the correct observable outcome is the socket closing with nothing written back.
        client.write_all(&build_bgp_notification(6, 2, &[])).await?;
        client.flush().await?;

        let mut scratch = [0u8; 1];
        let closed = timeout(Duration::from_secs(30), client.read(&mut scratch)).await;
        assert!(
            matches!(closed, Ok(Ok(0))),
            "a NOTIFICATION must close the session without a reply, got {closed:?}"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
