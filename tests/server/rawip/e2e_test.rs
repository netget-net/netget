//! Generic raw IP protocol-N tests.
//!
//! Two halves, and the split is the whole test strategy:
//!
//! 1. **The IP header decoder, against literal packet bytes.** It is a pure function over a
//!    byte slice, so it can be asserted exactly — IPv4 with and without options, a fragmented
//!    packet, IPv6, and a set of truncated and malformed inputs that must be *refused* rather
//!    than panic. This is the part of the protocol that is actually proven.
//! 2. **The full decode -> event -> LLM -> action path**, over the unprivileged UDP test
//!    transport (`transport: "udp"`), which carries whole IP packets inside datagrams. This
//!    exercises the same decoder, the same event, the same executor and the same emit path
//!    that the raw socket would, without needing root.
//!
//! What is **not** tested anywhere, and must not be claimed: the raw socket itself. Opening
//! `SOCK_RAW` needs root or `CAP_NET_RAW`, so nothing here binds one, sends on one or receives
//! on one. See `src/server/rawip/CLAUDE.md`.
//!
//! The transport tests call `RawIpServer::spawn_with_llm_actions` directly rather than going
//! through `ServerForm::create`. That is not a shortcut around the framework: the privilege
//! gate in `server_startup` reads the protocol's *static* `metadata()`, which declares
//! `RawSockets`, so an unprivileged start is refused whatever `transport` says. The gate is a
//! startup-path property; the server module underneath it is what these tests drive.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rawip \
//!       --test server -- server::rawip::e2e_test --test-threads=100

#[cfg(unix)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::helpers::mock_builder::MockLlmBuilder;
    use crate::helpers::mock_ollama::MockOllamaServer;
    use crate::helpers::E2EResult;

    use netget::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
    use netget::llm::OllamaClient;
    use netget::protocol::StartupParams;
    use netget::server::rawip::actions::RawIpProtocol;
    use netget::server::rawip::{
        decode_ip_packet, ip_protocol_name, IpDecodeError, IpHeader, IpVersion, RawIpConfig,
        RawIpServer, RawIpTransport,
    };
    use netget::state::app_state::AppState;
    use netget::state::server::ServerInstance;
    use netget::state::ServerId;
    use serde_json::json;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    // ========================================================================
    // Literal packet bytes
    // ========================================================================

    /// IPv4, no options, IP protocol 47 (GRE), DF set, 8 bytes of payload.
    ///
    /// Byte for byte against RFC 791 §3.1. The header checksum is left zero on purpose: the
    /// decoder reports the field and does not validate it, because a raw socket has already
    /// had the kernel validate it and re-checking would only reject packets the OS accepted.
    fn ipv4_gre_packet() -> Vec<u8> {
        let mut p = vec![
            0x45, // version 4, IHL 5
            0xB9, // DSCP 46 (EF), ECN 1
            0x00, 0x1C, // total length 28
            0x12, 0x34, // identification
            0x40, 0x00, // flags: DF; fragment offset 0
            0x40, // TTL 64
            0x2F, // protocol 47 (GRE)
            0x00, 0x00, // header checksum (not validated here)
            192, 0, 2, 1, // source 192.0.2.1
            192, 0, 2, 10, // destination 192.0.2.10
        ];
        p.extend_from_slice(&[0x00, 0x00, 0x65, 0x58, 0xDE, 0xAD, 0xBE, 0xEF]);
        p
    }

    /// The same packet with one 4-byte option (Router Alert, RFC 2113), so IHL is 6.
    fn ipv4_with_options_packet() -> Vec<u8> {
        let mut p = vec![
            0x46, // version 4, IHL 6 -> 24-byte header
            0x00, //
            0x00, 0x1C, // total length 28 = 24 header + 4 payload
            0x00, 0x01, //
            0x00, 0x00, //
            0x20, // TTL 32
            0x32, // protocol 50 (ESP)
            0x00, 0x00, //
            10, 0, 0, 1, //
            10, 0, 0, 2, //
            0x94, 0x04, 0x00, 0x00, // option: Router Alert
        ];
        p.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        p
    }

    /// A middle fragment: More Fragments set and a non-zero offset.
    fn ipv4_fragment_packet() -> Vec<u8> {
        // flags/offset word = MF (0x2000) | offset 185
        let word: u16 = 0x2000 | 185;
        let mut p = vec![
            0x45, 0x00, 0x00, 0x1C, 0xAB, 0xCD, // identification
        ];
        p.extend_from_slice(&word.to_be_bytes());
        p.extend_from_slice(&[
            0x10, // TTL 16
            0x84, // protocol 132 (SCTP)
            0x00, 0x00, //
            172, 16, 0, 1, //
            172, 16, 0, 2, //
        ]);
        p.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        p
    }

    /// IPv6 with traffic class 0x12, flow label 0x34567, next header 132 (SCTP).
    fn ipv6_packet() -> Vec<u8> {
        let mut p = vec![
            0x61, // version 6, traffic class high nibble
            0x23, // traffic class low nibble, flow label high nibble
            0x45, 0x67, // flow label
            0x00, 0x08, // payload length 8
            0x84, // next header 132 (SCTP)
            0x39, // hop limit 57
        ];
        p.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets());
        p.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).octets());
        p.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        p
    }

    // ========================================================================
    // Decoder
    // ========================================================================

    #[test]
    fn ipv4_header_decodes_field_by_field() {
        let packet = decode_ip_packet(&ipv4_gre_packet()).expect("well-formed IPv4 packet");

        let IpHeader::V4(h) = packet.header else {
            panic!("decoded an IPv4 packet as something else");
        };

        assert_eq!(h.ihl, 5);
        assert_eq!(h.header_length, 20);
        assert_eq!(h.dscp, 46, "DSCP is the top six bits of byte 1");
        assert_eq!(h.ecn, 1, "ECN is the bottom two bits of byte 1");
        assert_eq!(h.total_length, 28);
        assert_eq!(h.identification, 0x1234);
        assert!(!h.reserved_flag);
        assert!(h.dont_fragment);
        assert!(!h.more_fragments);
        assert_eq!(h.fragment_offset, 0);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.protocol, 47);
        assert_eq!(h.source, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(h.destination, Ipv4Addr::new(192, 0, 2, 10));
        assert!(!h.options_present);
        assert_eq!(h.options_length, 0);

        assert_eq!(
            packet.payload,
            vec![0x00, 0x00, 0x65, 0x58, 0xDE, 0xAD, 0xBE, 0xEF],
            "the payload is everything after the header, verbatim and unparsed"
        );
        assert!(!packet.payload_incomplete);
    }

    #[test]
    fn ipv4_options_are_reported_and_excluded_from_the_payload() {
        let packet = decode_ip_packet(&ipv4_with_options_packet()).expect("IPv4 with options");

        let IpHeader::V4(h) = packet.header else {
            panic!("not IPv4");
        };
        assert_eq!(h.ihl, 6);
        assert_eq!(h.header_length, 24);
        assert!(h.options_present);
        assert_eq!(h.options_length, 4);
        assert_eq!(h.protocol, 50, "ESP");

        assert_eq!(
            packet.payload,
            vec![0xCA, 0xFE, 0xBA, 0xBE],
            "the option bytes belong to the header, not the payload — an off-by-one here \
             would hand the model four bytes of IP option and call them protocol data"
        );
    }

    #[test]
    fn a_fragmented_packet_reports_its_offset_and_more_fragments_flag() {
        let packet = decode_ip_packet(&ipv4_fragment_packet()).expect("fragment");

        let IpHeader::V4(h) = packet.header else {
            panic!("not IPv4");
        };
        assert!(h.more_fragments, "MF must be read from bit 2 of the flags");
        assert!(!h.dont_fragment);
        assert_eq!(
            h.fragment_offset, 185,
            "the offset is the low 13 bits, in 8-byte units, and must not pick up the flags"
        );
        assert_eq!(h.identification, 0xABCD);
        assert_eq!(h.protocol, 132, "SCTP");
    }

    #[test]
    fn ipv6_header_decodes_field_by_field() {
        let packet = decode_ip_packet(&ipv6_packet()).expect("well-formed IPv6 packet");

        let IpHeader::V6(h) = packet.header else {
            panic!("decoded an IPv6 packet as something else");
        };

        assert_eq!(
            h.traffic_class, 0x12,
            "traffic class straddles bytes 0 and 1"
        );
        assert_eq!(
            h.flow_label, 0x34567,
            "the flow label is 20 bits across bytes 1..4"
        );
        assert_eq!(h.payload_length, 8);
        assert_eq!(h.next_header, 132);
        assert_eq!(h.hop_limit, 57);
        assert_eq!(h.source, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            h.destination,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)
        );

        assert_eq!(
            packet.payload,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert!(!packet.payload_incomplete);
    }

    /// Every one of these must come back as an `Err`. A panic here would take down the
    /// receive loop — this decoder is the only thing between a stranger's bytes and the
    /// server task, and it is reached before anything else looks at the buffer.
    #[test]
    fn malformed_and_truncated_packets_are_refused_not_panicked() {
        let cases: Vec<(&str, Vec<u8>, IpDecodeError)> = vec![
            (
                "empty buffer",
                vec![],
                IpDecodeError::TooShort {
                    got: 0,
                    need: 20,
                    version: 0,
                },
            ),
            (
                "two bytes of an IPv4 header",
                vec![0x45, 0x00],
                IpDecodeError::TooShort {
                    got: 2,
                    need: 20,
                    version: 4,
                },
            ),
            (
                "nineteen bytes — one short of the fixed header",
                vec![0x45; 19],
                IpDecodeError::TooShort {
                    got: 19,
                    need: 20,
                    version: 4,
                },
            ),
            (
                "IHL of 4 words, below the legal minimum",
                vec![0x44; 20],
                IpDecodeError::IhlTooSmall(4),
            ),
            (
                "IHL of 6 words but only 20 bytes captured",
                vec![0x46; 20],
                IpDecodeError::HeaderTruncated {
                    ihl_bytes: 24,
                    got: 20,
                },
            ),
            (
                "version nibble 5",
                vec![0x55; 40],
                IpDecodeError::UnsupportedVersion(5),
            ),
            (
                "version nibble 0",
                vec![0x00; 40],
                IpDecodeError::UnsupportedVersion(0),
            ),
            (
                "thirty-nine bytes of IPv6 header",
                {
                    let mut v = ipv6_packet();
                    v.truncate(39);
                    v
                },
                IpDecodeError::TooShort {
                    got: 39,
                    need: 40,
                    version: 6,
                },
            ),
        ];

        for (name, bytes, expected) in cases {
            match decode_ip_packet(&bytes) {
                Ok(p) => panic!("{name}: expected a refusal, decoded {p:?}"),
                Err(e) => assert_eq!(e, expected, "{name}: wrong refusal"),
            }
        }
    }

    /// A header that promises more payload than arrived must not read past the buffer, and
    /// must say so rather than handing over a silently short payload.
    #[test]
    fn a_packet_cut_short_is_reported_rather_than_over_read() {
        // total_length says 1200, only 28 bytes are here.
        let mut bytes = ipv4_gre_packet();
        bytes[2..4].copy_from_slice(&1200u16.to_be_bytes());

        let packet = decode_ip_packet(&bytes).expect("the header itself is intact");
        assert!(
            packet.payload_incomplete,
            "the model must be told the payload it is looking at is not the whole packet"
        );
        assert_eq!(packet.payload.len(), 8, "only what was actually captured");

        // And the opposite lie: total_length shorter than the header.
        let mut bytes = ipv4_gre_packet();
        bytes[2..4].copy_from_slice(&4u16.to_be_bytes());
        let packet = decode_ip_packet(&bytes).expect("header intact");
        assert_eq!(
            packet.payload.len(),
            8,
            "an impossible total_length falls back to what was captured rather than \
             producing a negative-length slice"
        );
    }

    /// The generic claim, asserted directly: nothing about decoding depends on which protocol
    /// number the packet carries. If someone ever adds `match protocol { 47 => .. }` this is
    /// the test that should fail.
    #[test]
    fn decoding_does_not_depend_on_the_protocol_number() {
        let baseline = decode_ip_packet(&ipv4_gre_packet()).expect("baseline");
        let IpHeader::V4(base) = baseline.header.clone() else {
            panic!("not IPv4");
        };

        for number in [0u8, 1, 41, 47, 50, 51, 89, 112, 132, 200, 253, 255] {
            let mut bytes = ipv4_gre_packet();
            bytes[9] = number;
            let packet = decode_ip_packet(&bytes).expect("still a valid IPv4 header");
            let IpHeader::V4(h) = packet.header else {
                panic!("not IPv4");
            };

            assert_eq!(h.protocol, number);
            assert_eq!(
                packet.payload, baseline.payload,
                "protocol {number}: the payload must be sliced identically — no protocol \
                 number may be given special framing here"
            );
            // Everything else about the header is untouched.
            assert_eq!(
                (h.ihl, h.ttl, h.total_length),
                (base.ihl, base.ttl, base.total_length)
            );
            assert_eq!((h.source, h.destination), (base.source, base.destination));
        }
    }

    #[test]
    fn iana_names_are_reported_where_known_and_absent_where_not() {
        assert_eq!(ip_protocol_name(47), Some("GRE"));
        assert_eq!(ip_protocol_name(50), Some("ESP"));
        assert_eq!(ip_protocol_name(51), Some("AH"));
        assert_eq!(ip_protocol_name(132), Some("SCTP"));
        assert_eq!(ip_protocol_name(6), Some("TCP"));
        assert_eq!(ip_protocol_name(17), Some("UDP"));
        assert_eq!(
            ip_protocol_name(200),
            None,
            "an unassigned number is reported as a number, not guessed at"
        );
    }

    // ========================================================================
    // Startup parameters
    // ========================================================================

    fn params(value: serde_json::Value) -> Result<StartupParams, String> {
        StartupParams::new(value, RawIpProtocol::new().get_startup_parameters())
            .map_err(|e| e.to_string())
    }

    fn config_from(value: serde_json::Value) -> Result<RawIpConfig, String> {
        let p = params(value)?;
        RawIpConfig::from_startup_params(Some(&p)).map_err(|e| format!("{e:#}"))
    }

    #[test]
    fn protocol_number_is_required_and_range_checked() {
        assert!(
            RawIpConfig::from_startup_params(None)
                .unwrap_err()
                .to_string()
                .contains("protocol_number"),
            "a generic protocol has no default number to fall back on"
        );

        let err = config_from(json!({})).unwrap_err();
        assert!(err.contains("protocol_number"), "{err}");

        for bad in [-1i64, 256, 100_000] {
            let err = config_from(json!({ "protocol_number": bad })).unwrap_err();
            assert!(err.contains("0..=255"), "{bad}: {err}");
        }

        assert_eq!(
            config_from(json!({ "protocol_number": 47 })).unwrap(),
            RawIpConfig {
                protocol_number: 47,
                ip_version: IpVersion::V4,
                transport: RawIpTransport::Raw,
            },
            "the defaults are IPv4 over a real raw socket"
        );
        assert_eq!(
            config_from(json!({ "protocol_number": 0 }))
                .unwrap()
                .protocol_number,
            0,
            "0 (HOPOPT) is a legal protocol number"
        );
        assert_eq!(
            config_from(json!({ "protocol_number": 255 }))
                .unwrap()
                .protocol_number,
            255
        );
    }

    #[test]
    fn tcp_and_udp_are_refused_and_point_at_the_real_protocols() {
        let err = config_from(json!({ "protocol_number": 6 })).unwrap_err();
        assert!(err.contains("TCP"), "{err}");
        assert!(
            err.contains("'tcp'"),
            "the refusal must name the protocol to use instead: {err}"
        );

        let err = config_from(json!({ "protocol_number": 17 })).unwrap_err();
        assert!(err.contains("UDP"), "{err}");
        assert!(err.contains("'udp'"), "{err}");
    }

    #[test]
    fn ip_version_and_transport_are_parsed_and_validated() {
        assert_eq!(
            config_from(json!({ "protocol_number": 41, "ip_version": "ipv6" }))
                .unwrap()
                .ip_version,
            IpVersion::V6
        );
        assert_eq!(
            config_from(json!({ "protocol_number": 41, "ip_version": "IPv4" }))
                .unwrap()
                .ip_version,
            IpVersion::V4
        );
        assert!(
            config_from(json!({ "protocol_number": 41, "ip_version": "ipv7" }))
                .unwrap_err()
                .contains("ipv4")
        );

        assert_eq!(
            config_from(json!({ "protocol_number": 47, "transport": "udp" }))
                .unwrap()
                .transport,
            RawIpTransport::Udp
        );
        assert!(
            config_from(json!({ "protocol_number": 47, "transport": "quic" }))
                .unwrap_err()
                .contains("transport must be")
        );
    }

    #[test]
    fn an_undeclared_startup_parameter_is_refused_by_name() {
        let err = params(json!({ "protocol_number": 47, "gre_key": 1 })).unwrap_err();
        assert!(err.contains("gre_key"), "{err}");
        assert!(
            err.contains("protocol_number"),
            "the refusal lists what is allowed: {err}"
        );
    }

    // ========================================================================
    // The executor — the half that must actually decode
    // ========================================================================

    fn payload_hex_of(result: &ActionResult) -> String {
        match result {
            ActionResult::Custom { name, data } => {
                assert_eq!(name, "rawip_packet");
                data["payload_hex"].as_str().unwrap().to_string()
            }
            other => panic!("expected a rawip_packet result, got {other:?}"),
        }
    }

    #[test]
    fn the_executor_actually_decodes_the_encoding_it_documents() {
        let p = RawIpProtocol::new();

        // hex in, those bytes out.
        let r = p
            .execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "192.0.2.1",
                "payload": "48656c6c6f",
                "encoding": "hex"
            }))
            .expect("hex payload");
        assert_eq!(
            payload_hex_of(&r),
            "48656c6c6f",
            "declared hex must become the five bytes of \"Hello\", not the ten ASCII \
             characters of the hex string — that is the send_tcp_data defect"
        );

        // utf8 in, the text's own bytes out.
        let r = p
            .execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "192.0.2.1",
                "payload": "48656c6c6f",
                "encoding": "utf8"
            }))
            .expect("utf8 payload");
        assert_eq!(
            payload_hex_of(&r),
            hex::encode("48656c6c6f"),
            "the very same string means something different under utf8, which is exactly \
             why the encoding is never sniffed"
        );

        // utf8 is the default.
        let r = p
            .execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "192.0.2.1",
                "payload": "hi"
            }))
            .expect("default encoding");
        assert_eq!(payload_hex_of(&r), "6869");
    }

    #[test]
    fn the_executor_refuses_what_it_cannot_honour() {
        let p = RawIpProtocol::new();

        let err = p
            .execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "192.0.2.1",
                "payload": "aGVsbG8=",
                "encoding": "base64"
            }))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("base64"),
            "an unsupported encoding must be refused, never silently treated as text: {err}"
        );

        let err = format!(
            "{:#}",
            p.execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "192.0.2.1",
                "payload": "not hex at all",
                "encoding": "hex"
            }))
            .unwrap_err()
        );
        assert!(err.contains("hex"), "{err}");

        let err = format!(
            "{:#}",
            p.execute_action(json!({
                "type": "send_rawip_packet",
                "destination": "not-an-address",
                "payload": "hi"
            }))
            .unwrap_err()
        );
        assert!(err.contains("destination"), "{err}");

        assert!(p
            .execute_action(json!({ "type": "send_gre_packet" }))
            .is_err());
    }

    #[test]
    fn every_advertised_action_runs_its_own_declared_example() {
        let p = RawIpProtocol::new();
        for action in p.get_sync_actions() {
            p.execute_action(action.example.clone())
                .unwrap_or_else(|e| {
                    panic!(
                        "action '{}' advertises an example its own executor refuses: {e:#}",
                        action.name
                    )
                });
        }
        assert!(matches!(
            p.execute_action(json!({ "type": "no_response" })).unwrap(),
            ActionResult::NoAction
        ));
    }

    #[test]
    fn the_event_offers_the_model_the_protocols_actions() {
        let p = RawIpProtocol::new();
        let events = p.get_event_types();
        assert_eq!(events.len(), 1);
        let names = events[0].action_names();
        assert!(
            names.contains(&"send_rawip_packet".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"no_response".to_string()), "{names:?}");
    }

    // ========================================================================
    // The full path, over the unprivileged UDP test transport
    // ========================================================================

    /// Start a rawip server on the UDP test transport and return its bound port.
    async fn start_udp_transport(
        state: &AppState,
        llm_url: &str,
        protocol_number: i64,
        instruction: &str,
    ) -> E2EResult<u16> {
        let server_id = state
            .add_server(ServerInstance::new(
                ServerId::new(0),
                0,
                "rawip".to_string(),
                instruction.to_string(),
            ))
            .await;

        let startup_params = StartupParams::new(
            json!({ "protocol_number": protocol_number, "transport": "udp" }),
            RawIpProtocol::new().get_startup_parameters(),
        )?;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        // Drain the status stream so nothing backs up in the unbounded channel.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let addr = RawIpServer::spawn_with_llm_actions(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            OllamaClient::new(llm_url.to_string()),
            Arc::new(state.clone()),
            tx,
            server_id,
            Some(startup_params),
        )
        .await?;

        Ok(addr.port())
    }

    /// Send one IP packet as a datagram and wait for whatever comes back, if anything.
    async fn exchange(port: u16, packet: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client
            .connect(("127.0.0.1", port))
            .await
            .expect("connect to the rawip test transport");
        client.send(packet).await.expect("send packet");

        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(wait, client.recv(&mut buf)).await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    /// The end-to-end claim, and the hex round trip inside it: a payload the model sends as
    /// `encoding: "hex"` must arrive as those **bytes**, not as that ASCII text.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_full_path_runs_and_a_hex_payload_arrives_as_bytes() -> E2EResult<()> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("rawip_packet_received")
                .and_event_data_contains("protocol", "47")
                .respond_with_actions(json!([{
                    "type": "send_rawip_packet",
                    "destination": "192.0.2.1",
                    "payload": "48656c6c6f",
                    "encoding": "hex"
                }]))
                .expect_calls(1)
                .build(),
        )
        .await?;

        let state = AppState::new_with_options(false, mock.base_url());
        state
            .set_llm_client(OllamaClient::new(mock.base_url()))
            .await;

        let port = start_udp_transport(
            &state,
            &mock.base_url(),
            47,
            "Answer every GRE packet with the bytes I tell you to.",
        )
        .await?;

        let reply = exchange(port, &ipv4_gre_packet(), Duration::from_secs(30)).await;

        mock.wait_for_expectations(30).await;
        mock.verify_calls().await?;

        let reply = reply.expect("the model asked for a packet, so one must have gone out");
        assert_eq!(
            reply,
            b"Hello".to_vec(),
            "a hex payload must reach the wire as the bytes it encodes. Receiving the ten \
             ASCII characters \"48656c6c6f\" instead means the executor documented hex and \
             never decoded it — the send_tcp_data defect, reintroduced."
        );

        // And the model was shown a decoded header, not an undifferentiated blob.
        let calls = mock.recorded_calls().await;
        let event = &calls
            .iter()
            .find(|c| c.context.event_type.as_deref() == Some("rawip_packet_received"))
            .expect("the packet event reached the model")
            .context
            .event_data;

        assert_eq!(event["ip_version"], 4);
        assert_eq!(event["source"], "192.0.2.1");
        assert_eq!(event["destination"], "192.0.2.10");
        assert_eq!(event["ttl"], 64);
        assert_eq!(event["protocol"], 47);
        assert_eq!(
            event["protocol_name"], "GRE",
            "the IANA name is a lookup, and it is what turns 47 into something the model \
             can reason about"
        );
        assert_eq!(event["identification"], 0x1234);
        assert_eq!(event["dscp"], 46);
        assert_eq!(event["flags"]["dont_fragment"], true);
        assert_eq!(event["payload_length"], 8);
        assert_eq!(
            event["payload_encoding"], "hex",
            "a binary payload is shown as hex, and the event says so rather than leaving the \
             model to guess"
        );
        assert_eq!(event["payload"], "00006558deadbeef");
        assert_eq!(event["listening_protocol_number"], 47);

        Ok(())
    }

    /// `no_response` is a decision, and it puts nothing on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_response_puts_nothing_on_the_wire() -> E2EResult<()> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("rawip_packet_received")
                .respond_with_actions(json!([{ "type": "no_response" }]))
                .expect_calls(1)
                .build(),
        )
        .await?;

        let state = AppState::new_with_options(false, mock.base_url());
        state
            .set_llm_client(OllamaClient::new(mock.base_url()))
            .await;

        let port = start_udp_transport(
            &state,
            &mock.base_url(),
            50,
            "Observe ESP packets. Do not answer them.",
        )
        .await?;

        let reply = exchange(port, &ipv4_gre_packet(), Duration::from_secs(8)).await;

        mock.wait_for_expectations(30).await;
        mock.verify_calls().await?;

        assert!(
            reply.is_none(),
            "no_response must emit nothing, got {reply:?}"
        );
        Ok(())
    }

    /// **The silence contract.** When the model cannot be reached, netget must emit nothing.
    ///
    /// This is not a compromise reached for lack of a better option: a generic IP protocol has
    /// no error frame, because netget deliberately does not implement the protocol above IP.
    /// Any bytes emitted here would be a guess at a format nobody has defined, and a guess a
    /// peer parses is worse than a packet it never receives. In particular no `WireFailure`
    /// text may reach the wire — there is no wire format to carry it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_llm_failure_puts_nothing_on_the_wire() -> E2EResult<()> {
        // Port 1 on loopback: nothing listens, so every LLM call fails immediately.
        let dead = "http://127.0.0.1:1".to_string();
        let state = AppState::new_with_options(false, dead.clone());
        state.set_llm_client(OllamaClient::new(dead.clone())).await;

        let port = start_udp_transport(
            &state,
            &dead,
            47,
            "Answer every packet. (The backend is unreachable, so this cannot happen.)",
        )
        .await?;

        let reply = exchange(port, &ipv4_gre_packet(), Duration::from_secs(15)).await;

        assert!(
            reply.is_none(),
            "an LLM failure must leave the wire empty; instead the peer received {:?} — if \
             this is a WireFailure category string, it has leaked into a protocol that has no \
             format to put it in",
            reply.map(|b| String::from_utf8_lossy(&b).to_string())
        );
        Ok(())
    }

    /// A datagram that is not an IP packet at all is dropped, and the server keeps running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_malformed_packet_is_dropped_without_reaching_the_model() -> E2EResult<()> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_any()
                .respond_with_actions(json!([{ "type": "no_response" }]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        let state = AppState::new_with_options(false, mock.base_url());
        state
            .set_llm_client(OllamaClient::new(mock.base_url()))
            .await;

        let port = start_udp_transport(
            &state,
            &mock.base_url(),
            47,
            "Answer every packet you are given.",
        )
        .await?;

        // Version nibble 7: not an IP packet, and the event's contract is decoded fields.
        let reply = exchange(port, &[0x77; 32], Duration::from_secs(6)).await;
        assert!(reply.is_none(), "nothing should be emitted for garbage");
        assert_eq!(
            mock.call_count().await,
            0,
            "an undecodable packet must not be handed to the model as an event whose header \
             fields would then be fabricated"
        );

        // The server survived it: a well-formed packet still gets through the decoder.
        assert!(decode_ip_packet(&ipv4_gre_packet()).is_ok());

        mock.verify_calls().await?;
        Ok(())
    }
}
