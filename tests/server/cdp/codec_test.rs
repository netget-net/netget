//! CDP frame codec tests — literal specification bytes and real captures.
//!
//! The raw 802.3 transport cannot run here (it needs packet-capture privilege), so the codec is
//! where all the evidence has to come from. Two kinds of assertion, and the distinction matters
//! for what the protocol's maturity rating is allowed to claim:
//!
//! 1. **Encode against literal bytes.** A complete advertisement is built through the public API
//!    and compared byte for byte with a frame written out by hand from the specification —
//!    header, every TLV, and the checksum.
//! 2. **Decode a real capture.** Three real CDP packets (a Catalyst 2950, a Cisco 7960 IP phone,
//!    and one carrying the CDP power TLVs) taken verbatim from **scapy's** CDP regression
//!    vectors, plus one complete 802.3 frame. Scapy is an independent implementation, so the
//!    field values and the checksum verdict asserted here are not this codec marking its own
//!    homework — which is exactly the circularity root `CLAUDE.md` names as a failure mode.
//!
//! The checksum gets its own attention because it is the field CDP implementations get wrong.
//! Cisco does not follow RFC 1071 for an odd-length payload, and every odd-length assertion here
//! also asserts that the RFC-1071 answer is *different*, so "simplifying" the padding away
//! cannot pass.

#[cfg(all(unix, feature = "libpcap"))]
mod tests {
    use netget::server::cdp::codec::{
        self, capability_bits, capability_names, decode_frame, decode_payload, encode_frame,
        encode_payload, CdpAdvertisement, Duplex, CDP_MULTICAST_MAC, LLC_SNAP_HEADER,
    };
    use serde_json::json;

    // =========================================================================================
    // Real captures (scapy test/contrib/cdp.uts, verbatim)
    // =========================================================================================

    /// CDPv2 from a Catalyst 2950 running IOS 12.1(22)EA14. Even length; its checksum is valid.
    const CAPTURE_CATALYST_2950: &str = concat!(
        "02b48cfa0001000c6d7973776974636800020011000000010101cc0004c0a800fd000300134661737445746865726e65",
        "74302f31000400080000002800050114436973636f20496e7465726e6574776f726b204f7065726174696e6720537973",
        "74656d20536f667477617265200a494f532028746d2920433239353020536f667477617265202843323935302d49364b",
        "324c3251342d4d292c2056657273696f6e2031322e3128323229454131342c2052454c4541534520534f465457415245",
        "2028666331290a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74",
        "656368737570706f72740a436f707972696768742028632920313938362d3230313020627920636973636f2053797374",
        "656d732c20496e632e0a436f6d70696c6564205475652032362d4f63742d31302031303a3335206279206e6275727261",
        "00060015636973636f2057532d43323935302d31320008002400000c011200000000ffffffff010221ff000000000000",
        "000bbe189a40ff00000009000c4d59444f4d41494e000a00060001000b000501000e000701000a001200050000130005",
        "0000160011000000010101cc0004c0a800fd",
    );

    /// CDPv2 from a Cisco IP Phone 7960. Its checksum field disagrees with the packet's own
    /// contents — scapy's rebuild test records the same disagreement (it rewrites the field to
    /// 0xf3f1), so this is a real-world example of a device that ships a bad checksum, and a
    /// useful proof that `checksum_valid()` is doing work rather than always returning true.
    const CAPTURE_IP_PHONE_7960: &str = concat!(
        "02b4d7db0001001353495030303131323233333434353500020011000000010101cc0004c0a801210003000a506f7274",
        "2031000400080000001000050010503030332d30382d322d303000060017436973636f2049502050686f6e6520373936",
        "30000f000820020001000b00050100100006189c",
    );

    /// CDPv2 carrying the Power Requested / Power Available TLVs, neither of which this codec
    /// models. It must survive them and report them as other TLVs, not choke.
    const CAPTURE_POWER_TLVS: &str = concat!(
        "02b439fa00010009536361707900020011000000010101cc00047f000001001000060010001900180000000000000001",
        "000000020000000300000004001a001400000000000000050000000600000007",
    );

    /// A complete 802.3 frame: destination 01:00:0c:cc:cc:cc, LLC/SNAP, then a router's CDPv2.
    ///
    /// **Framing and TLV evidence only.** Unlike the three payload captures above, this vector
    /// is assembled by hand inside scapy's suite rather than lifted from a capture: its 802.3
    /// length field says 384 for a 114-byte body, and its checksum field does not match its own
    /// contents. Both facts are asserted below so nobody later mistakes it for a valid packet —
    /// it is used here to prove the header parser accepts a real-shaped frame, nothing more.
    const CAPTURE_FRAME_ROUTER: &str = concat!(
        "01000ccccccc1122334455660180aaaa0300000c200002b475560001000a526f75746572000500040006000400020011",
        "000000020101cc0004c0a80165000300184769676162697445746865726e6574302f302f310004000800000041000700",
        "09140000001800090004000b00050100160011000000010101cc0004c0a80165",
    );

    fn bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("test vector is valid hex")
    }

    // =========================================================================================
    // 1. Encode against literal specification bytes
    // =========================================================================================

    /// The reference advertisement, used by the byte-for-byte tests below.
    fn reference_action() -> serde_json::Value {
        json!({
            "type": "send_cdp_advertisement",
            "device_id": "SW-CORE-01",
            "port_id": "GigabitEthernet0/1",
            "platform": "cisco WS-C2960-24TT-L",
            "software_version": "Cisco IOS Software, Version 15.0(2)SE11",
            "capabilities": ["switch", "igmp"],
            "native_vlan": 1,
            "duplex": "full",
            "addresses": ["192.168.1.1"],
            "management_addresses": ["192.168.1.1"],
            "ttl": 180,
            "version": 2
        })
    }

    /// Every byte of the payload, written out from the specification rather than produced by
    /// this codec: version 2, TTL 180, checksum, then TLVs in ascending type order with each
    /// length counting its own 4-byte header.
    ///
    /// The checksum `28a1` is computed by an independent transcription of Wireshark's
    /// `packet-cdp.c` (this payload is 161 bytes, so it goes through Cisco's odd-length branch).
    const EXPECTED_PAYLOAD: &str = concat!(
        "02",   // version 2
        "b4",   // TTL 180
        "28a1", // checksum
        "0001000e",
        "53572d434f52452d3031", // Device ID   "SW-CORE-01"
        "00020011",
        "00000001",
        "0101cc",
        "0004",
        "c0a80101", // Addresses  192.168.1.1
        "00030016",
        "4769676162697445746865726e6574302f31", // Port ID     "GigabitEthernet0/1"
        "00040008",
        "00000028", // Capabilities switch|igmp
        "0005002b",
        "436973636f20494f5320536f6674776172652c2056657273696f6e2031352e30283229534531",
        "31", // Software version
        "00060019",
        "636973636f2057532d43323936302d323454542d4c", // Platform
        "000a0006",
        "0001", // Native VLAN 1
        "000b0005",
        "01", // Duplex full
        "00160011",
        "00000001",
        "0101cc",
        "0004",
        "c0a80101", // Management address
    );

    #[test]
    fn encodes_a_full_advertisement_byte_for_byte() {
        let ad = CdpAdvertisement::from_action(&reference_action())
            .expect("the reference action is valid");
        let payload = encode_payload(&ad).expect("reference advertisement encodes");

        let expected = bytes(EXPECTED_PAYLOAD);
        assert_eq!(
            hex::encode(&payload),
            hex::encode(&expected),
            "encoded CDP payload does not match the literal specification bytes"
        );

        // Guard the properties the literal is asserting, so a future edit to the literal that
        // breaks one of them is caught rather than blessed.
        assert_eq!(payload.len(), 161, "reference payload length");
        assert_eq!(payload[0], 2, "CDP version");
        assert_eq!(payload[1], 180, "CDP TTL");
        assert_eq!(
            u16::from_be_bytes([payload[2], payload[3]]),
            0x28a1,
            "checksum literal"
        );
    }

    #[test]
    fn encodes_the_802_3_and_llc_snap_header_byte_for_byte() {
        let ad =
            CdpAdvertisement::from_action(&reference_action()).expect("reference action is valid");
        let payload = encode_payload(&ad).expect("encodes");
        let src = [0x02, 0x00, 0x0c, 0xcc, 0xcc, 0x01];
        let frame = encode_frame(src, &payload).expect("frames");

        assert_eq!(
            &frame[0..6],
            &CDP_MULTICAST_MAC,
            "destination must be the CDP group"
        );
        assert_eq!(&frame[6..12], &src, "source MAC");
        assert_eq!(
            u16::from_be_bytes([frame[12], frame[13]]),
            (8 + payload.len()) as u16,
            "802.3 length field covers LLC + SNAP + payload, and is a length not an EtherType"
        );
        assert_eq!(
            &frame[14..22],
            &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00],
            "LLC DSAP/SSAP 0xAA, control 0x03, SNAP OUI 00:00:0c, protocol 0x2000"
        );
        assert_eq!(&frame[14..22], &LLC_SNAP_HEADER);
        assert_eq!(
            &frame[22..],
            &payload[..],
            "payload follows the SNAP header"
        );
        assert_eq!(frame.len(), 183);
    }

    /// The header this codec emits is the header a real capture carries.
    #[test]
    fn emitted_llc_snap_header_matches_a_real_capture() {
        let captured = bytes(CAPTURE_FRAME_ROUTER);
        let ours = encode_frame(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            &[0x02, 0xb4, 0x00, 0x00],
        )
        .expect("frames");
        assert_eq!(
            &ours[0..6],
            &captured[0..6],
            "destination MAC matches the captured frame"
        );
        assert_eq!(
            &ours[14..22],
            &captured[14..22],
            "LLC/SNAP header matches the captured frame"
        );
    }

    // =========================================================================================
    // 2. Checksum
    // =========================================================================================

    /// A CDP payload validates when recomputing over it reproduces the field it carries.
    #[test]
    fn reproduces_the_checksum_of_real_captures() {
        for (name, hex_str, expected) in [
            ("Catalyst 2950", CAPTURE_CATALYST_2950, 0x8cfa_u16),
            ("power TLVs", CAPTURE_POWER_TLVS, 0x39fa),
        ] {
            let payload = bytes(hex_str);
            let decoded = decode_payload(&payload).expect("real capture decodes");
            assert_eq!(
                decoded.declared_checksum, expected,
                "{name}: capture carries checksum 0x{expected:04x}"
            );
            assert_eq!(
                decoded.computed_checksum, expected,
                "{name}: our checksum must reproduce the captured one"
            );
            assert!(decoded.checksum_valid(), "{name}: checksum must verify");
        }
    }

    /// The 7960 phone's capture carries a checksum that disagrees with its own contents. Scapy
    /// computes 0xf3f1 for the same bytes; so must we, and `checksum_valid()` must say no.
    #[test]
    fn rejects_the_bad_checksum_a_real_phone_shipped() {
        let payload = bytes(CAPTURE_IP_PHONE_7960);
        let decoded = decode_payload(&payload).expect("decodes");
        assert_eq!(decoded.declared_checksum, 0xd7db, "as captured");
        assert_eq!(
            decoded.computed_checksum, 0xf3f1,
            "the value scapy independently computes for these bytes"
        );
        assert!(
            !decoded.checksum_valid(),
            "checksum_valid() must be capable of returning false"
        );
    }

    /// Cisco's odd-length padding, and proof that RFC 1071's padding would give a different
    /// answer in each case.
    ///
    /// For an odd payload the last octet goes in the **low** half of the final big-endian word
    /// (RFC 1071 would put it in the high half), and when that octet has its top bit set both
    /// halves are decremented to compensate for Cisco's own off-by-one. Expected values are from
    /// an independent transcription of Wireshark's `packet-cdp.c`.
    #[test]
    fn implements_ciscos_odd_length_checksum_padding() {
        // Last byte < 0x80.
        let low = [
            0x02, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x61, 0x62, 0x63,
        ];
        assert_eq!(codec::checksum(&low), 0x9b7e, "odd length, last byte 0x63");
        assert_ne!(
            codec::checksum(&low),
            0x38e1,
            "0x38e1 is the RFC 1071 answer; CDP is not RFC 1071"
        );

        // Last byte >= 0x80 takes the compensated branch.
        let high = [
            0x02, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x61, 0x62, 0xa9,
        ];
        assert_eq!(codec::checksum(&high), 0x9c38, "odd length, last byte 0xa9");
        assert_ne!(codec::checksum(&high), 0xf2e0, "not the RFC 1071 answer");

        // Exactly 0x80 is the one value where Wireshark and scapy disagree. Wireshark tests
        // `byte & 0x80`, so 0x80 takes the compensated branch (0xFF7F); scapy tests
        // `byte <= 0x80` and would produce 0x0080. This codec follows Wireshark, because
        // Wireshark's reading is the one that treats the octet as signed and because Wireshark
        // is what an operator will check our frames with.
        let boundary = [
            0x02, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x61, 0x62, 0x80,
        ];
        assert_eq!(
            codec::checksum(&boundary),
            0x9c61,
            "odd length, last byte 0x80"
        );
        // The other two readings, so the choice is pinned rather than merely stated. All three
        // were recomputed by hand from the prose — RFC 1071's own text, Wireshark's
        // "Compensate off-by-one error" comment, scapy's `_check_len` — and not by running this
        // codec, which would make the assertion circular.
        assert_ne!(
            codec::checksum(&boundary),
            0x1be1,
            "0x1be1 is the RFC 1071 answer; CDP is not RFC 1071 even at this boundary"
        );
        assert_ne!(
            codec::checksum(&boundary),
            0x9b61,
            "0x9b61 is scapy's answer for this payload. It is the ONLY input on which scapy and \
             Wireshark disagree, so it is the only place a silent switch to scapy's `last <= \
             0x80` test would be invisible — which is exactly why it has to be asserted here."
        );

        // An even-length payload is the plain IP checksum, so the two agree.
        let even = [
            0x02, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x61, 0x62, 0x63, 0x64,
        ];
        assert_eq!(codec::checksum(&even), 0x387c, "even length");
    }

    #[test]
    fn a_flipped_byte_changes_the_checksum() {
        let mut payload = bytes(CAPTURE_CATALYST_2950);
        let before = decode_payload(&payload).unwrap().computed_checksum;
        payload[10] ^= 0x01;
        let after = decode_payload(&payload).unwrap().computed_checksum;
        assert_ne!(before, after, "the checksum must depend on the payload");
    }

    // =========================================================================================
    // 3. Decode real captures
    // =========================================================================================

    #[test]
    fn decodes_a_real_catalyst_2950_advertisement() {
        let decoded = decode_payload(&bytes(CAPTURE_CATALYST_2950)).expect("decodes");
        let ad = &decoded.advertisement;

        assert_eq!(ad.version, 2);
        assert_eq!(ad.ttl, 180);
        assert_eq!(ad.device_id.as_deref(), Some("myswitch"));
        assert_eq!(ad.port_id.as_deref(), Some("FastEthernet0/1"));
        assert_eq!(ad.platform.as_deref(), Some("cisco WS-C2950-12"));
        assert!(
            ad.software_version
                .as_deref()
                .unwrap_or_default()
                .starts_with("Cisco Internetwork Operating System Software"),
            "software version banner"
        );
        assert!(
            ad.software_version
                .as_deref()
                .unwrap_or_default()
                .contains("Version 12.1(22)EA14"),
            "the IOS version a recon tool would report"
        );
        assert_eq!(ad.capabilities, Some(0x28));
        assert_eq!(capability_names(0x28), vec!["switch", "igmp"]);
        assert_eq!(ad.native_vlan, Some(1));
        assert_eq!(ad.duplex, Some(Duplex::Full));

        assert_eq!(ad.addresses.len(), 1);
        assert_eq!(ad.addresses[0].protocol, "ipv4");
        assert_eq!(ad.addresses[0].address, "192.168.0.253");
        assert_eq!(ad.management_addresses.len(), 1);
        assert_eq!(ad.management_addresses[0].address, "192.168.0.253");

        // TLVs this codec does not model must be reported, not dropped and not guessed at.
        let others: Vec<(u16, &str)> = ad
            .other_tlvs
            .iter()
            .map(|t| (t.type_code, t.name))
            .collect();
        assert!(
            others.contains(&(0x0008, "protocol_hello")),
            "other TLVs were {:?}",
            others
        );
        assert!(others.contains(&(0x0009, "vtp_management_domain")));
        assert!(others.contains(&(0x0012, "trust_bitmap")));
        assert!(others.contains(&(0x0013, "untrusted_port_cos")));
    }

    #[test]
    fn decodes_a_real_ip_phone_advertisement() {
        let decoded = decode_payload(&bytes(CAPTURE_IP_PHONE_7960)).expect("decodes");
        let ad = &decoded.advertisement;

        assert_eq!(ad.device_id.as_deref(), Some("SIP001122334455"));
        assert_eq!(ad.port_id.as_deref(), Some("Port 1"));
        assert_eq!(ad.platform.as_deref(), Some("Cisco IP Phone 7960"));
        assert_eq!(ad.software_version.as_deref(), Some("P003-08-2-00"));
        assert_eq!(ad.capabilities, Some(0x10));
        assert_eq!(capability_names(0x10), vec!["host"]);
        assert_eq!(ad.duplex, Some(Duplex::Full));
        assert_eq!(ad.addresses.len(), 1);
        assert_eq!(ad.addresses[0].address, "192.168.1.33");
        assert!(
            ad.native_vlan.is_none(),
            "this phone advertises no native VLAN"
        );
    }

    #[test]
    fn survives_tlvs_it_does_not_model() {
        let decoded = decode_payload(&bytes(CAPTURE_POWER_TLVS)).expect("decodes");
        let ad = &decoded.advertisement;
        assert_eq!(ad.device_id.as_deref(), Some("Scapy"));
        assert_eq!(ad.addresses[0].address, "127.0.0.1");
        let others: Vec<(u16, &str)> = ad
            .other_tlvs
            .iter()
            .map(|t| (t.type_code, t.name))
            .collect();
        assert!(
            others.contains(&(0x0019, "power_requested")),
            "{:?}",
            others
        );
        assert!(
            others.contains(&(0x001a, "power_available")),
            "{:?}",
            others
        );
    }

    #[test]
    fn decodes_a_complete_captured_frame() {
        let frame = bytes(CAPTURE_FRAME_ROUTER);
        let (header, payload) = decode_frame(&frame).expect("real frame decodes");

        assert_eq!(header.destination_mac, CDP_MULTICAST_MAC);
        assert_eq!(
            codec::mac_to_string(&header.source_mac),
            "11:22:33:44:55:66"
        );

        // The header parser must not enforce the 802.3 length field: a captured frame is padded
        // to the Ethernet minimum and may be cut by the snaplen, so requiring agreement would
        // reject real traffic. This vector declares 384 for a 114-byte body and still decodes.
        assert_eq!(header.declared_length, 0x0180);
        assert_ne!(
            header.declared_length as usize,
            frame.len() - 14,
            "this vector's length field is inconsistent, and decoding must tolerate that"
        );

        let decoded = decode_payload(payload).expect("payload decodes");
        assert!(
            !decoded.checksum_valid(),
            "this vector is hand-assembled, not captured: its checksum does not verify, which \
             is why it is framing evidence only"
        );
        let ad = decoded.advertisement;
        assert_eq!(ad.device_id.as_deref(), Some("Router"));
        assert_eq!(ad.port_id.as_deref(), Some("GigabitEthernet0/0/1"));
        assert_eq!(ad.capabilities, Some(0x41));
        assert_eq!(capability_names(0x41), vec!["router", "repeater"]);
        assert_eq!(ad.duplex, Some(Duplex::Full));
        assert_eq!(ad.addresses[0].address, "192.168.1.101");
        assert_eq!(ad.management_addresses[0].address, "192.168.1.101");
    }

    #[test]
    fn refuses_a_frame_that_is_not_cdp() {
        // Right destination, wrong SNAP protocol id (0x2001 rather than 0x2000).
        let mut frame = bytes(CAPTURE_FRAME_ROUTER);
        frame[21] = 0x01;
        let err = decode_frame(&frame).expect_err("must reject");
        assert!(
            err.to_string().contains("LLC/SNAP"),
            "error should name the header it rejected: {err}"
        );

        // Too short to hold a header at all.
        assert!(decode_frame(&frame[..10]).is_err());
    }

    #[test]
    fn a_truncated_advertisement_stops_rather_than_over_reads() {
        // Cut the Catalyst capture in the middle of a TLV value. Decoding must return what it
        // could read, not panic and not run off the end.
        let payload = bytes(CAPTURE_CATALYST_2950);
        for cut in [8usize, 20, 33, 64, 200] {
            let decoded = decode_payload(&payload[..cut]).expect("short payload still decodes");
            assert_eq!(decoded.advertisement.version, 2);
        }
    }

    #[test]
    fn a_zero_length_tlv_does_not_loop_forever() {
        // A TLV whose declared length is below its own 4-byte header would not advance the
        // cursor. The decoder must stop instead of spinning.
        let payload = [0x02, 0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x41, 0x42];
        let decoded = decode_payload(&payload).expect("decodes");
        assert!(decoded.advertisement.device_id.is_none());
    }

    // =========================================================================================
    // 4. Round-trip and action parsing
    // =========================================================================================

    /// A round trip through our own encoder and decoder proves internal consistency only — the
    /// captures above are what prove correctness. It is here to catch an encode/decode pair
    /// drifting apart, not as evidence of spec compliance.
    #[test]
    fn round_trips_every_modelled_field() {
        let ad = CdpAdvertisement::from_action(&json!({
            "type": "send_cdp_advertisement",
            "device_id": "edge-1",
            "port_id": "TenGigabitEthernet1/0/4",
            "platform": "cisco C9300-48P",
            "software_version": "Cisco IOS XE Software, Version 17.06.04",
            "capabilities": ["router", "switch", "igmp"],
            "native_vlan": 4094,
            "duplex": "half",
            "addresses": ["10.0.0.1", "2001:db8::1"],
            "management_addresses": ["10.0.0.1"],
            "ttl": 90,
            "version": 2
        }))
        .expect("valid");

        let payload = encode_payload(&ad).expect("encodes");
        let back = decode_payload(&payload).expect("decodes");
        assert!(back.checksum_valid(), "our own frames must verify");
        assert_eq!(back.advertisement, ad);
        assert_eq!(back.advertisement.addresses.len(), 2);
        assert_eq!(back.advertisement.addresses[1].protocol, "ipv6");
    }

    #[test]
    fn capability_names_and_bits_agree() {
        for (mask, name) in [
            (0x01u32, "router"),
            (0x02, "transparent_bridge"),
            (0x04, "source_route_bridge"),
            (0x08, "switch"),
            (0x10, "host"),
            (0x20, "igmp"),
            (0x40, "repeater"),
            (0x80, "voip_phone"),
        ] {
            assert_eq!(
                capability_bits(&[name.to_string()]).unwrap(),
                mask,
                "{name}"
            );
            assert_eq!(capability_names(mask), vec![name]);
        }
        // A bit with no name is reported, not silently dropped.
        assert_eq!(capability_names(0x100), vec!["bit_8"]);
        // An unknown name is refused rather than ignored.
        assert!(capability_bits(&["firewall".to_string()]).is_err());
    }

    #[test]
    fn rejects_malformed_actions_naming_the_field() {
        let cases: &[(serde_json::Value, &str)] = &[
            (json!({"type": "send_cdp_advertisement"}), "device_id"),
            (
                json!({"type": "send_cdp_advertisement", "device_id": ""}),
                "device_id",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "capabilities": ["firewall"]}),
                "capability",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "duplex": "auto"}),
                "duplex",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "ttl": 4000}),
                "ttl",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "native_vlan": 9999}),
                "native_vlan",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "version": 3}),
                "version",
            ),
            (
                json!({"type": "send_cdp_advertisement", "device_id": "a", "addresses": ["not-an-ip"]}),
                "addresses",
            ),
        ];
        for (action, expected_field) in cases {
            let err =
                CdpAdvertisement::from_action(action).expect_err(&format!("must reject {action}"));
            let msg = err.to_string();
            assert!(
                msg.contains(expected_field),
                "error for {action} should name '{expected_field}', got: {msg}"
            );
        }
    }

    #[test]
    fn parses_and_renders_macs() {
        assert_eq!(
            codec::parse_mac("01:00:0C:CC:CC:CC").unwrap(),
            CDP_MULTICAST_MAC
        );
        assert_eq!(
            codec::parse_mac("01-00-0c-cc-cc-cc").unwrap(),
            CDP_MULTICAST_MAC
        );
        assert_eq!(
            codec::mac_to_string(&CDP_MULTICAST_MAC),
            "01:00:0c:cc:cc:cc"
        );
        assert!(codec::parse_mac("01:00:0c:cc:cc").is_err());
        assert!(codec::parse_mac("zz:00:0c:cc:cc:cc").is_err());
    }

    /// The event body handed to the model must be structured — no byte arrays, no hex, no
    /// base64 — which is the project-wide rule for anything the LLM reads.
    #[test]
    fn event_data_is_structured_not_bytes() {
        // Built from the real Catalyst payload so the event reports a genuinely valid packet.
        let payload = bytes(CAPTURE_CATALYST_2950);
        let frame = encode_frame([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], &payload).unwrap();
        let (header, payload) = decode_frame(&frame).unwrap();
        let decoded = decode_payload(payload).unwrap();
        let data = decoded.to_event_data(&header, "conn-7");

        assert_eq!(data["connection_id"], "conn-7");
        assert_eq!(data["source_mac"], "11:22:33:44:55:66");
        assert_eq!(data["destination_mac"], "01:00:0c:cc:cc:cc");
        assert_eq!(data["device_id"], "myswitch");
        assert_eq!(data["port_id"], "FastEthernet0/1");
        assert_eq!(data["platform"], "cisco WS-C2950-12");
        assert_eq!(data["capabilities"], json!(["switch", "igmp"]));
        assert_eq!(data["capabilities_value"], 0x28);
        assert_eq!(data["native_vlan"], 1);
        assert_eq!(data["duplex"], "full");
        assert_eq!(data["addresses"][0]["address"], "192.168.0.253");
        assert_eq!(data["checksum_valid"], true);

        // Nothing anywhere in the event may look like a byte blob.
        let rendered = serde_json::to_string(&data).unwrap();
        for banned in ["\"data\":", "\"bytes\":", "\"raw\":", "\"hex\":", "base64"] {
            assert!(
                !rendered.contains(banned),
                "event data must not carry {banned}: {rendered}"
            );
        }
    }

    // =========================================================================================
    // Control characters, and the 802.3 length field that stops being a length
    // =========================================================================================
    //
    // Two separate defects with the same root: a value the model or a neighbour supplies was
    // put on the wire, or into a log line, without a bound or a check.

    /// A control character in a model-authored identifier is refused, not encoded.
    ///
    /// `CDP advertisement from {device_id} ({platform}) on {port_id}` is rendered by
    /// `src/protocol/log_template.rs`, which quotes nothing, and the same three strings are what
    /// `show cdp neighbors detail` prints. A newline in `device_id` forges a whole neighbour
    /// entry in both.
    #[test]
    fn a_control_character_in_a_model_authored_identifier_is_refused() {
        for field in ["device_id", "port_id", "platform"] {
            let mut action = json!({
                "type": "send_cdp_advertisement",
                "device_id": "myswitch",
            });
            action[field] = json!("myswitch\nimpostor");

            let ad = CdpAdvertisement::from_action(&action)
                .expect("from_action does not encode, so it accepts the value");
            let err = encode_payload(&ad)
                .expect_err("encoding a control character into a neighbour table must be refused")
                .to_string();
            assert!(
                err.contains(field) && err.contains("control character"),
                "the error must name the field and say what is wrong, got: {err}"
            );
        }
    }

    /// **Software Version is exempt, and that is a decision, not an oversight.**
    ///
    /// A real IOS version banner is multi-line — the scapy Catalyst capture above contains
    /// several `0x0a` bytes — and it is the single most useful thing a recon operator reads off
    /// a CDP frame. It is interpolated into no log template, only into the JSON-escaped trace
    /// line, so refusing its newlines would cost real information to close a hole that is not
    /// there.
    #[test]
    fn a_newline_in_software_version_is_allowed_because_a_real_banner_has_one() {
        let banner = "Cisco Internetwork Operating System Software\nIOS (tm) C2950 Software";
        let ad = CdpAdvertisement::from_action(&json!({
            "type": "send_cdp_advertisement",
            "device_id": "myswitch",
            "software_version": banner,
        }))
        .expect("valid");

        let payload = encode_payload(&ad).expect("a real multi-line banner must encode");
        let decoded = decode_payload(&payload).expect("decodes");
        assert_eq!(
            decoded.advertisement.software_version.as_deref(),
            Some(banner),
            "the banner must survive byte for byte, newlines included"
        );
    }

    /// A hostile neighbour's Device ID, Port ID or Platform cannot forge a log line.
    ///
    /// The payload is built by hand, because the encoder now refuses these values — using it
    /// would test nothing. These are octets a real attacker puts on the wire and CDP permits:
    /// the TLV is length-prefixed, so a newline is legal framing. Only the rendering is wrong.
    #[test]
    fn a_neighbours_control_characters_cannot_forge_a_log_line() {
        let mut payload: Vec<u8> = vec![2, 180, 0, 0];
        let mut push = |type_code: u16, value: &[u8]| {
            payload.extend_from_slice(&type_code.to_be_bytes());
            payload.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
            payload.extend_from_slice(value);
        };
        push(
            0x0001,
            b"core-sw\n2026-09-11 CDP advertisement from attacker",
        );
        push(0x0003, b"Gi0/1\rforged");
        push(0x0006, b"cisco WS-C2950-12\nimpostor");

        let decoded = decode_payload(&payload).expect("a hostile payload is still well-formed CDP");
        let ad = &decoded.advertisement;

        for (field, text) in [
            ("device_id", ad.device_id.as_deref().expect("present")),
            ("port_id", ad.port_id.as_deref().expect("present")),
            ("platform", ad.platform.as_deref().expect("present")),
        ] {
            assert!(
                !text.chars().any(char::is_control),
                "{field} reached the event still carrying a control character: {text:?}. It is \
                 rendered unquoted into `CDP advertisement from {{device_id}} ({{platform}}) on \
                 {{port_id}}`, so this forges a log line."
            );
        }

        // Neutralised, not truncated: an operator still sees what the neighbour claimed.
        assert!(ad.device_id.as_deref().unwrap().starts_with("core-sw "));
        assert_eq!(ad.port_id.as_deref(), Some("Gi0/1 forged"));
        assert_eq!(ad.platform.as_deref(), Some("cisco WS-C2950-12 impostor"));

        // `summary()` goes to the status stream and the access log, so it must be one line.
        assert!(
            !ad.summary().chars().any(char::is_control),
            "summary() is written to the status stream as one line: {:?}",
            ad.summary()
        );
    }

    /// An oversized advertisement is refused rather than silently ceasing to be an 802.3 frame.
    ///
    /// **This is the narrowing cast the bound exists for.** `u16::try_from(body_len)` alone
    /// accepts everything up to 65535, but IEEE 802.3 reserves `0x0600` (1536) and above for
    /// EtherType — so a frame whose length field lands there is read by every receiver as an
    /// Ethernet II frame of that protocol and the CDP behind it is never parsed. The test
    /// asserts both halves: that it is refused, *and* that the value it would have written is in
    /// the EtherType range, so the bound cannot be deleted on the grounds that it never fires.
    #[test]
    fn an_oversized_frame_is_refused_rather_than_aliasing_an_ethertype() {
        let payload = vec![0u8; 2000];
        let body_len = LLC_SNAP_HEADER.len() + payload.len();
        assert!(
            body_len >= 0x0600,
            "this test is only meaningful if the length field would land in the EtherType range"
        );

        let err = encode_frame([0x02, 0, 0, 0, 0, 1], &payload)
            .expect_err("a frame whose length field is an EtherType must be refused")
            .to_string();
        assert!(
            err.contains("1500") && err.contains("EtherType"),
            "the error must say why 1500 is the bound, got: {err}"
        );

        // The largest frame that is still unambiguously a length is accepted, so the bound is
        // exactly at the encapsulation boundary rather than somewhere convenient.
        let largest = vec![0u8; codec::MAX_8023_LENGTH - LLC_SNAP_HEADER.len()];
        let frame = encode_frame([0x02, 0, 0, 0, 0, 1], &largest).expect("1500 is a valid length");
        assert_eq!(
            u16::from_be_bytes([frame[12], frame[13]]) as usize,
            codec::MAX_8023_LENGTH
        );
    }

    /// Each text field is bounded on its own, so the error names the field.
    ///
    /// The binding constraint is the frame length above; this exists only so a model that sends
    /// a 400-byte platform string is told *which* field was too long instead of being handed an
    /// arithmetic complaint about the whole frame.
    #[test]
    fn an_overlong_identifier_is_refused_by_name() {
        let ad = CdpAdvertisement::from_action(&json!({
            "type": "send_cdp_advertisement",
            "device_id": "x".repeat(codec::MAX_TEXT_TLV + 1),
        }))
        .expect("from_action does not encode");

        let err = encode_payload(&ad)
            .expect_err("an overlong device_id is refused")
            .to_string();
        assert!(
            err.contains("device_id") && err.contains(&codec::MAX_TEXT_TLV.to_string()),
            "the error must name the field and the bound, got: {err}"
        );
    }
}
