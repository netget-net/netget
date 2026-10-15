//! The LLDP TLV codec, against literal specification bytes.
//!
//! This is the file the protocol's maturity rating rests on. The raw-Ethernet transport needs
//! `CAP_NET_RAW` / `/dev/bpf*` and has never been executed anywhere, so the only thing about
//! LLDP that *can* be proven in this environment is the frame format — and it is proven the way
//! `bluetooth_ble_beacon`'s payload is: **every expected byte string is written out literally
//! and derived from the published layout, not from the implementation.**
//!
//! Round-tripping the encoder through the decoder would prove only that one function inverts
//! the other. The root `CLAUDE.md` names that circular evidence, so where it appears it is
//! labelled a consistency check and never the argument — in
//! `encode_and_decode_agree_but_this_proves_nothing_on_its_own`, and in
//! `a_newline_in_system_description_is_allowed_because_a_real_banner_has_one`, where the round
//! trip is the point (the claim being that a multi-line banner survives unchanged).
//!
//! Sources for every literal below:
//!
//! * IEEE 802.1AB-2016 §8.1 (EtherType 0x88CC), §8.4 (TLV format: 7-bit type, 9-bit length),
//!   §8.5.2 (Chassis ID + Table 8-2), §8.5.3 (Port ID + Table 8-3), §8.5.4 (TTL),
//!   §8.5.5-8.5.7 (text TLVs), §8.5.8 (System Capabilities + Table 8-4),
//!   §8.5.9 (Management Address), §8.5.1 (End Of LLDPDU).
//! * IEEE 802.1AB Table 7-1 (the nearest-bridge group address 01:80:C2:00:00:0E).
//! * The widely-distributed Extreme Networks Summit300-48 LLDP capture, for the
//!   `real_world_capture_*` cases. Only the TLVs whose octets were re-derived arithmetically
//!   from the spec are asserted; the capture's text TLVs are deliberately left out rather than
//!   transcribed from memory, which would make the "real capture" claim worthless.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features lldp \
//!       --test server lldp::codec_test -- --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use netget::server::lldp::codec::{
    self, AdvertisementRequest, IdKind, Lldpdu, ManagementAddress, LLDP_ETHERTYPE,
    LLDP_MULTICAST_MAC,
};
use serde_json::json;

/// A chassis MAC used throughout, chosen so every octet is distinct and a byte swap shows.
const CHASSIS_MAC: &str = "00:1b:21:3c:4d:5e";
const CHASSIS_MAC_BYTES: [u8; 6] = [0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e];

// =============================================================================================
// TLV header: 7-bit type, 9-bit length
// =============================================================================================

/// The header is the one piece of LLDP framing everything else depends on, and it is the one
/// most easily written as two separate octets by mistake. A 9-bit length means the type's low
/// bit shares the first octet, so a type-4 TLV of length 23 is `08 17`, not `04 17`.
#[test]
fn tlv_headers_pack_a_7_bit_type_and_a_9_bit_length() {
    // Chassis ID (type 1) with a 6-octet MAC plus its subtype octet = 7.
    // (1 << 9) | 7 = 0x0207
    let pdu = Lldpdu::minimal(4, CHASSIS_MAC, 5, "1/1", 120);
    let bytes = pdu.encode().expect("minimal LLDPDU encodes");
    assert_eq!(&bytes[0..2], &[0x02, 0x07], "chassis ID TLV header");

    // Port ID (type 2), subtype octet + "1/1" = 4. (2 << 9) | 4 = 0x0404
    assert_eq!(&bytes[9..11], &[0x04, 0x04], "port ID TLV header");

    // Time To Live (type 3), always 2 octets. (3 << 9) | 2 = 0x0602
    assert_eq!(&bytes[15..17], &[0x06, 0x02], "TTL TLV header");

    // The type occupies bits 15..9, so every header's first octet is `type << 1` plus the
    // length's ninth bit. Checked here against the three above, which is what makes a
    // "two separate octets" implementation fail this test rather than pass it by luck.
    for (tlv_type, header) in [(1u8, [0x02, 0x07]), (2, [0x04, 0x04]), (3, [0x06, 0x02])] {
        assert_eq!(
            (u16::from_be_bytes(header) >> 9) as u8,
            tlv_type,
            "type recovered from header {header:02x?}"
        );
    }
}

// =============================================================================================
// Encoding against literal spec bytes
// =============================================================================================

/// The mandatory three TLVs and End Of LLDPDU, octet for octet.
///
/// 802.1AB §8.5 fixes both the set and the order: Chassis ID, Port ID, TTL, then optional TLVs,
/// then End. An implementation that emitted them in any other order produces a frame a
/// conforming receiver discards.
#[test]
fn the_mandatory_tlvs_encode_to_exactly_these_bytes() {
    let pdu = Lldpdu::minimal(
        4, // Chassis ID subtype 4 = MAC address (Table 8-2)
        CHASSIS_MAC,
        5, // Port ID subtype 5 = interface name (Table 8-3)
        "1/1",
        120,
    );

    #[rustfmt::skip]
    let expected: &[u8] = &[
        // Chassis ID TLV: type 1, length 7
        0x02, 0x07,
        0x04,                                      // subtype 4 = MAC address
        0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,        // the address itself

        // Port ID TLV: type 2, length 4
        0x04, 0x04,
        0x05,                                      // subtype 5 = interface name
        0x31, 0x2f, 0x31,                          // "1/1"

        // Time To Live TLV: type 3, length 2
        0x06, 0x02,
        0x00, 0x78,                                // 120 seconds, big endian

        // End Of LLDPDU: type 0, length 0
        0x00, 0x00,
    ];

    assert_eq!(pdu.encode().expect("encodes"), expected);
}

/// The Ethernet header an LLDP frame carries: the nearest-bridge group address and 0x88CC.
#[test]
fn the_ethernet_header_is_the_group_address_and_ethertype_88cc() {
    let pdu = Lldpdu::minimal(4, CHASSIS_MAC, 5, "1/1", 120);
    let frame = codec::encode_frame(
        LLDP_MULTICAST_MAC,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        &pdu,
    )
    .expect("frame encodes");

    #[rustfmt::skip]
    let expected_header: &[u8] = &[
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,   // destination: nearest bridge (Table 7-1)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,   // source: locally administered
        0x88, 0xcc,                           // EtherType (§8.1)
    ];
    assert_eq!(&frame[..14], expected_header);
    assert_eq!(LLDP_ETHERTYPE, 0x88CC);
    assert_eq!(&frame[14..], pdu.encode().expect("encodes").as_slice());
}

/// Every optional TLV, each with its own hand-computed header.
#[test]
fn the_optional_tlvs_encode_to_exactly_these_bytes() {
    let pdu = Lldpdu {
        port_description: Some("Uplink".to_string()),
        system_name: Some("netget".to_string()),
        system_description: Some("NetGet".to_string()),
        // bridge (0x0004) | router (0x0010) = 0x0014, with only bridge switched on.
        capabilities: Some((0x0014, 0x0004)),
        management_address: Some(
            ManagementAddress::new("192.0.2.10", 3).expect("an IPv4 management address"),
        ),
        ..Lldpdu::minimal(4, CHASSIS_MAC, 5, "1/1", 120)
    };

    let bytes = pdu.encode().expect("encodes");
    // Skip the mandatory prefix asserted above (9 + 6 + 4 = 19 octets).
    let optional = &bytes[19..];

    #[rustfmt::skip]
    let expected: &[u8] = &[
        // Port Description TLV: type 4, length 6. (4 << 9) | 6 = 0x0806
        0x08, 0x06,
        0x55, 0x70, 0x6c, 0x69, 0x6e, 0x6b,        // "Uplink"

        // System Name TLV: type 5, length 6. (5 << 9) | 6 = 0x0a06
        0x0a, 0x06,
        0x6e, 0x65, 0x74, 0x67, 0x65, 0x74,        // "netget"

        // System Description TLV: type 6, length 6. (6 << 9) | 6 = 0x0c06
        0x0c, 0x06,
        0x4e, 0x65, 0x74, 0x47, 0x65, 0x74,        // "NetGet"

        // System Capabilities TLV: type 7, length 4. (7 << 9) | 4 = 0x0e04
        0x0e, 0x04,
        0x00, 0x14,                                // supported: bridge | router
        0x00, 0x04,                                // enabled:   bridge

        // Management Address TLV: type 8, length 12. (8 << 9) | 12 = 0x100c
        0x10, 0x0c,
        0x05,                                      // address string length: family + 4 octets
        0x01,                                      // IANA address family 1 = IPv4
        0xc0, 0x00, 0x02, 0x0a,                    // 192.0.2.10
        0x02,                                      // interface numbering subtype 2 = ifIndex
        0x00, 0x00, 0x00, 0x03,                    // interface number 3
        0x00,                                      // OID string length: none

        // End Of LLDPDU
        0x00, 0x00,
    ];

    assert_eq!(optional, expected);
}

/// A chassis ID under the `network_address` subtype carries an IANA family octet first.
///
/// This is the shape most easily got wrong: subtype 5 is *not* "an IP address", it is "a family
/// octet followed by an address", and omitting the family shifts every subsequent octet.
#[test]
fn a_network_address_identifier_carries_its_iana_family_first() {
    let pdu = Lldpdu::minimal(5, "192.0.2.1", 5, "1/1", 120);

    #[rustfmt::skip]
    let expected_chassis: &[u8] = &[
        0x02, 0x06,                    // type 1, length 6 (subtype + family + 4 address octets)
        0x05,                          // subtype 5 = network address
        0x01,                          // IANA family 1 = IPv4
        0xc0, 0x00, 0x02, 0x01,        // 192.0.2.1
    ];
    assert_eq!(&pdu.encode().expect("encodes")[..8], expected_chassis);

    // IPv6 takes family 2 and sixteen octets: 1 + 1 + 16 = 18, so (1 << 9) | 18 = 0x0212.
    let pdu = Lldpdu::minimal(5, "2001:db8::1", 5, "1/1", 120);
    let bytes = pdu.encode().expect("encodes");
    assert_eq!(&bytes[..4], &[0x02, 0x12, 0x05, 0x02]);
    assert_eq!(
        &bytes[4..20],
        &[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01
        ]
    );
}

/// **A MAC address is chassis subtype 4 and port subtype 3.** The two tables are numbered
/// differently for the same concept, which is the single easiest thing to get wrong in LLDP,
/// and the symptom is a neighbour showing a plausible-looking wrong field.
#[test]
fn chassis_and_port_subtype_numbering_differ_for_the_same_concept() {
    assert_eq!(codec::subtype_code(IdKind::Chassis, "mac_address"), Some(4));
    assert_eq!(codec::subtype_code(IdKind::Port, "mac_address"), Some(3));
    assert_eq!(
        codec::subtype_code(IdKind::Chassis, "network_address"),
        Some(5)
    );
    assert_eq!(
        codec::subtype_code(IdKind::Port, "network_address"),
        Some(4)
    );
    // Names that exist only on one side.
    assert_eq!(
        codec::subtype_code(IdKind::Chassis, "interface_name"),
        Some(6)
    );
    assert_eq!(codec::subtype_code(IdKind::Port, "interface_name"), Some(5));
    assert_eq!(
        codec::subtype_code(IdKind::Chassis, "agent_circuit_id"),
        None
    );
    assert_eq!(codec::subtype_code(IdKind::Port, "chassis_component"), None);

    // And it shows in the bytes: the same MAC, one octet different.
    let chassis_mac = Lldpdu::minimal(4, CHASSIS_MAC, 3, CHASSIS_MAC, 120)
        .encode()
        .expect("encodes");
    assert_eq!(chassis_mac[2], 0x04, "chassis MAC subtype");
    assert_eq!(chassis_mac[11], 0x03, "port MAC subtype");
    assert_eq!(&chassis_mac[3..9], &CHASSIS_MAC_BYTES);
    assert_eq!(&chassis_mac[12..18], &CHASSIS_MAC_BYTES);
}

/// Capability bits, each asserted separately. Table 8-4 assigns them in a fixed order and a
/// single misplaced bit turns a router into a telephone.
#[test]
fn every_system_capability_bit_is_where_the_spec_puts_it() {
    let expected: &[(&str, u16)] = &[
        ("other", 0x0001),
        ("repeater", 0x0002),
        ("bridge", 0x0004),
        ("wlan_access_point", 0x0008),
        ("router", 0x0010),
        ("telephone", 0x0020),
        ("docsis_cable_device", 0x0040),
        ("station_only", 0x0080),
        ("c_vlan_component", 0x0100),
        ("s_vlan_component", 0x0200),
        ("two_port_mac_relay", 0x0400),
    ];

    for (name, bit) in expected {
        assert_eq!(
            codec::capability_bits(&[name.to_string()]).expect("a known capability"),
            *bit,
            "capability '{name}'"
        );
        assert_eq!(codec::capability_names(*bit), vec![name.to_string()]);
    }

    // A bit the spec has not assigned is reported, not dropped: a neighbour setting it is
    // telling us something.
    assert_eq!(codec::capability_names(0x8000), vec!["reserved_bit_15"]);

    // A typo is an error. Silently dropping it would let a model believe it had claimed to be
    // a bridge when it advertised nothing at all.
    let err = codec::capability_bits(&["swtich".to_string()]).expect_err("a typo is refused");
    assert!(
        err.to_string().contains("swtich") && err.to_string().contains("bridge"),
        "the error must name the bad value and list the valid ones: {err}"
    );
}

// =============================================================================================
// Decoding literal bytes
// =============================================================================================

/// Decode a complete frame written out octet by octet, and check every field.
#[test]
fn a_literal_frame_decodes_to_its_fields() {
    #[rustfmt::skip]
    let frame: &[u8] = &[
        // Ethernet
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x88, 0xcc,

        // Chassis ID: type 1, length 7, subtype 4 (MAC)
        0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,
        // Port ID: type 2, length 7, subtype 5 (interface name), "eth0/12"
        0x04, 0x08, 0x05, 0x65, 0x74, 0x68, 0x30, 0x2f, 0x31, 0x32,
        // TTL: type 3, length 2, 65535
        0x06, 0x02, 0xff, 0xff,
        // System Name: type 5, length 4, "core"
        0x0a, 0x04, 0x63, 0x6f, 0x72, 0x65,
        // System Capabilities: type 7, length 4, supported router|telephone, enabled router
        0x0e, 0x04, 0x00, 0x30, 0x00, 0x10,
        // Management Address: type 8, length 12, IPv4 198.51.100.7, ifIndex 1
        0x10, 0x0c, 0x05, 0x01, 0xc6, 0x33, 0x64, 0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
        // End Of LLDPDU
        0x00, 0x00,
    ];

    let decoded = codec::decode_frame(frame).expect("a well-formed LLDP frame decodes");

    assert_eq!(decoded.destination_mac, LLDP_MULTICAST_MAC);
    assert_eq!(
        codec::format_mac(&decoded.source_mac),
        "aa:bb:cc:dd:ee:ff",
        "source MAC comes from the Ethernet header, not from any TLV"
    );

    let pdu = decoded.lldpdu;
    assert_eq!(pdu.chassis_id_subtype, 4);
    assert_eq!(pdu.chassis_id, CHASSIS_MAC, "subtype 4 renders as a MAC");
    assert_eq!(pdu.port_id_subtype, 5);
    assert_eq!(pdu.port_id, "eth0/12", "subtype 5 renders as text");
    assert_eq!(pdu.ttl, 65535, "TTL is big endian");
    assert_eq!(pdu.system_name.as_deref(), Some("core"));
    assert_eq!(pdu.port_description, None, "no TLV, no field");
    assert_eq!(pdu.system_description, None);
    assert_eq!(pdu.capabilities, Some((0x0030, 0x0010)));

    let mgmt = pdu.management_address.expect("a management address TLV");
    assert_eq!(mgmt.address, "198.51.100.7");
    assert_eq!(mgmt.family, 1);
    assert_eq!(mgmt.family_name(), "ipv4");
    assert_eq!(mgmt.interface_number, 1);
}

/// The mandatory, capability and management TLVs exactly as they appear in the widely
/// distributed Extreme Networks Summit300-48 LLDP capture.
///
/// The capture's text TLVs are deliberately **not** asserted: their octets were not re-derived
/// here, and transcribing a description from memory would turn "checked against a real capture"
/// into a claim about nothing. What is below was re-derived arithmetically from 802.1AB, and
/// every length octet was checked against its contents.
#[test]
fn real_world_capture_tlvs_decode() {
    #[rustfmt::skip]
    let frame: &[u8] = &[
        // Ethernet: to the nearest-bridge group address, from the switch's own MAC
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
        0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0,
        0x88, 0xcc,

        // 02 07 04 <MAC>  — Chassis ID, subtype 4, 00:01:30:f9:ad:a0
        0x02, 0x07, 0x04, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0,
        // 04 04 05 "1/1"  — Port ID, subtype 5 (interface name)
        0x04, 0x04, 0x05, 0x31, 0x2f, 0x31,
        // 06 02 00 78     — TTL 120
        0x06, 0x02, 0x00, 0x78,
        // 0e 04 0014 0014 — capabilities: bridge|router, both enabled
        0x0e, 0x04, 0x00, 0x14, 0x00, 0x14,
        // 10 0e 07 06 <MAC> 02 00000000 00 — management address, IANA family 6 (802/MAC)
        0x10, 0x0e, 0x07, 0x06, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        // End
        0x00, 0x00,
    ];

    let decoded = codec::decode_frame(frame).expect("the capture decodes");
    let pdu = decoded.lldpdu;

    assert_eq!(pdu.chassis_id, "00:01:30:f9:ad:a0");
    assert_eq!(
        codec::subtype_name(IdKind::Chassis, pdu.chassis_id_subtype),
        "mac_address"
    );
    assert_eq!(pdu.port_id, "1/1");
    assert_eq!(
        codec::subtype_name(IdKind::Port, pdu.port_id_subtype),
        "interface_name"
    );
    assert_eq!(pdu.ttl, 120);

    let (supported, enabled) = pdu.capabilities.expect("a capabilities TLV");
    assert_eq!(codec::capability_names(supported), vec!["bridge", "router"]);
    assert_eq!(codec::capability_names(enabled), vec!["bridge", "router"]);

    // IANA family 6 is "802", i.e. a 48-bit MAC — a management address need not be an IP.
    let mgmt = pdu.management_address.expect("a management address TLV");
    assert_eq!(mgmt.family, 6);
    assert_eq!(mgmt.family_name(), "mac_address");
    assert_eq!(mgmt.address, "00:01:30:f9:ad:a0");
    assert_eq!(mgmt.interface_number, 0);
}

/// Organisationally specific TLVs (type 127) and anything else unrecognised are skipped, not
/// fatal. Real switches send several of these in every frame — VLAN ID, MAC/PHY status, power
/// over Ethernet — and a decoder that rejected them would refuse most real traffic.
#[test]
fn unrecognised_tlvs_are_skipped_rather_than_fatal() {
    #[rustfmt::skip]
    let pdu_bytes: &[u8] = &[
        0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,
        0x04, 0x04, 0x05, 0x31, 0x2f, 0x31,
        0x06, 0x02, 0x00, 0x78,
        // Organisationally specific: type 127, length 6. (127 << 9) | 6 = 0xfe06
        0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x00, 0x64,
        // System Name after it, to prove the walk resumed at the right offset
        0x0a, 0x04, 0x63, 0x6f, 0x72, 0x65,
        0x00, 0x00,
    ];

    let pdu = Lldpdu::decode(pdu_bytes).expect("an unknown TLV is skipped");
    assert_eq!(pdu.system_name.as_deref(), Some("core"));
}

/// 802.1AB §8.5 fixes the order of the mandatory TLVs, and a decoder that accepted any order
/// would silently accept frames a real neighbour rejects.
#[test]
fn the_mandatory_tlv_order_is_enforced() {
    // Port ID first.
    #[rustfmt::skip]
    let wrong_order: &[u8] = &[
        0x04, 0x04, 0x05, 0x31, 0x2f, 0x31,
        0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,
        0x06, 0x02, 0x00, 0x78,
        0x00, 0x00,
    ];
    let err = Lldpdu::decode(wrong_order).expect_err("Port ID cannot come first");
    assert!(
        err.to_string().contains("Chassis ID"),
        "the error should name the TLV that was expected: {err}"
    );

    // TTL missing entirely.
    #[rustfmt::skip]
    let no_ttl: &[u8] = &[
        0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,
        0x04, 0x04, 0x05, 0x31, 0x2f, 0x31,
        0x00, 0x00,
    ];
    let err = Lldpdu::decode(no_ttl).expect_err("TTL is mandatory");
    assert!(err.to_string().contains("Time To Live"), "{err}");
}

/// A frame that is not LLDP, or that is truncated, is refused rather than half-read. The UDP
/// test transport accepts datagrams from anyone, so this is not hypothetical there.
#[test]
fn malformed_input_is_refused() {
    let err = codec::decode_frame(&[0u8; 8]).expect_err("shorter than an Ethernet header");
    assert!(err.to_string().contains("Ethernet header"), "{err}");

    let mut wrong_ethertype = vec![0u8; 20];
    wrong_ethertype[12] = 0x08;
    wrong_ethertype[13] = 0x00; // IPv4
    let err = codec::decode_frame(&wrong_ethertype).expect_err("EtherType is checked");
    assert!(err.to_string().contains("0x0800"), "{err}");

    // A TLV whose declared length runs past the buffer.
    let truncated: &[u8] = &[0x02, 0x07, 0x04, 0x00, 0x1b];
    let err = Lldpdu::decode(truncated).expect_err("a truncated TLV is refused");
    assert!(err.to_string().contains("declares"), "{err}");

    // A MAC-subtype chassis ID that is not six octets.
    let bad_mac: &[u8] = &[0x02, 0x04, 0x04, 0x00, 0x1b, 0x21];
    let err = Lldpdu::decode(bad_mac).expect_err("a 3-octet MAC is refused");
    assert!(err.to_string().contains("6 octets"), "{err}");
}

// =============================================================================================
// The action boundary: structured fields in, frames out, never bytes
// =============================================================================================

/// A `send_lldp_advertisement` action becomes the frame its fields describe.
#[test]
fn an_action_becomes_the_frame_it_describes() {
    let action = json!({
        "type": "send_lldp_advertisement",
        "chassis_id": "00:1b:21:3c:4d:5e",
        "chassis_id_subtype": "mac_address",
        "port_id": "1/1",
        "port_id_subtype": "interface_name",
        "ttl": 120
    });

    let request = AdvertisementRequest::from_action(&action).expect("a valid action");
    assert_eq!(
        request.destination_mac, LLDP_MULTICAST_MAC,
        "an advertisement goes to the nearest-bridge group address unless told otherwise"
    );
    assert_eq!(
        request.source_mac, None,
        "the server supplies the source address; the model names an identity, not a frame"
    );

    let frame = request
        .to_frame([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        .expect("the fallback source is used");

    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x88, 0xcc,
        0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e,
        0x04, 0x04, 0x05, 0x31, 0x2f, 0x31,
        0x06, 0x02, 0x00, 0x78,
        0x00, 0x00,
    ];
    assert_eq!(frame, expected);
}

/// The subtype is what a model is most likely to omit, so it is inferred from the value's shape
/// rather than defaulted to something that would misrepresent it.
#[test]
fn an_omitted_subtype_is_inferred_from_the_value() {
    let mac = AdvertisementRequest::from_action(&json!({
        "type": "send_lldp_advertisement",
        "chassis_id": "00:1b:21:3c:4d:5e",
        "port_id": "1/1"
    }))
    .expect("valid");
    assert_eq!(
        mac.lldpdu.chassis_id_subtype, 4,
        "a MAC becomes mac_address"
    );
    assert_eq!(mac.lldpdu.port_id_subtype, 7, "free text becomes 'local'");

    let ip = AdvertisementRequest::from_action(&json!({
        "type": "send_lldp_advertisement",
        "chassis_id": "192.0.2.1",
        "port_id": "aa:bb:cc:dd:ee:ff"
    }))
    .expect("valid");
    assert_eq!(
        ip.lldpdu.chassis_id_subtype, 5,
        "an IP becomes network_address"
    );
    assert_eq!(
        ip.lldpdu.port_id_subtype, 3,
        "a MAC port becomes port subtype 3"
    );
}

/// Capabilities default to "everything supported is enabled" when only one list is given.
///
/// The alternative — enabled = 0 — would describe a device that supports being a bridge and is
/// not one, which is not what a model asking to "advertise as a switch" means.
#[test]
fn capabilities_default_to_supported_when_only_one_list_is_given() {
    let request = AdvertisementRequest::from_action(&json!({
        "type": "send_lldp_advertisement",
        "chassis_id": "00:1b:21:3c:4d:5e",
        "port_id": "1/1",
        "capabilities": ["bridge", "router"]
    }))
    .expect("valid");
    assert_eq!(request.lldpdu.capabilities, Some((0x0014, 0x0014)));

    let request = AdvertisementRequest::from_action(&json!({
        "type": "send_lldp_advertisement",
        "chassis_id": "00:1b:21:3c:4d:5e",
        "port_id": "1/1",
        "capabilities": ["bridge", "router"],
        "capabilities_enabled": ["bridge"]
    }))
    .expect("valid");
    assert_eq!(request.lldpdu.capabilities, Some((0x0014, 0x0004)));
}

/// An action that cannot become a valid frame is refused **at the action**, where the model can
/// be told, rather than producing something a neighbour discards in silence.
#[test]
fn an_action_that_cannot_become_a_frame_is_refused() {
    let cases: &[(serde_json::Value, &str)] = &[
        (
            json!({"type": "send_lldp_advertisement", "port_id": "1/1"}),
            "chassis_id",
        ),
        (
            json!({"type": "send_lldp_advertisement", "chassis_id": "x", "port_id": "1/1",
                   "chassis_id_subtype": "mac_address"}),
            "MAC address",
        ),
        (
            json!({"type": "send_lldp_advertisement", "chassis_id": "00:1b:21:3c:4d:5e",
                   "port_id": "1/1", "chassis_id_subtype": "not_a_subtype"}),
            "802.1AB",
        ),
        (
            json!({"type": "send_lldp_advertisement", "chassis_id": "00:1b:21:3c:4d:5e",
                   "port_id": "1/1", "ttl": 99999}),
            "65535",
        ),
        (
            json!({"type": "send_lldp_advertisement", "chassis_id": "00:1b:21:3c:4d:5e",
                   "port_id": "1/1", "system_name": "x".repeat(256)}),
            "255",
        ),
        (
            json!({"type": "send_lldp_advertisement", "chassis_id": "00:1b:21:3c:4d:5e",
                   "port_id": "1/1", "management_address": "not-an-address"}),
            "management address",
        ),
    ];

    for (action, needle) in cases {
        let err = AdvertisementRequest::from_action(action)
            .expect_err(&format!("this must be refused: {action}"));
        assert!(
            err.to_string().contains(needle),
            "error for {action} should mention '{needle}': {err}"
        );
    }
}

/// **Nothing the model sees is a byte blob.** This is the rule the whole protocol design hangs
/// on: a `tlv_hex` field would be reliably unreadable to a model and would make LLDP pointless
/// as an LLM-driven protocol.
#[test]
fn event_data_carries_no_octets_anywhere() {
    let pdu = Lldpdu {
        port_description: Some("Uplink to core".to_string()),
        system_name: Some("core-sw-1".to_string()),
        system_description: Some("Vendor OS 1.2.3".to_string()),
        capabilities: Some((0x0014, 0x0004)),
        management_address: Some(ManagementAddress::new("192.0.2.10", 1).expect("valid")),
        ..Lldpdu::minimal(4, CHASSIS_MAC, 5, "1/1", 120)
    };

    let data = pdu.to_event_data();

    for (key, value) in &data {
        assert!(
            !key.contains("hex") && !key.contains("raw") && !key.contains("bytes"),
            "event field '{key}' looks like an encoded blob"
        );
        if let Some(text) = value.as_str() {
            let looks_like_hex = text.len() > 16
                && text.chars().all(|c| c.is_ascii_hexdigit())
                && !text.contains(':');
            assert!(
                !looks_like_hex,
                "field '{key}' carries a hex string: {text}"
            );
        }
    }

    // Subtypes reach the model as names; the numbers are there too, for anyone who wants them.
    assert_eq!(data["chassis_id_subtype"], json!("mac_address"));
    assert_eq!(data["chassis_id_subtype_code"], json!(4));
    assert_eq!(data["port_id_subtype"], json!("interface_name"));
    assert_eq!(data["capabilities"], json!(["bridge", "router"]));
    assert_eq!(data["capabilities_enabled"], json!(["bridge"]));
    assert_eq!(data["management_address"], json!("192.0.2.10"));

    // Absent optional TLVs are absent, not null: a handler can test with a plain `in`.
    let minimal = Lldpdu::minimal(4, CHASSIS_MAC, 5, "1/1", 120).to_event_data();
    assert!(!minimal.contains_key("system_name"));
    assert!(!minimal.contains_key("capabilities"));
    assert!(!minimal.contains_key("management_address"));
}

/// Consistency check, and **not** the evidence for anything: the literal-byte cases above are.
/// It is here because an asymmetry between the two directions would be a real bug.
#[test]
fn encode_and_decode_agree_but_this_proves_nothing_on_its_own() {
    let original = Lldpdu {
        port_description: Some("Uplink".to_string()),
        system_name: Some("core".to_string()),
        system_description: Some("Vendor OS".to_string()),
        capabilities: Some((0x0014, 0x0004)),
        management_address: Some(ManagementAddress::new("2001:db8::1", 7).expect("valid")),
        ..Lldpdu::minimal(4, CHASSIS_MAC, 3, "aa:bb:cc:dd:ee:ff", 120)
    };
    let decoded = Lldpdu::decode(&original.encode().expect("encodes")).expect("decodes");
    assert_eq!(decoded, original);
}

// =============================================================================================
// Control characters: an LLDP text TLV is an entry in somebody's neighbour table
// =============================================================================================
//
// LLDP has no authentication, so whatever a neighbour puts in its System Name is copied verbatim
// into `show lldp neighbors`, into an NMS topology display, and — on this side — into the
// `lldp_neighbor_advertisement` log line, which `src/protocol/log_template.rs` renders with no
// quoting at all. A newline therefore does not merely look odd: it forges a whole extra entry in
// every one of those displays, which is the point of impersonating a switch.
//
// The two directions take deliberately opposite exits, and both are pinned here:
//
// * **Encode** refuses. The model authored the string and can be told, and silently rewriting
//   its answer would make the frame disagree with the decision the log records.
// * **Decode** strips, on the identifier TLVs only. A neighbour cannot be asked to resend, and
//   dropping the advertisement would hide a device that is really there.

/// A control character in a model-authored identifier or `ifDescr` field is refused, not encoded.
///
/// Asserted through `AdvertisementRequest::from_action`, which is the path a model's answer
/// actually takes, rather than through `Lldpdu::encode` directly.
#[test]
fn a_control_character_in_a_model_authored_identifier_is_refused() {
    for (field, value) in [
        ("system_name", "sw1\nsw2"),
        ("port_description", "Uplink\rto core"),
    ] {
        let mut action = json!({
            "type": "send_lldp_advertisement",
            "chassis_id": CHASSIS_MAC,
            "port_id": "1/1",
        });
        action[field] = json!(value);

        let err = AdvertisementRequest::from_action(&action)
            .expect_err("a control character in a neighbour-table field must be refused")
            .to_string();
        assert!(
            err.contains(field) && err.contains("control character"),
            "the error must name the field and say what is wrong, got: {err}"
        );
    }
}

/// The same refusal on a free-text Chassis ID / Port ID, which are the *keys* of the table.
///
/// These do not go through `push_text_tlv` at all — they are built by `encode_id_value`, a
/// separate path that would otherwise be a separate hole.
#[test]
fn a_control_character_in_a_free_text_chassis_or_port_id_is_refused() {
    for (field, subtype_field, subtype) in [
        ("chassis_id", "chassis_id_subtype", "local"),
        ("port_id", "port_id_subtype", "interface_name"),
    ] {
        let mut action = json!({
            "type": "send_lldp_advertisement",
            "chassis_id": CHASSIS_MAC,
            "port_id": "1/1",
        });
        action[field] = json!("real-switch\nimpostor");
        action[subtype_field] = json!(subtype);

        let err = AdvertisementRequest::from_action(&action)
            .expect_err("a control character in a table key must be refused")
            .to_string();
        assert!(
            err.contains("control character"),
            "expected a control-character refusal for {field}, got: {err}"
        );
    }
}

/// **System Description is exempt, and that is a decision, not an oversight.**
///
/// 802.1AB's System Description is `sysDescr`; for IOS it is a multi-line banner, and it is the
/// most useful single thing a recon operator reads off a link. It is interpolated into no log
/// template — only into the JSON-escaped trace line — so refusing its newlines would cost real
/// information to close a hole that is not there.
#[test]
fn a_newline_in_system_description_is_allowed_because_a_real_banner_has_one() {
    let banner = "Vendor OS Software\nVersion 15.0(2)SE11\nCopyright (c) 1986-2010";
    let action = json!({
        "type": "send_lldp_advertisement",
        "chassis_id": CHASSIS_MAC,
        "port_id": "1/1",
        "system_description": banner,
    });
    let request = AdvertisementRequest::from_action(&action).expect("a real banner must encode");
    assert_eq!(request.lldpdu.system_description.as_deref(), Some(banner));

    // And it survives the round trip byte for byte, so the exemption is real rather than a
    // refusal that happens not to fire.
    let decoded = Lldpdu::decode(&request.lldpdu.encode().expect("encodes")).expect("decodes");
    assert_eq!(decoded.system_description.as_deref(), Some(banner));
}

/// A hostile neighbour cannot forge a log line through the System Name, Chassis ID or Port ID.
///
/// The frame is built by hand rather than through our encoder — the encoder now refuses these
/// values, so using it would test nothing. These are the octets a real attacker puts on the
/// wire, and 802.1AB permits them: the TLV is length-prefixed, so a newline is perfectly legal
/// framing. Only the rendering is the problem.
#[test]
fn a_neighbours_control_characters_cannot_forge_a_log_line() {
    // Chassis ID subtype 7 and Port ID subtype 7 are both "locally assigned", i.e. the free-text
    // forms, so the injected bytes land in the identifier rather than in a MAC.
    let chassis = b"core-sw\n2026-09-11 LLDP neighbour attacker";
    let port = b"Gi0/1\rforged";
    let name = b"switch1\nswitch2";

    let mut lldpdu: Vec<u8> = Vec::new();
    {
        let mut push = |tlv_type: u8, value: &[u8]| {
            let header = ((tlv_type as u16) << 9) | value.len() as u16;
            lldpdu.extend_from_slice(&header.to_be_bytes());
            lldpdu.extend_from_slice(value);
        };
        let mut chassis_value = vec![7u8];
        chassis_value.extend_from_slice(chassis);
        push(1, &chassis_value);
        let mut port_value = vec![7u8];
        port_value.extend_from_slice(port);
        push(2, &port_value);
        push(3, &120u16.to_be_bytes());
        push(5, name);
        push(0, &[]);
    }

    let decoded = Lldpdu::decode(&lldpdu).expect("a hostile LLDPDU is still well-formed LLDP");

    for (field, text) in [
        ("chassis_id", decoded.chassis_id.as_str()),
        ("port_id", decoded.port_id.as_str()),
        (
            "system_name",
            decoded.system_name.as_deref().expect("present"),
        ),
    ] {
        assert!(
            !text.chars().any(char::is_control),
            "{field} reached the event still carrying a control character: {text:?}. It is \
             rendered unquoted into `LLDP neighbour {{system_name}} ({{chassis_id}}) on port \
             {{port_id}}`, so this forges a log line."
        );
    }

    // Neutralised, not truncated: the rest of the value is still reported, so an operator sees
    // what the neighbour actually claimed.
    assert_eq!(decoded.system_name.as_deref(), Some("switch1 switch2"));
    assert!(decoded.chassis_id.starts_with("core-sw "));
    assert_eq!(decoded.port_id, "Gi0/1 forged");

    // The event the model reads carries the same neutralised string.
    let data = decoded.to_event_data();
    assert_eq!(data["system_name"], json!("switch1 switch2"));
}
