//! GTP codec assertions against literal, 3GPP-derived octets.
//!
//! **Not round trips.** Encoding with our encoder and decoding with our decoder proves only
//! that one implementation agrees with itself, which the root `CLAUDE.md` names as circular
//! evidence. Every assertion below is against a byte vector written out by hand from
//! TS 29.060 §6 / §7.7 and TS 29.274 §5.1 / §8, so a change of interpretation fails here
//! rather than passing quietly.
//!
//! Two traps get a test of their own because implementations get them wrong routinely:
//!
//! * the GTPv1 **E/S/PN all-or-nothing rule** — any one flag means all four optional octets
//!   are present, and a decoder that consumes only the flagged field desynchronises
//!   everything after it;
//! * the GTPv1 **fixed (<128) vs TLV (>=128) information element split** — a parser that
//!   assumes TLV throughout reads a Cause value as the first octet of a length.

use netget::server::gtp::codec as ng;
use std::net::{IpAddr, Ipv4Addr};

// ===========================================================================
// GTPv1 header
// ===========================================================================

#[test]
fn test_v1_header_bit_layout_matches_ts_29_060() {
    // TS 29.060 §6: Version=001, PT=1 (GTP, not GTP'), spare=0, E=0, S=0, PN=0 => 0x30.
    // Message type 255 (G-PDU), Length = 1 (the body only), TEID = 0x12345678.
    let message = ng::GtpV1Message {
        header: ng::GtpV1Header::new(ng::V1_G_PDU, 0x1234_5678),
        body: vec![0xAA],
    };
    assert_eq!(
        message.encode(),
        vec![0x30, 0xFF, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0xAA],
        "a G-PDU with no optional fields is exactly eight header octets plus its payload"
    );

    // With a sequence number the S flag sets bit 2 => 0x32, and the Length field grows by the
    // whole four-octet optional block, not by two.
    let echo = ng::GtpV1Message {
        header: ng::GtpV1Header::with_sequence(ng::V1_ECHO_REQUEST, 0, 0x0001),
        body: Vec::new(),
    };
    assert_eq!(
        echo.encode(),
        vec![0x32, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        "the Length field counts the optional block: 4, not 2"
    );

    // PT=0 is GTP' (charging), which this server does not serve but must still encode
    // distinguishably.
    let mut prime = ng::GtpV1Header::new(ng::V1_ECHO_REQUEST, 0);
    prime.protocol_type = false;
    assert_eq!(prime.flags(), 0x20);
}

#[test]
fn test_v1_optional_block_is_all_or_nothing() {
    // *** The rule. *** Only PN is set, so the header must STILL carry all four optional
    // octets: a zero sequence number, the N-PDU number, and a zero next-extension-header.
    let message = ng::GtpV1Message {
        header: ng::GtpV1Header {
            protocol_type: true,
            message_type: ng::V1_G_PDU,
            teid: 0x0000_0001,
            sequence: None,
            npdu: Some(0x07),
            extension_headers: Vec::new(),
        },
        body: vec![0xBB],
    };
    assert_eq!(
        message.encode(),
        vec![
            0x31, // version 1, PT=1, PN=1
            0xFF, // G-PDU
            0x00, 0x05, // length: 4 optional octets + 1 body octet
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // sequence: absent, but written as zero
            0x07, // N-PDU number
            0x00, // next extension header type: none
            0xBB,
        ],
        "PN alone still emits the sequence and next-extension octets"
    );

    // The decode side of the same rule, and the failure it prevents. `0xEE` sits where the
    // N-PDU number would be; a decoder that consumed only the two sequence octets would
    // report a body of EE 00 DE AD instead of DE AD.
    let wire = vec![
        0x32, // S only
        0xFF, 0x00, 0x06, // length 6
        0x00, 0x00, 0x00, 0x01, // TEID
        0x00, 0x2A, // sequence 42
        0xEE, // N-PDU number: present on the wire, meaningless because PN is clear
        0x00, // next extension header type
        0xDE, 0xAD,
    ];
    let decoded = ng::GtpV1Message::decode(&wire).expect("a well-formed GTPv1 datagram");
    assert_eq!(decoded.header.sequence, Some(42));
    assert_eq!(
        decoded.header.npdu, None,
        "the N-PDU octet is present but must not be reported when PN is clear"
    );
    assert_eq!(
        decoded.body,
        vec![0xDE, 0xAD],
        "the body starts after all four optional octets, not after two"
    );
}

#[test]
fn test_v1_extension_headers() {
    // TS 29.060 §6.1: an extension header is length-in-4-octet-units, contents, next type.
    // One header of type 0x85 (PDCP PDU number) with two content octets is one unit.
    let message = ng::GtpV1Message {
        header: ng::GtpV1Header {
            protocol_type: true,
            message_type: ng::V1_G_PDU,
            teid: 0x0000_00FF,
            sequence: Some(9),
            npdu: None,
            extension_headers: vec![ng::ExtensionHeader {
                ext_type: 0x85,
                content: vec![0x01, 0x02],
            }],
        },
        body: vec![0xCC],
    };
    assert_eq!(
        message.encode(),
        vec![
            0x36, // version 1, PT=1, E=1, S=1
            0xFF, 0x00, 0x09, // length: 4 optional + 4 extension + 1 body
            0x00, 0x00, 0x00, 0xFF, // TEID
            0x00, 0x09, // sequence
            0x00, // N-PDU: absent, written as zero
            0x85, // next extension header type
            0x01, // extension header length: 1 unit = 4 octets
            0x01, 0x02, // contents
            0x00, // next extension header type: none
            0xCC,
        ]
    );

    let decoded = ng::GtpV1Message::decode(&message.encode()).expect("valid");
    assert_eq!(decoded.header.extension_headers.len(), 1);
    assert_eq!(decoded.header.extension_headers[0].ext_type, 0x85);
    assert_eq!(
        decoded.header.extension_headers[0].content,
        vec![0x01, 0x02]
    );
    assert_eq!(decoded.body, vec![0xCC]);
}

#[test]
fn test_v1_decode_rejections() {
    assert_eq!(
        ng::GtpV1Message::decode(&[0x30, 0xFF]),
        Err(ng::DecodeError::TooShort { len: 2, needed: 8 })
    );
    // Version 0 is GTPv0, which this server answers with Version Not Supported rather than
    // decoding.
    assert_eq!(
        ng::GtpV1Message::decode(&[0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0]),
        Err(ng::DecodeError::BadVersion { version: 0 })
    );
    // A length field that promises more than the datagram holds.
    assert_eq!(
        ng::GtpV1Message::decode(&[0x30, 0xFF, 0x00, 0x40, 0, 0, 0, 0, 0xAA]),
        Err(ng::DecodeError::LengthMismatch {
            declared: 64,
            available: 1
        })
    );
    assert_eq!(ng::peek_version(&[0x48, 0x20]), Some(2));
    assert_eq!(ng::peek_version(&[]), None);
}

// ===========================================================================
// GTPv1 information elements: the fixed / TLV split
// ===========================================================================

#[test]
fn test_v1_ies_split_at_128() {
    // A Create PDP Context Request body, written out octet by octet.
    //
    // The trap: IE type 1 (Cause) carries ONE octet with no length prefix. A parser that
    // assumed TLV throughout would read 0x80 0x02 as a 32770-octet length and give up.
    let body: Vec<u8> = vec![
        0x01, 0x80, // Cause = 128 (Request accepted), fixed, 1 octet
        0x02, 0x62, 0x02, 0x11, 0x32, 0x54, 0x76, 0x98, 0xF0, // IMSI, fixed, 8 octets
        0x11, 0x22, 0x22, 0x22, 0x22, // TEID Control Plane (17), fixed, 4 octets
        0x14, 0x05, // NSAPI (20), fixed, 1 octet
        0x83, 0x00, 0x09, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e',
        b't', // APN (131), TLV
    ];

    let ies = ng::parse_v1_ies(&body).expect("a well-formed GTPv1-C body");
    let types: Vec<u8> = ies.iter().map(|ie| ie.ie_type).collect();
    assert_eq!(
        types,
        vec![1, 2, 17, 20, 131],
        "five information elements, four of them length-free"
    );
    assert_eq!(ng::find_v1(&ies, 1), Some([0x80].as_slice()));
    assert_eq!(
        ng::decode_tbcd(ng::find_v1(&ies, 2).unwrap()),
        "262011234567890"
    );
    assert_eq!(
        u32::from_be_bytes(ng::find_v1(&ies, 17).unwrap().try_into().unwrap()),
        0x2222_2222
    );
    assert_eq!(
        ng::decode_apn(ng::find_v1(&ies, 131).unwrap()).as_deref(),
        Some("internet")
    );

    // Encoding the same elements must reproduce the same octets.
    assert_eq!(ng::encode_v1_ies(&ies), body);

    // A fixed-length type whose length is not known cannot be skipped, so parsing stops
    // rather than guessing and misreading everything after it.
    assert_eq!(
        ng::parse_v1_ies(&[0x06, 0x00, 0x00]),
        Err(ng::DecodeError::UnknownFixedIe { ie_type: 6 })
    );
    // A TLV element whose length runs past the buffer.
    assert_eq!(
        ng::parse_v1_ies(&[0x83, 0x00, 0x40, 0x01]),
        Err(ng::DecodeError::TruncatedIe { ie_type: 131 })
    );

    // The table itself: below 128 fixed, at and above 128 not.
    assert_eq!(ng::v1_fixed_ie_len(1), Some(1)); // Cause
    assert_eq!(ng::v1_fixed_ie_len(2), Some(8)); // IMSI
    assert_eq!(ng::v1_fixed_ie_len(16), Some(4)); // TEID Data I
    assert_eq!(ng::v1_fixed_ie_len(127), Some(4)); // Charging ID
    assert_eq!(ng::v1_fixed_ie_len(128), None); // End User Address is TLV
    assert_eq!(ng::v1_fixed_ie_len(131), None); // so is the APN
}

// ===========================================================================
// GTPv2-C
// ===========================================================================

#[test]
fn test_v2_header_bit_layout_matches_ts_29_274() {
    // TS 29.274 §5.1: Version=010, P=0, T=0 => 0x40. Echo never carries a TEID, so the
    // header is four octets plus sequence(3) + spare(1), and the Recovery IE is TLIV.
    let echo = ng::GtpV2Message {
        header: ng::GtpV2Header::without_teid(ng::V2_ECHO_RESPONSE, 0x00_0001),
        ies: vec![ng::GtpV2Ie::new(ng::V2_IE_RECOVERY, 0, vec![0x00])],
    };
    assert_eq!(
        echo.encode(),
        vec![
            0x40, // version 2, T=0
            0x02, // Echo Response
            0x00, 0x09, // length: 3 sequence + 1 spare + 5 IE octets
            0x00, 0x00, 0x01, // 24-bit sequence
            0x00, // spare / message priority
            0x03, 0x00, 0x01, 0x00, 0x00, // Recovery IE: type, length, instance, value
        ],
        "a GTPv2 Echo Response has no TEID and a three-octet sequence"
    );

    // With the T flag the TEID appears between the length and the sequence => 0x48.
    let response = ng::GtpV2Message {
        header: ng::GtpV2Header::new(ng::V2_CREATE_SESSION_RESPONSE, 0x3333_3333, 0x00_0002),
        ies: vec![ng::GtpV2Ie::new(ng::V2_IE_CAUSE, 0, vec![16, 0])],
    };
    assert_eq!(
        response.encode(),
        vec![
            0x48, // version 2, T=1
            0x21, // Create Session Response (33)
            0x00, 0x0E, // length: 4 TEID + 3 sequence + 1 spare + 6 IE octets
            0x33, 0x33, 0x33, 0x33, // TEID
            0x00, 0x00, 0x02, // sequence
            0x00, // spare
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00, // Cause IE = 16 (Request accepted)
        ]
    );

    let decoded = ng::GtpV2Message::decode(&response.encode()).expect("valid");
    assert_eq!(decoded.header.teid, Some(0x3333_3333));
    assert_eq!(decoded.header.sequence, 2);
    assert_eq!(decoded.find(ng::V2_IE_CAUSE), Some([16u8, 0].as_slice()));

    // A GTPv1 datagram must not decode as GTPv2 and vice versa.
    assert_eq!(
        ng::GtpV2Message::decode(&[0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 1, 0, 0]),
        Err(ng::DecodeError::BadVersion { version: 1 })
    );
}

#[test]
fn test_v2_instances_and_grouped_ies() {
    // Two F-TEIDs of the same type are told apart only by their instance number.
    let message = ng::GtpV2Message {
        header: ng::GtpV2Header::new(ng::V2_CREATE_SESSION_RESPONSE, 1, 1),
        ies: vec![
            ng::GtpV2Ie::new(ng::V2_IE_FTEID, 0, vec![0xAA]),
            ng::GtpV2Ie::new(ng::V2_IE_FTEID, 1, vec![0xBB]),
        ],
    };
    let decoded = ng::GtpV2Message::decode(&message.encode()).expect("valid");
    assert_eq!(
        decoded.find_instance(ng::V2_IE_FTEID, 1),
        Some([0xBB].as_slice()),
        "instance selects between two elements of the same type"
    );

    // Bearer Context is a grouped IE: its value is a whole IE sequence.
    let inner = vec![
        ng::GtpV2Ie::new(ng::V2_IE_EBI, 0, vec![5]),
        ng::GtpV2Ie::new(ng::V2_IE_CAUSE, 0, vec![16, 0]),
    ];
    let grouped = ng::encode_v2_grouped(&inner);
    assert_eq!(
        grouped,
        vec![
            0x49, 0x00, 0x01, 0x00, 0x05, // EBI (73)
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00, // Cause
        ]
    );
    assert_eq!(ng::parse_v2_grouped(&grouped).unwrap(), inner);
}

// ===========================================================================
// Subscriber identifiers, APNs and addresses
// ===========================================================================

#[test]
fn test_tbcd_apn_and_address_encodings() {
    // TBCD: two digits per octet, low nibble first, 0xF filler for an odd count.
    // "262011234567890" is 15 digits, so the last octet is F0.
    assert_eq!(
        ng::encode_tbcd("262011234567890"),
        vec![0x62, 0x02, 0x11, 0x32, 0x54, 0x76, 0x98, 0xF0],
        "IMSI digit pairs are swapped within each octet"
    );
    assert_eq!(
        ng::decode_tbcd(&[0x62, 0x02, 0x11, 0x32, 0x54, 0x76, 0x98, 0xF0]),
        "262011234567890"
    );
    // An even digit count needs no filler.
    assert_eq!(ng::encode_tbcd("1234"), vec![0x21, 0x43]);

    // APN labels: one length octet per dot-separated label, no root label.
    assert_eq!(
        ng::encode_apn("internet").unwrap(),
        vec![0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']
    );
    assert_eq!(
        ng::encode_apn("test.apn.epc").unwrap(),
        vec![0x04, b't', b'e', b's', b't', 0x03, b'a', b'p', b'n', 0x03, b'e', b'p', b'c']
    );
    assert_eq!(
        ng::decode_apn(&[0x03, b'i', b'm', b's', 0x03, b'g', b'p', b'r']).as_deref(),
        Some("ims.gpr")
    );
    // Labels that do not tile the buffer are not an APN.
    assert_eq!(ng::decode_apn(&[0x08, b'a']), None);

    // End User Address: spare nibble 1111, PDP Type Organisation 1 (IETF), type 0x21 (IPv4).
    let ue: IpAddr = "10.45.0.2".parse().unwrap();
    assert_eq!(
        ng::encode_end_user_address(Some(ue)),
        vec![0xF1, 0x21, 10, 45, 0, 2]
    );
    // The "assign me one" form a device sends: type only, no address.
    assert_eq!(ng::encode_end_user_address(None), vec![0xF1, 0x21]);
    let (pdp_type, addr) = ng::decode_end_user_address(&[0xF1, 0x21, 10, 45, 0, 2]);
    assert_eq!(pdp_type, "IPv4");
    assert_eq!(addr, Some(ue));
    assert_eq!(ng::decode_end_user_address(&[0xF1, 0x21]).1, None);

    // GTPv2 PDN Address Allocation: PDN type 1 is IPv4.
    assert_eq!(ng::encode_paa(ue), vec![0x01, 10, 45, 0, 2]);
    assert_eq!(ng::decode_paa(&[0x01, 10, 45, 0, 2]), ("IPv4", Some(ue)));

    // F-TEID: V4 flag 0x80 OR'd with the six-bit interface type, then TEID, then address.
    assert_eq!(
        ng::encode_fteid(7, 0x1234_5678, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        vec![0x87, 0x12, 0x34, 0x56, 0x78, 127, 0, 0, 1]
    );
    assert_eq!(
        ng::decode_fteid(&[0x87, 0x12, 0x34, 0x56, 0x78, 127, 0, 0, 1]),
        Some((7, 0x1234_5678, Some(IpAddr::V4(Ipv4Addr::LOCALHOST))))
    );

    // Protocol Configuration Options: extension bit set, PPP, then the DNS containers.
    assert_eq!(
        ng::encode_pco_dns(&["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()]),
        vec![0x80, 0x00, 0x0D, 0x04, 8, 8, 8, 8, 0x00, 0x0D, 0x04, 1, 1, 1, 1]
    );
}

// ===========================================================================
// The inner packet of a G-PDU
// ===========================================================================

#[test]
fn test_inner_ip_header_is_decoded_into_fields() {
    // A 29-octet IPv4/UDP datagram: 10.45.0.2:40000 -> 1.1.1.1:53, one octet of payload.
    let packet: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1D, // version 4, IHL 5, total length 29
        0x00, 0x02, 0x00, 0x00, // id, flags
        0x40, 0x11, 0x00, 0x00, // TTL 64, protocol 17 (UDP), checksum
        10, 45, 0, 2, // source
        1, 1, 1, 1, // destination
        0x9C, 0x40, // source port 40000
        0x00, 0x35, // destination port 53
        0x00, 0x09, 0x00, 0x00, // UDP length 9, checksum
        0x71, // payload
    ];

    let inner = ng::decode_inner_ip(&packet).expect("a well-formed IPv4 packet");
    assert_eq!(inner.version, 4);
    assert_eq!(inner.source.to_string(), "10.45.0.2");
    assert_eq!(inner.destination.to_string(), "1.1.1.1");
    assert_eq!(inner.protocol, 17);
    assert_eq!(inner.protocol_name, "UDP");
    assert_eq!(inner.ttl, 64);
    assert_eq!(inner.length, 29);
    assert_eq!(inner.source_port, Some(40000));
    assert_eq!(inner.destination_port, Some(53));
    assert_eq!(inner.payload_offset, Some(28));

    // Anything that is not IP is reported as such rather than mis-parsed.
    assert!(ng::decode_inner_ip(&[0x00, 0x01, 0x02]).is_none());
    assert!(ng::decode_inner_ip(&[]).is_none());
}

// ===========================================================================
// Causes
// ===========================================================================

#[test]
fn test_cause_table_and_the_acceptance_boundary() {
    // TS 29.060 §7.7.1 puts acceptance at 128-191 and refusal at 192-255; TS 29.274 §8.4
    // puts acceptance at 16-63 and refusal at 64-255. The fail-closed rule depends on these
    // boundaries being right in both directions.
    assert!(ng::cause_accepts(ng::GtpVersion::V1, 128));
    assert!(!ng::cause_accepts(ng::GtpVersion::V1, 199));
    assert!(!ng::cause_accepts(ng::GtpVersion::V1, 204));
    assert!(ng::cause_accepts(ng::GtpVersion::V2, 16));
    assert!(!ng::cause_accepts(ng::GtpVersion::V2, 73));
    assert!(!ng::cause_accepts(ng::GtpVersion::V2, 72));

    let accepted = ng::cause_by_name("request_accepted").expect("known cause");
    assert_eq!((accepted.v1, accepted.v2), (128, 16));
    assert!(accepted.accepts);

    // The two causes the fail-closed path uses must never be acceptances, in either version.
    for name in ["no_resources_available", "system_failure"] {
        let cause = ng::cause_by_name(name).expect("known cause");
        assert!(!cause.accepts, "{name} must not accept");
        assert!(!ng::cause_accepts(ng::GtpVersion::V1, cause.v1));
        assert!(!ng::cause_accepts(ng::GtpVersion::V2, cause.v2));
    }

    // Spellings a model actually produces.
    assert_eq!(
        ng::cause_by_name("Request accepted").map(|c| c.v1),
        Some(128)
    );
    assert_eq!(
        ng::cause_by_name("MISSING-OR-UNKNOWN-APN").map(|c| c.v2),
        Some(77)
    );
    assert!(ng::cause_by_name("probably fine").is_none());

    // No two names may share a code, in either version, or a refusal could be reported as
    // the wrong refusal.
    let mut v1: Vec<u8> = ng::CAUSES.iter().map(|c| c.v1).collect();
    v1.sort_unstable();
    let before = v1.len();
    v1.dedup();
    assert_eq!(before, v1.len(), "duplicate GTPv1 cause code in the table");
    let mut v2: Vec<u8> = ng::CAUSES.iter().map(|c| c.v2).collect();
    v2.sort_unstable();
    let before = v2.len();
    v2.dedup();
    assert_eq!(before, v2.len(), "duplicate GTPv2 cause code in the table");
}
