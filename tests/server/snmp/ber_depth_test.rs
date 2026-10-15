//! A hostile SNMP datagram must be rejected, not crash the process.
//!
//! BER lets an OCTET STRING be *constructed*: its contents are themselves a series of
//! OCTET STRINGs, which may in turn be constructed. `rasn` 0.18's
//! `ber::de::parser::parse_encoded_value` walks that nesting by calling itself, with no
//! depth counter, so nesting depth is bounded only by the datagram size. Two bytes buy one
//! level (`24 80`, constructed OCTET STRING, indefinite length), so a single 64 KB UDP
//! datagram — the largest one a socket can deliver, and unauthenticated — reaches roughly
//! 32000 frames.
//!
//! Rust does not unwind a stack overflow: it is `SIGSEGV`/`SIGABRT` from the guard page, so
//! `tokio::spawn` cannot contain it, `catch_unwind` cannot see it, and the whole netget
//! process dies. That makes this a remote kill switch for everything else the process is
//! serving, not merely an SNMP fault.
//!
//! `parse_snmp_message` therefore screens the datagram's TLV structure before rasn sees it.


use netget::server::snmp::SnmpServer;

/// `version` (INTEGER 1) followed by a `community` OCTET STRING nested `depth` levels deep,
/// wrapped in the outer Message SEQUENCE.
///
/// Every level is `24 80` — constructed OCTET STRING, indefinite length — and the matching
/// end-of-contents markers are simply left off. That is what makes the attack cheap: the
/// decoder descends on `while !input.is_empty()`, so it recurses all the way down before it
/// discovers there is no EOC to close anything, and one level costs **two** bytes rather than
/// four. A 64 KB datagram therefore buys ~32000 frames.
fn nested_community_message(depth: usize) -> Vec<u8> {
    let mut msg = vec![0x30, 0x80]; // SEQUENCE, indefinite
    msg.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER version = 1 (v2c)
    for _ in 0..depth {
        msg.extend_from_slice(&[0x24, 0x80]); // constructed OCTET STRING, indefinite
    }
    msg
}

#[test]
fn deeply_nested_ber_is_rejected_not_fatal() {
    // Comfortably past any legitimate SNMP message and past the depth at which the
    // recursive decoder exhausts a 2 MB tokio worker stack.
    let payload = nested_community_message(30_000);
    assert!(
        payload.len() <= 65_507,
        "payload must fit in one UDP datagram, was {} bytes",
        payload.len()
    );

    // The assertion is that this returns at all. A depth-unbounded decoder never gets here.
    let result = SnmpServer::parse_snmp_message(&payload);
    assert!(
        result.is_err(),
        "a 30000-deep BER nesting must be rejected, not parsed"
    );
}

#[test]
fn a_length_reaching_past_the_datagram_is_rejected() {
    // The other half of the same mistake: trusting the length the peer declared. `84 7F FF FF
    // FF` announces a 2 GB element inside a nine-byte datagram. Nothing here allocates on that
    // number today, but the screen bounds it against the datagram's real size rather than
    // against whatever bytes happen to be left, which is the check that keeps being got wrong.
    let payload: Vec<u8> = vec![0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x01];
    assert!(
        SnmpServer::parse_snmp_message(&payload).is_err(),
        "an element declaring more bytes than the datagram holds must be rejected"
    );
}

#[test]
fn definite_length_nesting_is_bounded_too() {
    // Indefinite lengths are the cheapest way in, not the only one. Nested definite-length
    // constructed OCTET STRINGs reach the same recursion by a different route.
    let mut inner = vec![0x04, 0x00]; // empty primitive OCTET STRING
    for _ in 0..40 {
        let len = inner.len();
        assert!(
            len < 0x80,
            "keep the short length form for a compact payload"
        );
        let mut wrapped = vec![0x24, len as u8];
        wrapped.extend_from_slice(&inner);
        inner = wrapped;
    }
    let mut payload = vec![0x30, 0x80, 0x02, 0x01, 0x01];
    payload.extend_from_slice(&inner);
    payload.extend_from_slice(&[0x00, 0x00]);

    assert!(
        SnmpServer::parse_snmp_message(&payload).is_err(),
        "definite-length nesting must be bounded by the same screen"
    );
}

#[test]
fn a_real_snmp_get_still_parses() {
    // SNMPv2c GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0 — the shape the depth
    // screen must not reject. Nesting here is 4 levels (Message > PDU > VarBindList >
    // VarBind), which is what every real SNMP message looks like.
    let payload: Vec<u8> = vec![
        0x30, 0x29, // SEQUENCE, 41 bytes
        0x02, 0x01, 0x01, // INTEGER version 1 (v2c)
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // OCTET STRING "public"
        0xA0, 0x1C, // GetRequest PDU, 28 bytes
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // request-id
        0x02, 0x01, 0x00, // error-status 0
        0x02, 0x01, 0x00, // error-index 0
        0x30, 0x0E, // VarBindList SEQUENCE, 14 bytes
        0x30, 0x0C, // VarBind SEQUENCE, 12 bytes
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID
        0x05, 0x00, // NULL
    ];

    let parsed = SnmpServer::parse_snmp_message(&payload).expect("a real GetRequest must parse");
    assert_eq!(parsed.request_type, "GetRequest");
    assert_eq!(parsed.request_id, 0x12345678);
    assert_eq!(parsed.community, b"public".to_vec());
    assert_eq!(parsed.requested_oids, vec!["1.3.6.1.2.1.1.1.0".to_string()]);
}
