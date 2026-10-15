//! EAPOL / EAP codec against literal specification bytes.
//!
//! **Round-tripping an encoder through its own decoder proves nothing** — the root
//! `CLAUDE.md` names that failure explicitly, and `rss` sat at Experimental for months
//! because its test parsed the server's XML with the same crate that wrote it. So every
//! literal below is derived from the specification field by field, in the comment above it,
//! and both directions are asserted against *that*: `decode(LITERAL)` must yield the fields,
//! and `encode(fields)` must yield the literal. Neither direction is allowed to define the
//! other.
//!
//! MD5 comes from the `md-5` crate, so the RFC 1321 §A.5 vectors here are not testing an
//! implementation of ours — they are testing that `codec.rs` *drives* one correctly, which is
//! still a thing that breaks. They were kept for exactly that reason when the hand-rolled
//! version was removed.
//!
//! Layouts used throughout:
//!
//! ```text
//! EAPOL  (IEEE 802.1X-2004 §11.3):  version(1) | packet type(1) | body length(2) | body
//! EAP    (RFC 3748 §4):             code(1)    | identifier(1)  | length(2)      | [type(1) | data]
//! ```
//!
//! `length` in an EAP packet covers the *whole* packet including its four-octet header, which
//! is the field everyone gets wrong first.

#![cfg(all(unix, feature = "libpcap"))]

use netget::server::eapol::codec::{self, CodecError, EapPacket, EapolFrame};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace([' ', '\n'], "")).expect("test literal is not valid hex")
}

// ===========================================================================
// EAPOL-Start
// ===========================================================================

/// `02` version 2 (802.1X-2004) · `01` EAPOL-Start · `0000` body length zero.
///
/// An EAPOL-Start has no body at all: the packet *is* the request.
const EAPOL_START_V2: &str = "02 01 0000";

/// The same PDU as an 802.1X-2001 supplicant sends it. Version is the only difference, and
/// plenty of real supplicants still emit 1.
const EAPOL_START_V1: &str = "01 01 0000";

#[test]
fn decodes_an_eapol_start() {
    let frame = EapolFrame::decode(&unhex(EAPOL_START_V2)).expect("must decode");
    assert_eq!(frame.version, 2);
    assert_eq!(frame.packet_type, codec::EAPOL_TYPE_START);
    assert!(frame.body.is_empty(), "EAPOL-Start carries no body");
}

#[test]
fn encodes_an_eapol_start_byte_for_byte() {
    assert_eq!(codec::eapol_start_frame(1), unhex(EAPOL_START_V1));
    assert_eq!(codec::eapol_start_frame(2), unhex(EAPOL_START_V2));
}

/// `02` version 2 · `02` EAPOL-Logoff · `0000` no body.
const EAPOL_LOGOFF_V2: &str = "02 02 0000";

#[test]
fn encodes_and_decodes_an_eapol_logoff() {
    assert_eq!(codec::eapol_logoff_frame(2), unhex(EAPOL_LOGOFF_V2));
    let frame = EapolFrame::decode(&unhex(EAPOL_LOGOFF_V2)).unwrap();
    assert_eq!(frame.packet_type, codec::EAPOL_TYPE_LOGOFF);
}

// ===========================================================================
// EAP-Request/Identity — the frame every 802.1X capture opens with
// ===========================================================================

/// `01` version 1 · `00` EAP-Packet · `0005` body is five octets
/// · `01` EAP Request · `01` identifier 1 · `0005` EAP length five · `01` type Identity.
///
/// Five octets is the shortest legal Request: the four-octet EAP header plus one type octet,
/// with no prompt.
const REQUEST_IDENTITY: &str = "01 00 0005 01 01 0005 01";

#[test]
fn decodes_an_eap_request_identity() {
    let frame = EapolFrame::decode(&unhex(REQUEST_IDENTITY)).unwrap();
    assert_eq!(frame.version, 1);
    assert_eq!(frame.packet_type, codec::EAPOL_TYPE_EAP_PACKET);
    assert_eq!(frame.body.len(), 5);

    let eap = EapPacket::decode(&frame.body).unwrap();
    assert_eq!(eap.code, codec::EAP_CODE_REQUEST);
    assert_eq!(eap.identifier, 1);
    assert_eq!(eap.eap_type, Some(codec::EAP_TYPE_IDENTITY));
    assert!(eap.type_data.is_empty());
}

#[test]
fn encodes_an_eap_request_identity_byte_for_byte() {
    let eap = codec::eap_request_identity(1);
    assert_eq!(
        codec::eapol_wrap_eap(1, &eap).unwrap(),
        unhex(REQUEST_IDENTITY),
        "EAP-Request/Identity must match the frame on the wire exactly"
    );
}

// ===========================================================================
// EAP-Response/Identity
// ===========================================================================

/// `01` version 1 · `00` EAP-Packet · `000a` body is ten octets
/// · `02` EAP Response · `01` identifier 1 (echoing the Request above) · `000a` EAP length ten
/// · `01` type Identity · `616c696365` "alice".
///
/// Ten = 4 header + 1 type + 5 identity octets.
const RESPONSE_IDENTITY: &str = "01 00 000a 02 01 000a 01 616c696365";

#[test]
fn decodes_an_eap_response_identity() {
    let frame = EapolFrame::decode(&unhex(RESPONSE_IDENTITY)).unwrap();
    let eap = EapPacket::decode(&frame.body).unwrap();

    assert_eq!(eap.code, codec::EAP_CODE_RESPONSE);
    assert_eq!(
        eap.identifier, 1,
        "the Response echoes the Request's identifier; a mismatch makes a supplicant \
         silently discard the frame, which looks exactly like a hang"
    );
    assert_eq!(eap.eap_type, Some(codec::EAP_TYPE_IDENTITY));
    assert_eq!(String::from_utf8(eap.type_data).unwrap(), "alice");
}

#[test]
fn encodes_an_eap_response_identity_byte_for_byte() {
    let eap = codec::eap_response_identity(1, "alice").unwrap();
    assert_eq!(
        codec::eapol_wrap_eap(1, &eap).unwrap(),
        unhex(RESPONSE_IDENTITY)
    );
}

// ===========================================================================
// The two terminal frames — the whole point of the protocol
// ===========================================================================

/// `02` version 2 · `00` EAP-Packet · `0004` body is four octets
/// · `03` EAP **Success** · `05` identifier 5 · `0004` EAP length four.
///
/// RFC 3748 §4.2: a Success has no type octet and is exactly four octets. This is the frame
/// that opens a switch port.
const EAP_SUCCESS_ID5: &str = "02 00 0004 03 05 0004";

/// The same frame with `04` — Failure — in the code octet. Everything else is identical,
/// which is exactly why `codec.rs` refuses to build them with a shared function.
const EAP_FAILURE_ID5: &str = "02 00 0004 04 05 0004";

#[test]
fn encodes_eap_success_byte_for_byte() {
    assert_eq!(
        codec::eapol_eap_success_frame(2, 5),
        unhex(EAP_SUCCESS_ID5),
        "the admission frame must be exactly what 802.1X specifies"
    );
}

#[test]
fn encodes_eap_failure_byte_for_byte() {
    assert_eq!(codec::eapol_eap_failure_frame(2, 5), unhex(EAP_FAILURE_ID5));
}

/// The two differ in exactly one octet, and it is the code. Stated as a test because it is
/// the property a reader most wants confirmed: nothing else about the frames encodes the
/// decision, so nothing else can leak it.
#[test]
fn success_and_failure_differ_only_in_the_code_octet() {
    let success = codec::eapol_eap_success_frame(2, 5);
    let failure = codec::eapol_eap_failure_frame(2, 5);

    assert_eq!(success.len(), failure.len());
    let differing: Vec<usize> = (0..success.len())
        .filter(|&i| success[i] != failure[i])
        .collect();
    assert_eq!(differing, vec![4], "only the EAP code octet may differ");
    assert_eq!(success[4], codec::EAP_CODE_SUCCESS);
    assert_eq!(failure[4], codec::EAP_CODE_FAILURE);
}

/// The identifier really is carried through. RFC 3748 §4.2 requires a Success or Failure to
/// echo the Response it answers, and a supplicant discards a mismatch in silence.
#[test]
fn terminal_frames_carry_the_identifier_they_are_given() {
    for id in [0u8, 1, 42, 255] {
        assert_eq!(codec::eapol_eap_success_frame(2, id)[5], id);
        assert_eq!(codec::eapol_eap_failure_frame(2, id)[5], id);
    }
}

#[test]
fn decodes_a_success_and_a_failure() {
    let success = EapPacket::decode(&EapolFrame::decode(&unhex(EAP_SUCCESS_ID5)).unwrap().body)
        .expect("must decode");
    assert_eq!(success.code, codec::EAP_CODE_SUCCESS);
    assert_eq!(success.identifier, 5);
    assert_eq!(success.eap_type, None, "a Success has no type octet");

    let failure = EapPacket::decode(&EapolFrame::decode(&unhex(EAP_FAILURE_ID5)).unwrap().body)
        .expect("must decode");
    assert_eq!(failure.code, codec::EAP_CODE_FAILURE);
    assert_eq!(failure.identifier, 5);
}

// ===========================================================================
// EAP-Request/MD5-Challenge and its response
// ===========================================================================

/// `02` version 2 · `00` EAP-Packet · `001c` body 28 octets
/// · `01` Request · `02` identifier 2 · `001c` EAP length 28 · `04` type MD5-Challenge
/// · `10` value-size 16 · `1011…1f` the 16-octet challenge · `6e6574676574` name "netget".
///
/// 28 = 4 header + 1 type + 1 value-size + 16 challenge + 6 name. The value layout is
/// RFC 1994 §4.1, which EAP-MD5 (RFC 3748 §5.4) adopts verbatim.
const REQUEST_MD5: &str =
    "02 00 001c 01 02 001c 04 10 101112131415161718191a1b1c1d1e1f 6e6574676574";

const MD5_CHALLENGE: &str = "101112131415161718191a1b1c1d1e1f";

/// `02` version 2 · `00` EAP-Packet · `001b` body 27 octets
/// · `02` Response · `02` identifier 2 (echoed) · `001b` length 27 · `04` MD5-Challenge
/// · `10` value-size 16 · the digest · `616c696365` name "alice".
///
/// The digest is `MD5(0x02 || "hunter2" || challenge)` — RFC 1994 §2.2 — computed with
/// Python's `hashlib`, an implementation unrelated to this tree.
const RESPONSE_MD5: &str =
    "02 00 001b 02 02 001b 04 10 801f5f3dc4b0e73b2e69795f6ab89bdc 616c696365";

const EXPECTED_DIGEST: &str = "801f5f3dc4b0e73b2e69795f6ab89bdc";

#[test]
fn encodes_an_md5_challenge_request_byte_for_byte() {
    let eap = codec::eap_request_md5_challenge(2, &unhex(MD5_CHALLENGE), "netget").unwrap();
    assert_eq!(codec::eapol_wrap_eap(2, &eap).unwrap(), unhex(REQUEST_MD5));
}

#[test]
fn decodes_an_md5_challenge_response() {
    let frame = EapolFrame::decode(&unhex(RESPONSE_MD5)).unwrap();
    let eap = EapPacket::decode(&frame.body).unwrap();
    assert_eq!(eap.code, codec::EAP_CODE_RESPONSE);
    assert_eq!(eap.identifier, 2);
    assert_eq!(eap.eap_type, Some(codec::EAP_TYPE_MD5_CHALLENGE));

    let (value, name) = codec::decode_md5_value(&eap.type_data).unwrap();
    assert_eq!(hex::encode(&value), EXPECTED_DIGEST);
    assert_eq!(name, "alice");
}

/// The digest itself, against the Python-computed literal. If the concatenation order is
/// wrong — `secret || identifier || challenge` is the classic slip — this is what catches it,
/// and it is the difference between rejecting every real supplicant and accepting them.
#[test]
fn computes_the_rfc_1994_md5_challenge_digest() {
    let digest = codec::md5_challenge_digest(2, "hunter2", &unhex(MD5_CHALLENGE));
    assert_eq!(hex::encode(digest), EXPECTED_DIGEST);
}

#[test]
fn md5_verification_accepts_only_the_right_password() {
    let challenge = unhex(MD5_CHALLENGE);
    let response = unhex(EXPECTED_DIGEST);

    assert!(codec::md5_response_matches(
        2, "hunter2", &challenge, &response
    ));

    assert!(
        !codec::md5_response_matches(2, "hunter3", &challenge, &response),
        "a different password must not verify"
    );
    assert!(
        !codec::md5_response_matches(3, "hunter2", &challenge, &response),
        "the identifier is part of the digest, so a replay under another identifier fails"
    );
    assert!(
        !codec::md5_response_matches(
            2,
            "hunter2",
            &unhex("00000000000000000000000000000000"),
            &response
        ),
        "a different challenge must not verify"
    );
    assert!(
        !codec::md5_response_matches(2, "hunter2", &challenge, &[]),
        "an empty response must not verify"
    );
    assert!(
        !codec::md5_response_matches(2, "hunter2", &challenge, &response[..15]),
        "a truncated response must not verify"
    );
}

/// RFC 1321 §A.5 publishes these seven digests, written by the IETF rather than by anything in
/// this repository.
///
/// MD5 itself is the `md-5` crate's, so this no longer guards an implementation of ours. It
/// still guards our *use* of one, which is where the live mistakes are: a wrapper that feeds
/// the hasher the wrong buffer, drops an update, or returns the digest with the wrong
/// endianness would pass every other test in this file and fail here.
#[test]
fn md5_matches_the_rfc_1321_test_suite() {
    let vectors: &[(&str, &str)] = &[
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(
            hex::encode(codec::md5(input.as_bytes())),
            *expected,
            "RFC 1321 §A.5 digest of {:?}",
            input
        );
    }
}

/// A message that straddles the 56-octet padding boundary exercises the two-block path, which
/// the short §A.5 vectors mostly do not.
#[test]
fn md5_handles_the_padding_boundary() {
    // 55, 56, 57 and 64 octets: the last chunk that fits its length field, the first that
    // does not, and an exact block. Digests from Python hashlib.
    let cases: &[(usize, &str)] = &[
        (55, "ef1772b6dff9a122358552954ad0df65"),
        (56, "3b0c8ac703f828b04c6c197006d17218"),
        (57, "652b906d60af96844ebd21b674f35e93"),
        (64, "014842d480b571495a4a0363793f7367"),
    ];
    for (len, expected) in cases {
        let input = vec![b'a'; *len];
        assert_eq!(
            hex::encode(codec::md5(&input)),
            *expected,
            "MD5 of {} 'a' octets",
            len
        );
    }
}

// ===========================================================================
// Ethernet framing
// ===========================================================================

/// `0180c2000003` the PAE group address (802.1X-2004 Table 7-2) · `020000000001` a locally
/// administered source MAC · `888e` the EAPOL EtherType · the EAPOL-Start above · zero pad
/// to the 60-octet Ethernet minimum.
#[test]
fn builds_an_ethernet_frame_with_the_pae_group_address() {
    let payload = codec::eapol_start_frame(2);
    let frame = codec::build_ethernet_frame(
        codec::PAE_GROUP_ADDRESS,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        codec::ETHERTYPE_EAPOL,
        &payload,
    );

    assert_eq!(
        frame.len(),
        60,
        "an Ethernet frame is padded to 60 octets before the FCS"
    );
    assert_eq!(&frame[0..6], &codec::PAE_GROUP_ADDRESS);
    assert_eq!(&frame[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&frame[12..14], &[0x88, 0x8e]);
    assert_eq!(&frame[14..18], &payload[..]);
    assert!(
        frame[18..].iter().all(|b| *b == 0),
        "the pad must be zero, and the EAPOL length field is what makes it ignorable"
    );

    let parsed = codec::parse_ethernet_frame(&frame).unwrap();
    assert_eq!(parsed.destination, codec::PAE_GROUP_ADDRESS);
    assert_eq!(parsed.ethertype, codec::ETHERTYPE_EAPOL);
}

/// The pad is the reason `EapolFrame::decode` must not require the buffer to end where the
/// body does. A strict equality check here would reject every real frame on the wire.
#[test]
fn decoding_ignores_ethernet_padding() {
    let mut padded = unhex(EAPOL_START_V2);
    padded.resize(46, 0); // 60-octet frame minus the 14-octet header
    let frame = EapolFrame::decode(&padded).expect("padding must not break decoding");
    assert_eq!(frame.packet_type, codec::EAPOL_TYPE_START);
    assert!(frame.body.is_empty());
}

#[test]
fn formats_and_parses_mac_addresses() {
    let mac = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];
    assert_eq!(codec::format_mac(&mac), "01:80:c2:00:00:03");
    assert_eq!(codec::parse_mac("01:80:C2:00:00:03").unwrap(), mac);
    assert_eq!(codec::parse_mac("01-80-c2-00-00-03").unwrap(), mac);
    assert_eq!(codec::parse_mac("0180c2000003").unwrap(), mac);
    assert!(matches!(
        codec::parse_mac("01:80:c2:00:00"),
        Err(CodecError::BadMac(_))
    ));
    assert!(matches!(
        codec::parse_mac("zz:80:c2:00:00:03"),
        Err(CodecError::BadMac(_))
    ));
}

// ===========================================================================
// Refusals
// ===========================================================================

#[test]
fn rejects_a_truncated_eapol_header() {
    assert!(matches!(
        EapolFrame::decode(&unhex("0201")),
        Err(CodecError::TooShort { .. })
    ));
}

#[test]
fn rejects_an_unsupported_eapol_version() {
    assert!(matches!(
        EapolFrame::decode(&unhex("00 01 0000")),
        Err(CodecError::UnsupportedVersion(0))
    ));
    assert!(matches!(
        EapolFrame::decode(&unhex("04 01 0000")),
        Err(CodecError::UnsupportedVersion(4))
    ));
}

#[test]
fn rejects_a_body_longer_than_the_buffer() {
    // Declares 32 octets of body and supplies none.
    assert!(matches!(
        EapolFrame::decode(&unhex("02 00 0020")),
        Err(CodecError::BadLength { .. })
    ));
}

/// A Success or Failure that is not exactly four octets is malformed. This matters more than
/// it looks: a five-octet "Success" with a trailing byte is the shape a sloppy parser would
/// accept, and accepting it means accepting a frame nobody specified.
#[test]
fn rejects_a_success_that_is_not_four_octets() {
    assert!(matches!(
        EapPacket::decode(&unhex("03 05 0005 01")),
        Err(CodecError::MalformedEap(_))
    ));
}

#[test]
fn rejects_a_request_with_no_type_octet() {
    assert!(matches!(
        EapPacket::decode(&unhex("01 01 0004")),
        Err(CodecError::MalformedEap(_))
    ));
}

#[test]
fn rejects_an_unknown_eap_code() {
    assert!(matches!(
        EapPacket::decode(&unhex("07 01 0004")),
        Err(CodecError::MalformedEap(_))
    ));
}

#[test]
fn rejects_an_eap_length_below_the_header() {
    assert!(matches!(
        EapPacket::decode(&unhex("01 01 0002 01")),
        Err(CodecError::BadLength { .. })
    ));
}

#[test]
fn rejects_an_md5_value_longer_than_its_field() {
    assert!(matches!(
        codec::decode_md5_value(&unhex("20 0102")),
        Err(CodecError::BadLength { .. })
    ));
    assert!(matches!(
        codec::decode_md5_value(&[]),
        Err(CodecError::TooShort { .. })
    ));
}

// ===========================================================================
// Method payload details
// ===========================================================================

/// EAP-TLS/PEAP flags, RFC 5216 §3.1: `L` 0x80 length included, `M` 0x40 more fragments,
/// `S` 0x20 start.
#[test]
fn reads_tls_flags() {
    assert_eq!(codec::tls_flags(&[0x20]), Some((false, false, true)));
    assert_eq!(codec::tls_flags(&[0xc0]), Some((true, true, false)));
    assert_eq!(codec::tls_flags(&[0x00]), Some((false, false, false)));
    assert_eq!(codec::tls_flags(&[]), None);
}

/// `02` version 2 · `00` EAP-Packet · `0006` body six · `01` Request · `03` identifier 3
/// · `0006` length six · `0d` type 13 EAP-TLS · `20` the Start flag.
#[test]
fn encodes_an_eap_tls_start_byte_for_byte() {
    let eap = codec::eap_request_tls_start(3, codec::EAP_TYPE_TLS).unwrap();
    assert_eq!(
        codec::eapol_wrap_eap(2, &eap).unwrap(),
        unhex("02 00 0006 01 03 0006 0d 20")
    );
}

/// `02` version 2 · `00` EAP-Packet · `000e` body 14 · `01` Request · `04` identifier 4
/// · `000e` length 14 · `02` type Notification · `4e6f7420746f646179` "Not today".
///
/// 14 = 4 header + 1 type + 9 text octets.
#[test]
fn encodes_an_eap_notification_byte_for_byte() {
    let eap = codec::eap_request_notification(4, "Not today").unwrap();
    assert_eq!(
        codec::eapol_wrap_eap(2, &eap).unwrap(),
        unhex("02 00 000e 01 04 000e 02 4e6f7420746f646179")
    );
}

#[test]
fn names_the_types_the_events_report() {
    assert_eq!(codec::eap_type_name(codec::EAP_TYPE_IDENTITY), "identity");
    assert_eq!(codec::eap_type_name(codec::EAP_TYPE_NAK), "nak");
    assert_eq!(
        codec::eap_type_name(codec::EAP_TYPE_MD5_CHALLENGE),
        "md5-challenge"
    );
    assert_eq!(codec::eap_type_name(codec::EAP_TYPE_PEAP), "peap");
    assert_eq!(codec::eap_type_name(200), "unknown");
    assert_eq!(codec::eap_code_name(codec::EAP_CODE_SUCCESS), "EAP-Success");
    assert_eq!(
        codec::eapol_packet_type_name(codec::EAPOL_TYPE_KEY),
        "EAPOL-Key"
    );
}
