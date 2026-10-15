//! Pure HSRP codec tests — no socket, no LLM, no `AppState`.
//!
//! `e2e_test.rs` already pins both wire layouts byte for byte through a running server. What
//! lives here is the part that needs no server at all: the treatment of the **plaintext
//! authentication field**, which is the one place in HSRP where a string crosses between the
//! wire, the model and a log line.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features hsrp \
//!       --test server hsrp::codec_test -- --test-threads=100

use netget::server::hsrp::codec::{
    self, HsrpMessage, HsrpState, HsrpVersion, Opcode, AUTH_FIELD_LEN,
};
use std::net::{IpAddr, Ipv4Addr};

/// A plain v1 Hello, with the authentication field left for each test to set.
fn hello_v1(auth: Option<&str>) -> HsrpMessage {
    HsrpMessage {
        version: HsrpVersion::V1,
        opcode: Opcode::Hello,
        state: HsrpState::Standby,
        hellotime_secs: 3,
        holdtime_secs: 10,
        priority: 100,
        group: 1,
        auth_data: auth.map(str::to_string),
        virtual_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        identifier: [0u8; 6],
        md5_auth: None,
    }
}

/// A control character in a model-authored `auth_data` is refused, not encoded.
///
/// The field is a plaintext group password that every peer prints back in its diagnostics, and
/// that this server's own event template renders as `... auth={auth_data}, from={source_address}`
/// with no quoting. A newline there forges a log line. Refusing is the right exit on this side:
/// the model wrote the string and can be told.
#[test]
fn a_control_character_in_auth_data_is_refused() {
    for bad in ["ci\nsco", "ci\0sco", "cisco\r"] {
        let err = codec::encode(&hello_v1(Some(bad)))
            .expect_err("a control character in the auth field must be refused")
            .to_string();
        assert!(
            err.contains("control character"),
            "the error must say what is wrong, got: {err}"
        );
    }

    // The Cisco default still encodes, so the check is a bound and not a blanket refusal.
    let packet = codec::encode(&hello_v1(Some(codec::DEFAULT_AUTH_DATA))).expect("'cisco' encodes");
    assert_eq!(&packet[8..16], b"cisco\0\0\0");
}

/// A hostile neighbour's authentication field cannot forge a log line.
///
/// Built by hand, because the encoder now refuses these octets — encoding them would test
/// nothing. RFC 2281 puts no constraint on the eight bytes, so this is a packet a real peer can
/// send, and the field is reported to the model and rendered into the event's own debug line.
#[test]
fn a_neighbours_control_characters_in_auth_data_cannot_forge_a_log_line() {
    let mut packet = vec![0u8; codec::V1_LEN];
    packet[0] = codec::V1_VERSION_BYTE;
    packet[1] = Opcode::Hello.code();
    packet[2] = HsrpState::Active.v1_code();
    packet[3] = 3; // hellotime
    packet[4] = 10; // holdtime
    packet[5] = 200; // priority
    packet[6] = 1; // group
    packet[8..16].copy_from_slice(b"a\nb\rc\td\x07");
    packet[16..20].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());

    let decoded = codec::decode(&packet).expect("a hostile v1 packet is still well-formed HSRP");
    let auth = decoded.auth_data.expect("the field was not empty");
    assert!(
        !auth.chars().any(char::is_control),
        "auth_data reached the event still carrying a control character: {auth:?}. The event's \
         log template renders it unquoted as `auth={{auth_data}}`, so this forges a log line."
    );
    // Neutralised, not dropped: an operator still sees eight characters' worth of what arrived.
    assert_eq!(auth, "a b c d ");
    assert_eq!(auth.len(), AUTH_FIELD_LEN);
}

/// The field is NUL-terminated on the wire, and an all-NUL field is still reported as absent.
///
/// This is the boundary the sanitiser could plausibly have broken: a NUL is a control character,
/// so a naive "replace every control character with a space" applied before the NUL trim would
/// turn an empty field into eight spaces and make every packet look authenticated.
#[test]
fn an_empty_auth_field_is_still_absent_rather_than_eight_spaces() {
    let mut packet = vec![0u8; codec::V1_LEN];
    packet[1] = Opcode::Hello.code();
    packet[2] = HsrpState::Listen.v1_code();
    packet[16..20].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());

    let decoded = codec::decode(&packet).expect("decodes");
    assert_eq!(
        decoded.auth_data, None,
        "an all-zero authentication field means 'none', not a string of spaces"
    );
}
