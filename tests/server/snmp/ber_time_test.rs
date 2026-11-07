//! A BER GeneralizedTime whose characters are not ASCII must be a decode error, not a panic.
//!
//! `18 06 c3 a9 2b 30 30 30` is a GeneralizedTime (tag 0x18) of six bytes, "é+000": a two-byte
//! UTF-8 character followed by a time-zone offset. `rasn` 0.18's
//! `parse_any_generalized_time_string` checked `chars().nth(len - 5)` and then sliced at *byte*
//! `len - 5`, which falls inside the `é`, so the decode panicked on a char boundary. `rasn` 0.26
//! and later parse the bytes and return `Err`.
//!
//! No SNMP type carries a GeneralizedTime, so a datagram cannot reach this parser through
//! `SnmpServer::parse_snmp_message` today; the test holds the linked `rasn` to it directly, so
//! that an SMI module adding one, or a downgrade, cannot bring the panic back unnoticed. A
//! panic there would be inside a socket task, where `tokio::spawn` swallows it.

use netget::server::snmp::SnmpServer;

const NON_ASCII_GENERALIZED_TIME: [u8; 8] = [0x18, 0x06, 0xc3, 0xa9, 0x2b, 0x30, 0x30, 0x30];

#[test]
fn a_non_ascii_generalized_time_is_an_error_not_a_panic() {
    let outcome = std::panic::catch_unwind(|| {
        rasn::ber::decode::<rasn::types::GeneralizedTime>(&NON_ASCII_GENERALIZED_TIME)
    });
    match outcome {
        Err(_) => panic!("rasn::ber::decode panicked on a non-ASCII GeneralizedTime"),
        Ok(Ok(time)) => panic!("a non-ASCII GeneralizedTime decoded as {time:?}"),
        Ok(Err(_)) => {}
    }
}

/// The same bytes as an SNMP datagram, through NetGet's own decode path: refused, no panic.
#[test]
fn the_same_bytes_as_a_datagram_are_refused() {
    let outcome =
        std::panic::catch_unwind(|| SnmpServer::parse_snmp_message(&NON_ASCII_GENERALIZED_TIME));
    assert!(
        matches!(outcome, Ok(Err(_))),
        "parse_snmp_message must refuse the bytes without panicking"
    );
}
