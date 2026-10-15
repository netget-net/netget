//! Unprivileged evidence for the ICMP server: the bytes it puts on the wire, and what its
//! action executor accepts and refuses.
//!
//! `e2e_test.rs` is the only other ICMP server test and it is `#[ignore]`d behind raw-socket
//! privilege, so before this file **nothing about ICMP's packets ran in any ordinary test
//! run**. Everything here needs no socket and no privilege: `build_echo_reply` and its two
//! siblings are pure functions, and `execute_action` is a pure `serde_json::Value ->
//! ActionResult` mapping.
//!
//! Every packet is asserted field by field at its RFC 791 / RFC 792 offset, not against a
//! golden blob, so a failure names the field that moved. Both checksums are *verified* rather
//! than compared to a constant: a header whose ones' complement sum is not zero is one no peer
//! will accept, and that is the property, not any particular pair of bytes.
//!
//! What this file cannot prove, and nothing in the repo does: that any of these bytes ever
//! reach a wire. That needs root — see `metadata().notes`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features icmp \
//!       --test server -- server::icmp::packet_codec --test-threads=100

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use netget::server::icmp::actions::IcmpProtocol;
use netget::server::icmp::{prepare_ipv4_for_raw_send, IcmpServer};
use std::net::Ipv4Addr;

const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const DST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

/// RFC 1071 ones' complement sum. Over a whole header (checksum field included) a valid
/// checksum makes this zero.
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&odd) = chunks.remainder().first() {
        sum += (odd as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Assert the IPv4 header of `packet` against RFC 791 for a NetGet-built ICMP packet.
fn assert_ipv4_header(packet: &[u8]) {
    assert!(
        packet.len() >= 20,
        "an IPv4 packet is at least a 20-byte header, got {}",
        packet.len()
    );
    assert_eq!(
        packet[0], 0x45,
        "version 4 in the high nibble, IHL 5 (20 bytes, no options) in the low"
    );
    assert_eq!(packet[1], 0, "DSCP and ECN both unset");
    assert_eq!(
        u16::from_be_bytes([packet[2], packet[3]]) as usize,
        packet.len(),
        "total length must describe the whole datagram, header included"
    );
    assert_eq!(
        u16::from_be_bytes([packet[6], packet[7]]),
        0,
        "no flags, no fragment offset: every message we build fits one datagram"
    );
    assert_eq!(packet[8], 64, "TTL 64");
    assert_eq!(packet[9], 1, "protocol 1 = ICMP");
    assert_eq!(
        ones_complement_sum(&packet[..20]),
        0,
        "IPv4 header checksum does not verify; no peer would accept this header"
    );
    assert_eq!(&packet[12..16], &SRC.octets(), "source address");
    assert_eq!(&packet[16..20], &DST.octets(), "destination address");
}

/// Assert the ICMP message checksum covers header + payload, per RFC 792.
fn assert_icmp_checksum(packet: &[u8]) {
    assert_eq!(
        ones_complement_sum(&packet[20..]),
        0,
        "ICMP checksum does not verify over the whole message"
    );
}

// ---------------------------------------------------------------- echo reply

#[test]
fn echo_reply_matches_the_rfc_792_layout() {
    let payload = b"Hello";
    let p = IcmpServer::build_echo_reply(SRC, DST, 0x1234, 0x0007, payload);

    assert_eq!(
        p.len(),
        20 + 8 + payload.len(),
        "IPv4 header (20) + ICMP echo header (8) + payload"
    );
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);

    // RFC 792 Echo Reply, offsets relative to the start of the ICMP message (20).
    assert_eq!(
        p[20], 0,
        "type 0 = ECHO REPLY (a server that emitted 8 would be asking, not answering)"
    );
    assert_eq!(p[21], 0, "code 0 is the only code an echo reply has");
    assert_eq!(
        u16::from_be_bytes([p[24], p[25]]),
        0x1234,
        "identifier is echoed back unchanged, or the peer cannot match the reply"
    );
    assert_eq!(
        u16::from_be_bytes([p[26], p[27]]),
        0x0007,
        "sequence number is echoed back unchanged"
    );
    assert_eq!(&p[28..], payload, "payload is echoed byte for byte");
}

#[test]
fn echo_reply_with_no_payload_is_still_a_whole_message() {
    let p = IcmpServer::build_echo_reply(SRC, DST, 1, 1, &[]);
    assert_eq!(p.len(), 28, "an empty ping is 20 + 8 bytes and legal");
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);
    assert_eq!(p[20], 0, "type 0 = ECHO REPLY");
}

// ------------------------------------------------- destination unreachable

/// The 28 bytes RFC 792 wants quoted back: an IPv4 header plus the first 8 bytes of the
/// offending datagram. Byte 0 is 0x45 so a decoder can see where the quotation starts.
fn quoted_datagram() -> Vec<u8> {
    let mut v = vec![0x45u8, 0x00, 0x00, 0x1c];
    v.extend_from_slice(&[0x1c, 0x46, 0x00, 0x00, 0x40, 0x11, 0x60, 0xab]);
    v.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 50).octets());
    v.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 5).octets());
    v.extend_from_slice(&[0xa1, 0x12, 0x00, 0x35, 0x00, 0x08, 0x60, 0xb6]);
    assert_eq!(v.len(), 28);
    v
}

#[test]
fn destination_unreachable_matches_the_rfc_792_layout() {
    let original = quoted_datagram();
    let p = IcmpServer::build_destination_unreachable(SRC, DST, 1, &original);

    assert_eq!(p.len(), 20 + 8 + 28, "IPv4 + ICMP header + quoted datagram");
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);

    assert_eq!(p[20], 3, "type 3 = DESTINATION UNREACHABLE");
    assert_eq!(p[21], 1, "code 1 = host unreachable, as asked for");
    assert_eq!(
        &p[24..28],
        &[0, 0, 0, 0],
        "RFC 792 requires the four bytes after the checksum to be unused/zero"
    );
    assert_eq!(
        &p[28..],
        &original[..],
        "the original datagram is quoted verbatim; that is how the peer matches it to a socket"
    );
}

#[test]
fn a_longer_original_datagram_is_quoted_at_28_bytes() {
    let mut original = quoted_datagram();
    original.extend_from_slice(&[0xff; 40]);
    let p = IcmpServer::build_destination_unreachable(SRC, DST, 3, &original);

    assert_eq!(
        p.len(),
        20 + 8 + 28,
        "RFC 792 quotes the IP header plus the next 64 bits and no more"
    );
    assert_eq!(&p[28..], &original[..28]);
    assert_icmp_checksum(&p);
}

#[test]
fn a_shorter_original_datagram_does_not_panic() {
    // Hostile shape: the model quotes three bytes. Slicing `[..28]` on this would panic and
    // take the whole receive task with it.
    let p = IcmpServer::build_destination_unreachable(SRC, DST, 0, &[0x45, 0x00, 0x00]);
    assert_eq!(p.len(), 20 + 8 + 3);
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);
}

// -------------------------------------------------------------- time exceeded

#[test]
fn time_exceeded_matches_the_rfc_792_layout() {
    let original = quoted_datagram();
    let p = IcmpServer::build_time_exceeded(SRC, DST, 0, &original);

    assert_eq!(p.len(), 20 + 8 + 28);
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);

    assert_eq!(
        p[20], 11,
        "type 11 = TIME EXCEEDED; this is what traceroute reads"
    );
    assert_eq!(p[21], 0, "code 0 = TTL exceeded in transit");
    assert_eq!(
        &p[24..28],
        &[0, 0, 0, 0],
        "RFC 792 requires the four bytes after the checksum to be unused/zero"
    );
    assert_eq!(&p[28..], &original[..]);
}

// ------------------------------------------------------- host byte order fixup

/// The Darwin/FreeBSD `IP_HDRINCL` quirk, asserted for whichever platform this is compiled
/// for. It cannot be asserted against a kernel here — see the function's own doc comment —
/// but it can be asserted to do what it says.
#[test]
fn raw_send_fixup_matches_the_platform() {
    let mut p = IcmpServer::build_echo_reply(SRC, DST, 1, 1, b"x");
    let before = p.clone();
    prepare_ipv4_for_raw_send(&mut p);

    if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "freebsd"
    )) {
        assert_eq!(
            u16::from_ne_bytes([p[2], p[3]]) as usize,
            before.len(),
            "total length must reach a Darwin/FreeBSD raw socket in HOST byte order; \
             XNU's rip_output compares it against the real buffer length and returns EINVAL"
        );
        assert_eq!(
            u16::from_ne_bytes([p[6], p[7]]),
            0,
            "flags + fragment offset likewise"
        );
        assert_eq!(
            &p[10..12],
            &[0, 0],
            "the checksum computed over the network-order fields cannot survive the swap, so \
             it is zeroed for the kernel to fill in rather than left stale"
        );
        assert_eq!(
            &p[12..20],
            &before[12..20],
            "addresses are untouched: they are byte arrays, not integers"
        );
    } else {
        assert_eq!(
            p, before,
            "on Linux the header already is what the kernel wants; the fixup must be a no-op"
        );
    }
}

#[test]
fn raw_send_fixup_ignores_a_runt() {
    // Not reachable from the send path, but the function is `pub` and indexing [10] on a
    // 4-byte buffer would panic.
    let mut runt = vec![0x45, 0x00, 0x00, 0x1c];
    prepare_ipv4_for_raw_send(&mut runt);
    assert_eq!(runt, vec![0x45, 0x00, 0x00, 0x1c]);
}

// ------------------------------------------------------------------- executor

fn output_of(action: serde_json::Value) -> Vec<u8> {
    match IcmpProtocol::new()
        .execute_action(action.clone())
        .unwrap_or_else(|e| panic!("executor refused {action}: {e:#}"))
    {
        ActionResult::Output(bytes) => bytes,
        other => panic!("expected packet bytes from {action}, got {other:?}"),
    }
}

/// The shape the model copies. `executable_examples_test` covers this tree-wide; asserting it
/// here as well means a change to ICMP's own examples fails ICMP's own suite.
#[test]
fn every_advertised_example_is_accepted_by_its_own_executor() {
    let protocol = IcmpProtocol::new();
    for action in protocol.get_sync_actions() {
        let result = protocol.execute_action(action.example.clone());
        assert!(
            result.is_ok(),
            "the example for '{}' is what a model will copy verbatim, and its own executor \
             refuses it: {:#}",
            action.name,
            result.unwrap_err()
        );
    }
}

#[test]
fn the_echo_reply_example_produces_the_packet_it_describes() {
    let p = output_of(serde_json::json!({
        "type": "send_echo_reply",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.50",
        "identifier": 1234,
        "sequence": 1,
        "payload_hex": "48656c6c6f"
    }));
    assert_ipv4_header(&p);
    assert_icmp_checksum(&p);
    assert_eq!(p[20], 0, "type 0 = ECHO REPLY");
    assert_eq!(u16::from_be_bytes([p[24], p[25]]), 1234);
    assert_eq!(u16::from_be_bytes([p[26], p[27]]), 1);
    assert_eq!(
        &p[28..],
        b"Hello",
        "payload_hex is decoded, not sent as text"
    );
}

#[test]
fn ignore_icmp_puts_nothing_on_the_wire() {
    let result = IcmpProtocol::new()
        .execute_action(serde_json::json!({"type": "ignore_icmp"}))
        .expect("ignore_icmp is a real answer, not an error");
    assert!(
        matches!(result, ActionResult::NoAction),
        "ignore_icmp must produce no bytes at all, got {result:?}"
    );
}

/// Every one of these is something a confused or hostile model can send. None of them may
/// panic: `execute_action` runs on the receive task, and a panic there is the whole server.
#[test]
fn malformed_actions_are_refused_rather_than_panicking() {
    let protocol = IcmpProtocol::new();
    let cases: Vec<(&str, serde_json::Value)> = vec![
        (
            "unknown action name",
            serde_json::json!({"type": "send_icmp_lies"}),
        ),
        (
            "no type at all",
            serde_json::json!({"source_ip": "127.0.0.1"}),
        ),
        (
            "missing identifier",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "sequence": 1
            }),
        ),
        (
            "identifier past 16 bits truncates silently unless refused",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "identifier": 70000, "sequence": 1
            }),
        ),
        (
            "identifier as a string, not a number",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "identifier": "1234", "sequence": 1
            }),
        ),
        (
            "odd-length hex payload",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "identifier": 1, "sequence": 1, "payload_hex": "abc"
            }),
        ),
        (
            "non-hex payload",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "identifier": 1, "sequence": 1, "payload_hex": "zz"
            }),
        ),
        (
            "payload larger than an IPv4 datagram",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "identifier": 1, "sequence": 1,
                "payload_hex": "ab".repeat(65_536)
            }),
        ),
        (
            "source_ip is not an address",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "not an ip", "destination_ip": "127.0.0.1",
                "identifier": 1, "sequence": 1
            }),
        ),
        (
            "IPv6 where IPv4 is required",
            serde_json::json!({
                "type": "send_echo_reply",
                "source_ip": "::1", "destination_ip": "::1",
                "identifier": 1, "sequence": 1
            }),
        ),
        (
            "unreachable code past 8 bits",
            serde_json::json!({
                "type": "send_destination_unreachable",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "code": 300, "original_packet_hex": "45000014"
            }),
        ),
        (
            "missing quoted datagram",
            serde_json::json!({
                "type": "send_destination_unreachable",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "code": 1
            }),
        ),
        (
            "quoted datagram is not hex",
            serde_json::json!({
                "type": "send_time_exceeded",
                "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                "code": 0, "original_packet_hex": "not hex"
            }),
        ),
    ];

    for (what, action) in cases {
        let result = protocol.execute_action(action.clone());
        assert!(
            result.is_err(),
            "{what}: {action} was accepted; it must be refused with an error the model can read"
        );
    }
}

/// `code` is the one optional numeric field, and its default has to be the RFC 792 one.
#[test]
fn time_exceeded_defaults_to_ttl_exceeded_in_transit() {
    let p = output_of(serde_json::json!({
        "type": "send_time_exceeded",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.50",
        "original_packet_hex": "450000140000000040010000c0a80132cb007105"
    }));
    assert_eq!(p[20], 11, "type 11 = TIME EXCEEDED");
    assert_eq!(p[21], 0, "code 0 when the model does not say");
}

// ---------------------------------------------------------------------------
// The quoted datagram, described rather than transcribed
// ---------------------------------------------------------------------------

/// The 28 bytes RFC 792 quotes, built from `original_packet` fields.
///
/// The point of the structured form is that the model never writes a checksum: both of the
/// ones' complement sums in this quotation are computed here, and a wrong one is *silent* —
/// the peer just fails to match the error against its outstanding probe. So the assertion is
/// that each sum verifies, not that the bytes equal any particular constant.
#[test]
fn structured_quoted_datagram_is_a_real_udp_probe() {
    let p = output_of(serde_json::json!({
        "type": "send_time_exceeded",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.50",
        "original_packet": {
            "source_ip": "192.168.1.50",
            "destination_ip": "203.0.113.5",
            "protocol": "udp",
            "source_port": 41234,
            "destination_port": 33434,
            "ttl": 1,
            "identification": 7238
        }
    }));
    assert_ipv4_header(&p);
    assert_eq!(p[20], 11, "type 11 = TIME EXCEEDED");

    // The quotation begins after the 8-byte ICMP header.
    let quoted = &p[28..];
    assert_eq!(
        quoted.len(),
        28,
        "IPv4 header (20) + 64 bits of payload (8)"
    );
    assert_eq!(quoted[0], 0x45, "IPv4, 20-byte header");
    assert_eq!(
        u16::from_be_bytes([quoted[2], quoted[3]]),
        28,
        "total length describes the header plus the 8 quoted transport bytes"
    );
    assert_eq!(
        u16::from_be_bytes([quoted[4], quoted[5]]),
        7238,
        "identification is carried through, so the peer can match its own probe"
    );
    assert_eq!(quoted[8], 1, "ttl 1 — what makes this a traceroute probe");
    assert_eq!(quoted[9], 17, "protocol 17 = UDP");
    assert_eq!(
        ones_complement_sum(&quoted[..20]),
        0,
        "the quoted IPv4 header's checksum must verify; the whole point of describing the \
         datagram as fields is that nobody hand-writes this"
    );
    assert_eq!(&quoted[12..16], &[192, 168, 1, 50], "probe source");
    assert_eq!(&quoted[16..20], &[203, 0, 113, 5], "probe destination");
    assert_eq!(u16::from_be_bytes([quoted[20], quoted[21]]), 41234);
    assert_eq!(u16::from_be_bytes([quoted[22], quoted[23]]), 33434);
    assert_eq!(
        u16::from_be_bytes([quoted[24], quoted[25]]),
        8,
        "UDP length: the header and no payload"
    );
    // Pseudo-header + UDP header. A UDP checksum that does not verify is one a peer treats as
    // corruption, which is indistinguishable from the error never arriving.
    let mut checked = Vec::new();
    checked.extend_from_slice(&quoted[12..20]); // source + destination address
    checked.push(0);
    checked.push(17); // zero, protocol
    checked.extend_from_slice(&8u16.to_be_bytes()); // UDP length
    checked.extend_from_slice(&quoted[20..28]);
    assert_eq!(
        ones_complement_sum(&checked),
        0,
        "UDP checksum over the pseudo-header does not verify"
    );
}

/// TCP quotes the ports and the sequence number — the 64 bits RFC 792 asks for, and exactly
/// what a peer matches a half-open connection against.
#[test]
fn structured_quoted_datagram_handles_tcp() {
    let p = output_of(serde_json::json!({
        "type": "send_destination_unreachable",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.50",
        "code": 3,
        "original_packet": {
            "source_ip": "192.168.1.50",
            "destination_ip": "203.0.113.5",
            "protocol": "tcp",
            "source_port": 52000,
            "destination_port": 443,
            "sequence": 305419896u32
        }
    }));
    let quoted = &p[28..];
    assert_eq!(quoted[9], 6, "protocol 6 = TCP");
    assert_eq!(ones_complement_sum(&quoted[..20]), 0, "header checksum");
    assert_eq!(u16::from_be_bytes([quoted[20], quoted[21]]), 52000);
    assert_eq!(u16::from_be_bytes([quoted[22], quoted[23]]), 443);
    assert_eq!(
        u32::from_be_bytes([quoted[24], quoted[25], quoted[26], quoted[27]]),
        305419896,
        "sequence number"
    );
}

/// The hex escape hatch still works, and still means bytes the caller captured.
#[test]
fn the_hex_escape_hatch_is_still_passed_through_verbatim() {
    let p = output_of(serde_json::json!({
        "type": "send_destination_unreachable",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.50",
        "code": 1,
        "original_packet_hex": "450000140000000040010000c0a80132cb007105"
    }));
    assert_eq!(
        hex::encode(&p[28..]),
        "450000140000000040010000c0a80132cb007105",
        "bytes the caller supplied must reach the wire unchanged"
    );
}

/// Both spellings at once is refused rather than resolved.
///
/// This is the `send_tcp_data` rule applied to a second field: the structured description and
/// the hex blob say the same thing in incompatible ways, and only the sender knows which was
/// meant. Picking one would make the other silently ignored.
#[test]
fn giving_both_spellings_of_the_quotation_is_refused() {
    let err = IcmpProtocol::new()
        .execute_action(serde_json::json!({
            "type": "send_time_exceeded",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "original_packet": {"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"},
            "original_packet_hex": "450000140000000040010000c0a80132cb007105"
        }))
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not both"),
        "the error must say which of the two to drop, got {err:#}"
    );
}

/// A structured quotation that cannot be built is refused, never half-built.
#[test]
fn malformed_structured_quotations_are_refused() {
    let protocol = IcmpProtocol::new();
    for (what, spec) in [
        (
            "no source",
            serde_json::json!({"destination_ip": "203.0.113.5"}),
        ),
        (
            "source is not an address",
            serde_json::json!({"source_ip": "not an ip", "destination_ip": "203.0.113.5"}),
        ),
        (
            "IPv6 where IPv4 is required",
            serde_json::json!({"source_ip": "::1", "destination_ip": "::1"}),
        ),
        (
            "a protocol with no structured form",
            serde_json::json!({
                "source_ip": "192.168.1.50", "destination_ip": "203.0.113.5",
                "protocol": "sctp"
            }),
        ),
        (
            "a numeric protocol with no structured form",
            serde_json::json!({
                "source_ip": "192.168.1.50", "destination_ip": "203.0.113.5",
                "protocol": 132
            }),
        ),
        (
            "ttl past 8 bits",
            serde_json::json!({
                "source_ip": "192.168.1.50", "destination_ip": "203.0.113.5", "ttl": 300
            }),
        ),
        ("not an object at all", serde_json::json!("192.168.1.50")),
    ] {
        let action = serde_json::json!({
            "type": "send_time_exceeded",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "original_packet": spec
        });
        assert!(
            protocol.execute_action(action.clone()).is_err(),
            "{what}: {action} was accepted; it must be refused with an error the model can read"
        );
    }
}
