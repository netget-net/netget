//! Unprivileged evidence for the IGMP server: the bytes it puts on the wire, where it addresses
//! them, what it accepts off the wire, and what its action executor refuses.
//!
//! `e2e_test.rs` is the only other IGMP server test and all four of its cases are `#[ignore]`d
//! behind raw-socket privilege, so before this file **nothing about the IGMP server ran in any
//! ordinary test run** — `cargo test --features igmp --test server` reported `0 passed; 4
//! ignored`. Everything here needs no socket, no interface and no privilege: the packet
//! builders reached through `execute_action` are pure, `IgmpMessage::parse` is a pure decode,
//! and `igmp_payload` / `response_destination` are pure functions.
//!
//! Assertions are field by field against the literal RFC 2236 §2 layout (and RFC 3376 §4.2.14
//! for the IGMPv3 destination), not against a golden blob, so a failure names the field that
//! moved.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features igmp \
//!       --test server -- server::igmp::packet_codec --test-threads=100

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::igmp::actions::{igmp_checksum, IgmpProtocol};
use netget::server::igmp::{
    igmp_payload, response_destination, IgmpMessage, IgmpMessageType, PayloadReject,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
const ALL_IGMPV3_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

fn peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)), 0)
}

/// Run one action and require it to have produced wire bytes.
fn output_of(action: serde_json::Value) -> Vec<u8> {
    let protocol = IgmpProtocol::new();
    match protocol
        .execute_action(action.clone())
        .unwrap_or_else(|e| panic!("{action} must execute: {e}"))
    {
        ActionResult::Output(bytes) => bytes,
        other => panic!("{action} must produce Output, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Emitted packets
// ---------------------------------------------------------------------------

/// The declared `send_membership_report` example, byte by byte against RFC 2236 §2.
#[test]
fn membership_report_matches_the_rfc_2236_layout() {
    let p = output_of(serde_json::json!({
        "type": "send_membership_report",
        "group_address": "239.255.255.250"
    }));

    assert_eq!(p.len(), 8, "an IGMPv2 message is exactly 8 octets");
    assert_eq!(
        p[0], 0x16,
        "type 0x16 = Version 2 Membership Report (0x12 would be a v1 report, 0x11 a query)"
    );
    assert_eq!(
        p[1], 0x00,
        "Max Response Time is zeroed and ignored in every message that is not a Query"
    );
    assert_eq!(
        &p[4..8],
        &GROUP.octets(),
        "Group Address is the group being reported"
    );
    assert_eq!(
        igmp_checksum(&p),
        0,
        "the RFC 1071 checksum over the whole message must fold to zero"
    );
}

/// The declared `send_leave_group` example, byte by byte.
#[test]
fn leave_group_matches_the_rfc_2236_layout() {
    let p = output_of(serde_json::json!({
        "type": "send_leave_group",
        "group_address": "239.255.255.250"
    }));

    assert_eq!(p.len(), 8);
    assert_eq!(p[0], 0x17, "type 0x17 = Leave Group");
    assert_eq!(p[1], 0x00, "Max Response Time is unused in a Leave");
    assert_eq!(&p[4..8], &GROUP.octets(), "the group being left");
    assert_eq!(igmp_checksum(&p), 0);
}

/// A report and a leave for the same group must differ in exactly one field — and the checksum
/// must therefore differ too. A builder that forgot to recompute the checksum after changing
/// the type byte would pass every other assertion in this file.
#[test]
fn report_and_leave_differ_in_type_and_checksum_only() {
    let report = output_of(serde_json::json!({
        "type": "send_membership_report", "group_address": "239.255.255.250"
    }));
    let leave = output_of(serde_json::json!({
        "type": "send_leave_group", "group_address": "239.255.255.250"
    }));

    assert_ne!(report[0], leave[0]);
    assert_ne!(
        &report[2..4],
        &leave[2..4],
        "the checksum must follow the type byte"
    );
    assert_eq!(&report[4..8], &leave[4..8]);
    assert_eq!(igmp_checksum(&leave), 0);
}

/// The checksum is the whole reason a receiver trusts the rest. One flipped bit anywhere in the
/// message must break it.
#[test]
fn a_single_flipped_bit_breaks_the_checksum() {
    let good = output_of(serde_json::json!({
        "type": "send_membership_report", "group_address": "224.0.1.1"
    }));
    assert_eq!(igmp_checksum(&good), 0);

    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            assert_ne!(
                igmp_checksum(&bad),
                0,
                "flipping bit {bit} of octet {i} must invalidate the checksum"
            );
        }
    }
}

/// `igmp_checksum` is called on whatever a receiver hands it, including nothing at all. The
/// fold loop is written as `while i < data.len() - 1`, which underflows on an empty slice and
/// then indexes far out of range.
#[test]
fn checksum_survives_empty_and_odd_length_input() {
    assert_eq!(igmp_checksum(&[]), !0u16, "empty input must not underflow");
    for len in 1..=64usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let _ = igmp_checksum(&data); // must not panic, odd lengths included
    }
}

// ---------------------------------------------------------------------------
// Where those packets are addressed
// ---------------------------------------------------------------------------

/// RFC 2236 §9 and RFC 3376 §4.2.14 fix the destination of every message we can emit. Sending
/// one back to whoever queried us would put a multicast control message on a unicast address,
/// where no router is listening for it.
#[test]
fn responses_are_addressed_where_the_rfcs_require() {
    let report = output_of(serde_json::json!({
        "type": "send_membership_report", "group_address": "239.255.255.250"
    }));
    assert_eq!(
        response_destination(&report, peer()).ip(),
        IpAddr::V4(GROUP),
        "a Membership Report goes to the group it reports"
    );

    let leave = output_of(serde_json::json!({
        "type": "send_leave_group", "group_address": "239.255.255.250"
    }));
    assert_eq!(
        response_destination(&leave, peer()).ip(),
        IpAddr::V4(ALL_ROUTERS),
        "a Leave Group goes to ALL-ROUTERS 224.0.0.2, not to the group"
    );

    // Not produced by any current action, but the receive path routes on the type byte alone,
    // so the rule has to hold for anything a handler could put there.
    let mut v1_report = report.clone();
    v1_report[0] = 0x12;
    assert_eq!(
        response_destination(&v1_report, peer()).ip(),
        IpAddr::V4(GROUP),
        "a v1 Membership Report is addressed like a v2 one"
    );

    let mut v3_report = report.clone();
    v3_report[0] = 0x22;
    assert_eq!(
        response_destination(&v3_report, peer()).ip(),
        IpAddr::V4(ALL_IGMPV3_ROUTERS),
        "every IGMPv3 report goes to 224.0.0.22"
    );
}

/// Anything the rules do not cover falls back to the sender, and must never index out of range.
#[test]
fn unroutable_output_falls_back_to_the_peer_without_panicking() {
    assert_eq!(response_destination(&[], peer()), peer());
    for len in 0..8usize {
        assert_eq!(response_destination(&vec![0x16; len], peer()), peer());
    }
    // A report naming a unicast "group" is not addressable as a group.
    let mut bogus = vec![0x16, 0x00, 0x00, 0x00];
    bogus.extend_from_slice(&[192, 0, 2, 1]);
    assert_eq!(response_destination(&bogus, peer()), peer());
    // A query is never something we emit in reply.
    let query = vec![0x11, 0x64, 0x00, 0x00, 224, 0, 0, 1];
    assert_eq!(response_destination(&query, peer()), peer());
}

// ---------------------------------------------------------------------------
// What arrives off the wire
// ---------------------------------------------------------------------------

/// Wrap an IGMP message in a minimal IPv4 header, the way a raw socket delivers it.
fn ip_wrap(ihl_words: u8, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; (ihl_words as usize) * 4];
    p[0] = 0x40 | (ihl_words & 0x0F);
    p[9] = protocol;
    p.extend_from_slice(payload);
    p
}

fn report_bytes(group: Ipv4Addr) -> Vec<u8> {
    output_of(serde_json::json!({
        "type": "send_membership_report",
        "group_address": group.to_string()
    }))
}

#[test]
fn a_well_formed_capture_yields_exactly_the_igmp_message() {
    let igmp = report_bytes(GROUP);

    for ihl_words in 5..=15u8 {
        let packet = ip_wrap(ihl_words, 2, &igmp);
        assert_eq!(
            igmp_payload(&packet).expect("IHL 5..=15 is legal"),
            &igmp[..],
            "options in the IP header must be skipped, not parsed as IGMP"
        );
    }
}

/// Every rejection reason, including the ones a hostile sender chooses. The IHL field is four
/// bits, so it can name a header of 0 or of 60 bytes: without a lower bound the IP header
/// itself would be handed to the IGMP parser, and without an upper one the slice would be out
/// of range and panic inside the capture task — where `tokio::spawn` swallows it and the server
/// goes on reporting `Running`.
#[test]
fn malformed_captures_are_rejected_and_never_panic() {
    for len in 0..20usize {
        assert!(
            matches!(
                igmp_payload(&vec![0x45; len]),
                Err(PayloadReject::TooShort(_))
            ),
            "{len} bytes is short of an IPv4 header"
        );
    }

    for ihl_words in 0..5u8 {
        let packet = ip_wrap(5, 2, &report_bytes(GROUP));
        let mut packet = packet;
        packet[0] = 0x40 | ihl_words;
        assert!(
            matches!(
                igmp_payload(&packet),
                Err(PayloadReject::HeaderLength { .. })
            ),
            "IHL {ihl_words} is below the legal minimum of 5 words"
        );
    }

    // IHL names a header longer than the packet.
    let mut truncated = ip_wrap(5, 2, &report_bytes(GROUP));
    truncated[0] = 0x4f; // 15 words = 60 bytes, but the packet is 28
    assert!(matches!(
        igmp_payload(&truncated),
        Err(PayloadReject::HeaderLength { .. })
    ));

    for protocol in [0u8, 1, 6, 17, 89, 255] {
        let packet = ip_wrap(5, protocol, &report_bytes(GROUP));
        assert!(
            matches!(igmp_payload(&packet), Err(PayloadReject::NotIgmp(p)) if p == protocol),
            "IP protocol {protocol} is not IGMP"
        );
    }

    // A header that consumes the whole packet leaves an empty, but valid, payload.
    assert_eq!(igmp_payload(&ip_wrap(5, 2, &[])).unwrap(), &[] as &[u8]);
}

/// The parser is reached from the wire, so no byte pattern may panic it.
#[test]
fn parse_refuses_short_and_unknown_messages_without_panicking() {
    for len in 0..8usize {
        assert!(
            IgmpMessage::parse(&vec![0x16; len]).is_err(),
            "{len} bytes is shorter than the 8-octet IGMP message"
        );
    }

    for type_byte in 0..=255u8 {
        let mut msg = report_bytes(GROUP);
        msg[0] = type_byte;
        let parsed = IgmpMessage::parse(&msg);
        match type_byte {
            0x11 | 0x12 | 0x16 | 0x17 | 0x22 => {
                assert!(parsed.is_ok(), "type 0x{type_byte:02x} is defined")
            }
            _ => assert!(
                parsed.is_err(),
                "type 0x{type_byte:02x} is not an IGMP type we act on"
            ),
        }
    }

    // Long messages (an IGMPv3 report carries group records) parse from the fixed prefix.
    let mut long = report_bytes(GROUP);
    long[0] = 0x22;
    long.extend_from_slice(&[0xff; 512]);
    let parsed = IgmpMessage::parse(&long).expect("a v3 report is longer than 8 octets");
    assert_eq!(parsed.msg_type, IgmpMessageType::V3MembershipReport);
    assert_eq!(parsed.raw_data.len(), long.len(), "the tail is preserved");
}

/// A message that fails its own checksum is corrupt, not merely unfamiliar, and the two have to
/// stay separable: the parser accepts it, `checksum_valid` is what rejects it.
#[test]
fn checksum_validation_is_separate_from_parsing() {
    let good = report_bytes(GROUP);
    let parsed = IgmpMessage::parse(&good).expect("parse");
    assert!(parsed.checksum_valid(), "a message we built must verify");
    assert_eq!(
        parsed.checksum,
        u16::from_be_bytes([good[2], good[3]]),
        "the checksum field is reported as it arrived"
    );

    let mut corrupt = good.clone();
    corrupt[7] ^= 0x01; // one bit of the group address
    let parsed = IgmpMessage::parse(&corrupt).expect("still parses: it is still IGMP");
    assert!(
        !parsed.checksum_valid(),
        "a corrupt message must fail verification rather than be acted on"
    );
    assert_ne!(parsed.group_address, GROUP);
}

/// A general query names group 0.0.0.0. That is what makes membership a policy question rather
/// than something the query answers, and it is the field the server branches on.
#[test]
fn a_general_query_is_distinguished_by_its_zero_group() {
    let mut general = vec![0x11, 0x64, 0x00, 0x00, 0, 0, 0, 0];
    let sum = igmp_checksum(&general);
    general[2] = (sum >> 8) as u8;
    general[3] = (sum & 0xff) as u8;

    let parsed = IgmpMessage::parse(&general).expect("parse");
    assert!(parsed.checksum_valid());
    assert_eq!(parsed.msg_type, IgmpMessageType::MembershipQuery);
    assert_eq!(parsed.max_response_time, 0x64, "10 seconds in deciseconds");
    assert!(parsed.is_general_query());

    let mut specific = vec![0x11, 0x64, 0x00, 0x00];
    specific.extend_from_slice(&GROUP.octets());
    let sum = igmp_checksum(&specific);
    specific[2] = (sum >> 8) as u8;
    specific[3] = (sum & 0xff) as u8;
    let parsed = IgmpMessage::parse(&specific).expect("parse");
    assert!(!parsed.is_general_query());
    assert_eq!(parsed.group_address, GROUP);
}

// ---------------------------------------------------------------------------
// The action executor
// ---------------------------------------------------------------------------

/// `ignore_message` is what the model says when it has decided to answer nothing. On a
/// deliberately-silent protocol the difference between "produced nothing" and "produced an
/// empty packet" is the difference between silence and a malformed multicast frame.
#[test]
fn ignore_message_produces_no_output_at_all() {
    let protocol = IgmpProtocol::new();
    let result = protocol
        .execute_action(serde_json::json!({"type": "ignore_message"}))
        .expect("ignore_message must execute");
    assert!(
        matches!(result, ActionResult::NoAction),
        "ignore_message must be NoAction, got {result:?}"
    );
}

/// The join/leave verbs change kernel membership rather than writing bytes, so they hand the
/// group back for the server loop to apply. The name is what the loop matches on.
#[test]
fn join_and_leave_hand_the_group_to_the_server_loop() {
    let protocol = IgmpProtocol::new();
    for (verb, custom_name) in [
        ("join_group", "igmp_join_group"),
        ("leave_group", "igmp_leave_group"),
    ] {
        let result = protocol
            .execute_action(serde_json::json!({
                "type": verb, "group_address": "239.255.255.250"
            }))
            .unwrap_or_else(|e| panic!("{verb} must execute: {e}"));
        match result {
            ActionResult::Custom { name, data } => {
                assert_eq!(name, custom_name, "the server loop matches on this name");
                assert_eq!(data["group_address"], "239.255.255.250");
            }
            other => panic!("{verb} must be Custom, got {other:?}"),
        }
    }
}

/// Every rejection path, so a model's malformed answer becomes an error the caller logs rather
/// than a panic inside a spawned task.
#[test]
fn malformed_actions_are_refused_without_panicking() {
    let protocol = IgmpProtocol::new();
    let mut cases = vec![
        (
            "unknown verb",
            serde_json::json!({"type": "send_igmpv3_report"}),
        ),
        (
            "no type field",
            serde_json::json!({"group_address": "239.1.1.1"}),
        ),
        ("type is not a string", serde_json::json!({"type": 22})),
    ];

    for verb in [
        "join_group",
        "leave_group",
        "send_membership_report",
        "send_leave_group",
    ] {
        cases.push((verb, serde_json::json!({"type": verb})));
        for bad in [
            serde_json::json!("not-an-address"),
            serde_json::json!("239.255.255"),
            serde_json::json!("::1"),
            serde_json::json!("ff02::1"),
            serde_json::json!("192.0.2.1"),       // unicast
            serde_json::json!("0.0.0.0"),         // what a General Query names
            serde_json::json!("240.0.0.1"),       // reserved, above 224.0.0.0/4
            serde_json::json!("255.255.255.255"), // broadcast, not multicast
            serde_json::json!(3232235777u64),
            serde_json::json!(null),
        ] {
            cases.push((
                verb,
                serde_json::json!({"type": verb, "group_address": bad}),
            ));
        }
    }

    for (what, action) in cases {
        assert!(
            protocol.execute_action(action.clone()).is_err(),
            "{what} must be refused, not accepted: {action}"
        );
    }
}

/// Reporting membership in 0.0.0.0 is the mistake a General Query invites, because the query
/// names that group and echoing it back looks like the obvious answer. It is not a membership,
/// so it must be refused rather than put on the wire — and the multicast range is exactly the
/// set of groups that can be.
#[test]
fn only_real_multicast_groups_are_accepted() {
    let protocol = IgmpProtocol::new();
    for group in ["224.0.0.1", "224.0.0.22", "232.1.2.3", "239.255.255.255"] {
        assert!(
            protocol
                .execute_action(serde_json::json!({
                    "type": "send_membership_report", "group_address": group
                }))
                .is_ok(),
            "{group} is inside 224.0.0.0/4"
        );
    }
    for group in ["223.255.255.255", "240.0.0.0", "0.0.0.0", "10.0.0.1"] {
        assert!(
            protocol
                .execute_action(serde_json::json!({
                    "type": "send_membership_report", "group_address": group
                }))
                .is_err(),
            "{group} is outside 224.0.0.0/4 and cannot be reported"
        );
    }
}
