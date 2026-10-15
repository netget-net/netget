//! Unprivileged evidence for the ARP server: the bytes it puts on the wire, and what its
//! action executor accepts and refuses.
//!
//! `e2e_test.rs` is the only other ARP server test and it is `#[ignore]`d behind layer-2
//! capture privilege, so before this file **nothing about ARP ran in any ordinary test run**.
//! Everything here needs no interface, no socket and no privilege: `build_arp_reply` is a pure
//! function and `execute_action` is a pure `serde_json::Value -> ActionResult` mapping.
//!
//! The reply is asserted field by field against the literal layout of Ethernet II (IEEE 802.3
//! clause 3) plus RFC 826, not against a golden blob, so a failure names the field that moved.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features arp \
//!       --test server -- server::arp::frame_codec --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::arp::actions::ArpProtocol;
use netget::server::arp::ArpServer;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

const SENDER_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const TARGET_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
const SENDER_IP: [u8; 4] = [192, 168, 1, 100];
const TARGET_IP: [u8; 4] = [192, 168, 1, 1];

fn reply() -> Vec<u8> {
    ArpServer::build_arp_reply(
        MacAddr::new(
            SENDER_MAC[0],
            SENDER_MAC[1],
            SENDER_MAC[2],
            SENDER_MAC[3],
            SENDER_MAC[4],
            SENDER_MAC[5],
        ),
        Ipv4Addr::from(SENDER_IP),
        MacAddr::new(
            TARGET_MAC[0],
            TARGET_MAC[1],
            TARGET_MAC[2],
            TARGET_MAC[3],
            TARGET_MAC[4],
            TARGET_MAC[5],
        ),
        Ipv4Addr::from(TARGET_IP),
    )
}

/// Every field of the emitted frame, at its spec offset.
#[test]
fn arp_reply_matches_the_ethernet_ii_and_rfc_826_layout() {
    let f = reply();

    // Ethernet II: 6 destination + 6 source + 2 ethertype, then the 28-byte ARP payload.
    assert_eq!(f.len(), 42, "Ethernet II header (14) + ARP for IPv4 (28)");

    assert_eq!(
        &f[0..6],
        &TARGET_MAC,
        "ethernet destination is the requester"
    );
    assert_eq!(
        &f[6..12],
        &SENDER_MAC,
        "ethernet source is the MAC we claim"
    );
    assert_eq!(&f[12..14], &[0x08, 0x06], "ethertype 0x0806 = ARP");

    // RFC 826, offsets relative to the start of the ARP payload (14).
    assert_eq!(&f[14..16], &[0x00, 0x01], "htype 1 = Ethernet");
    assert_eq!(&f[16..18], &[0x08, 0x00], "ptype 0x0800 = IPv4");
    assert_eq!(f[18], 6, "hlen = 6 octets of MAC");
    assert_eq!(f[19], 4, "plen = 4 octets of IPv4");
    assert_eq!(
        &f[20..22],
        &[0x00, 0x02],
        "oper 2 = REPLY (a server that emitted 1 would be asking, not answering)"
    );
    assert_eq!(&f[22..28], &SENDER_MAC, "sha: the MAC being advertised");
    assert_eq!(&f[28..32], &SENDER_IP, "spa: the IP it is advertised for");
    assert_eq!(&f[32..38], &TARGET_MAC, "tha: the requester's MAC");
    assert_eq!(&f[38..42], &TARGET_IP, "tpa: the requester's IP");
}

/// The `sender_*` pair is the assertion "this MAC owns that IP"; the `target_*` pair is who is
/// being told. Swapping them would answer the wrong host with the wrong claim, and every field
/// is a valid MAC/IP either way, so nothing else would catch it.
#[test]
fn sender_and_target_are_not_transposed() {
    let f = reply();
    assert_ne!(&f[22..28], &TARGET_MAC);
    assert_ne!(&f[28..32], &TARGET_IP);
    assert_eq!(
        &f[0..6],
        &f[32..38],
        "the ethernet destination and the ARP target hardware address are the same host"
    );
}

/// The example the model is shown must be the example the executor accepts — and it must
/// produce exactly the frame the pure builder produces.
#[test]
fn declared_send_arp_reply_example_executes_to_the_same_frame() {
    let protocol = ArpProtocol::new();
    let result = protocol
        .execute_action(serde_json::json!({
            "type": "send_arp_reply",
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "sender_ip": "192.168.1.100",
            "target_mac": "11:22:33:44:55:66",
            "target_ip": "192.168.1.1"
        }))
        .expect("the documented send_arp_reply example must execute");

    match result {
        ActionResult::Output(bytes) => assert_eq!(bytes, reply()),
        other => panic!("send_arp_reply must produce Output, got {other:?}"),
    }
}

/// `ignore_arp` is documented as "no action taken". On a deliberately-silent protocol the
/// difference between "produced nothing" and "produced an empty frame" is the difference
/// between silence and a malformed broadcast.
#[test]
fn ignore_arp_produces_no_output_at_all() {
    let protocol = ArpProtocol::new();
    let result = protocol
        .execute_action(serde_json::json!({"type": "ignore_arp"}))
        .expect("ignore_arp must execute");
    assert!(
        matches!(result, ActionResult::NoAction),
        "ignore_arp must be NoAction, got {result:?}"
    );
}

/// Every rejection path, so a model's malformed answer becomes an error the caller can log
/// rather than a panic inside the capture task (where `tokio::spawn` would swallow it and the
/// server would go on reporting Running).
#[test]
fn malformed_actions_are_refused_without_panicking() {
    let protocol = ArpProtocol::new();
    let cases = [
        (
            "unknown verb",
            serde_json::json!({"type": "send_rarp_reply"}),
        ),
        ("no type field", serde_json::json!({"sender_ip": "1.2.3.4"})),
        (
            "missing target_ip",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66"
            }),
        ),
        (
            "MAC with too few octets",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "aa:bb:cc:dd:ee",
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
        (
            "MAC with too many octets",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "aa:bb:cc:dd:ee:ff:00",
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
        (
            "MAC octet out of range",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "aa:bb:cc:dd:ee:1ff",
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
        (
            "MAC that is not hex",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "zz:bb:cc:dd:ee:ff",
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
        (
            "IPv6 where IPv4 is required",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "::1",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
        (
            "MAC passed as a number",
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": 42,
                "sender_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66",
                "target_ip": "192.168.1.1"
            }),
        ),
    ];

    for (what, action) in cases {
        assert!(
            protocol.execute_action(action).is_err(),
            "{what} must be refused, not accepted"
        );
    }
}
