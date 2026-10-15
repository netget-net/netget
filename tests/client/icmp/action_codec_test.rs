//! Unprivileged evidence for the ICMP client: the echo request it builds, and what its action
//! executor accepts and refuses.
//!
//! Everything else about this client needs `CAP_NET_RAW` — `e2e_test.rs` holds two `#[ignore]`d
//! stubs and `command_channel_test.rs` asserts the failure path. `build_echo_request` is a pure
//! function and `execute_action` is a pure `serde_json::Value -> ClientActionResult` mapping, so
//! both can be pinned here without a socket.
//!
//! The request is asserted field by field at its RFC 791 / RFC 792 offset, and both checksums
//! are *verified* rather than compared to a constant.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features icmp \
//!       --test client -- icmp::action_codec --test-threads=100

#![cfg(unix)]

use netget::client::icmp::{IcmpClient, IcmpClientProtocol};
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::llm::actions::protocol_trait::Protocol;
use std::net::Ipv4Addr;

/// RFC 1071 ones' complement sum. Over a whole header a valid checksum makes this zero.
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

#[test]
fn the_echo_request_matches_the_rfc_792_layout() {
    let dest = Ipv4Addr::new(127, 0, 0, 1);
    let payload = b"Hello";
    let p = IcmpClient::build_echo_request(Ipv4Addr::UNSPECIFIED, dest, 0x1234, 7, payload, 42);

    assert_eq!(
        p.len(),
        20 + 8 + payload.len(),
        "IPv4 + ICMP header + payload"
    );
    assert_eq!(p[0], 0x45, "version 4, IHL 5 (20 bytes, no options)");
    assert_eq!(
        u16::from_be_bytes([p[2], p[3]]) as usize,
        p.len(),
        "total length describes the whole datagram"
    );
    assert_eq!(
        p[8], 42,
        "the model's ttl reaches the header; this is the field traceroute walks, and it is \
         meaningless unless the socket sets IP_HDRINCL"
    );
    assert_eq!(p[9], 1, "protocol 1 = ICMP");
    assert_eq!(
        ones_complement_sum(&p[..20]),
        0,
        "IPv4 header checksum does not verify"
    );
    assert_eq!(
        &p[12..16],
        &[0, 0, 0, 0],
        "source 0.0.0.0 asks the kernel to fill in the outgoing interface's address"
    );
    assert_eq!(&p[16..20], &dest.octets(), "destination address");

    assert_eq!(p[20], 8, "type 8 = ECHO REQUEST (type 0 would be a reply)");
    assert_eq!(p[21], 0, "code 0 is the only code an echo request has");
    assert_eq!(
        ones_complement_sum(&p[20..]),
        0,
        "ICMP checksum does not verify over the whole message"
    );
    assert_eq!(u16::from_be_bytes([p[24], p[25]]), 0x1234, "identifier");
    assert_eq!(u16::from_be_bytes([p[26], p[27]]), 7, "sequence number");
    assert_eq!(&p[28..], payload, "payload");
}

#[test]
fn an_empty_payload_still_builds_a_whole_message() {
    let p = IcmpClient::build_echo_request(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(127, 0, 0, 1),
        1,
        1,
        &[],
        64,
    );
    assert_eq!(p.len(), 28);
    assert_eq!(ones_complement_sum(&p[..20]), 0);
    assert_eq!(ones_complement_sum(&p[20..]), 0);
}

/// The shape the model copies.
#[test]
fn every_advertised_example_is_accepted_by_its_own_executor() {
    let protocol = IcmpClientProtocol::new();
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
fn send_echo_request_normalises_its_parameters() {
    let result = IcmpClientProtocol::new()
        .execute_action(serde_json::json!({
            "type": "send_echo_request",
            "destination_ip": "127.0.0.1"
        }))
        .expect("every parameter but destination_ip is optional");

    match result {
        ClientActionResult::Custom { name, data } => {
            assert_eq!(name, "send_echo_request");
            assert_eq!(data["destination_ip"], "127.0.0.1");
            assert_eq!(data["identifier"], 1234, "documented default");
            assert_eq!(data["sequence"], 1, "documented default");
            assert_eq!(data["ttl"], 64, "documented default");
        }
        other => panic!("expected a Custom result, got {other:?}"),
    }
}

#[test]
fn wait_for_more_and_disconnect_are_real_answers() {
    let protocol = IcmpClientProtocol::new();
    assert!(matches!(
        protocol
            .execute_action(serde_json::json!({"type": "wait_for_more"}))
            .unwrap(),
        ClientActionResult::WaitForMore
    ));
    assert!(matches!(
        protocol
            .execute_action(serde_json::json!({"type": "disconnect"}))
            .unwrap(),
        ClientActionResult::Disconnect
    ));
}

/// None of these may panic, and none may be silently substituted with a default: the client
/// loop runs `execute_action` on whatever the model produced.
#[test]
fn malformed_actions_are_refused_rather_than_panicking() {
    let protocol = IcmpClientProtocol::new();
    let cases: Vec<(&str, serde_json::Value)> = vec![
        (
            "unknown action name",
            serde_json::json!({"type": "ping_harder"}),
        ),
        (
            "no type at all",
            serde_json::json!({"destination_ip": "127.0.0.1"}),
        ),
        (
            "missing destination_ip",
            serde_json::json!({"type": "send_echo_request", "identifier": 1}),
        ),
        (
            "identifier as a string silently became the default 1234",
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "identifier": "5678"
            }),
        ),
        (
            "identifier past 16 bits",
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "identifier": 70000
            }),
        ),
        (
            "sequence past 16 bits",
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "sequence": 65536
            }),
        ),
        (
            "ttl past one byte",
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "ttl": 256
            }),
        ),
        (
            "negative ttl",
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "ttl": -1
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

/// Every event the client raises must offer the model something it can act on. Clients union
/// async ∪ sync ∪ the event's own list, so the sync list is what carries this — and it must not
/// be empty, or the model has no vocabulary at all.
#[test]
fn the_model_is_offered_a_vocabulary_on_every_event() {
    let protocol = IcmpClientProtocol::new();
    let names: Vec<String> = protocol
        .get_sync_actions()
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert!(
        names.contains(&"send_echo_request".to_string())
            && names.contains(&"wait_for_more".to_string())
            && names.contains(&"disconnect".to_string()),
        "sync actions are the client's whole vocabulary, got {names:?}"
    );

    for event in protocol.get_event_types() {
        assert!(
            !event.response_example.is_null(),
            "event '{}' shows the model no example answer",
            event.id
        );
    }
}
