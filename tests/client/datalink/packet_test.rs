//! The DataLink packet builder and decoder against literal bytes — **no privilege at all**.
//!
//! Everything here is pure: link-type framing (Ethernet, BSD loopback `NULL` / `LOOP`, `RAW`),
//! IPv4 + TCP crafting with both checksums, TCP and MPTCP option encoding and decoding, the
//! event payload for a frame on each link type, and how `remote_addr` / `filter` resolve into a
//! capture filter. The reference packet is a SYN that tcpdump reported with a correct TCP
//! checksum of `0x434b`.
//!
//! ```bash
//! ./cargo-isolated.sh test --test client -- client::datalink::packet_test
//! ```

#![cfg(all(unix, feature = "libpcap"))]

use netget::client::datalink::actions::{
    build_frame_for_link, build_probe, build_tcp_frame, DataLinkClientProtocol, LinkSession,
};
use netget::client::datalink::packet::{
    build_ipv4_tcp, decode_frame, decode_link, decode_tcp_options, echoed_options,
    encode_tcp_options, ipv4_header_checksum, link_header, parse_target, tcp_checksum_ipv4,
    BuildDefaults, LinkType, TcpFlow, AF_INET, AF_INET6,
};
use netget::client::datalink::{
    frame_event_fields_for_link, reply_matches, resolve_capture_filter,
};
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;
use std::net::Ipv4Addr;

/// 127.0.0.1:40000 -> 127.0.0.1:3333, SYN, seq 0x11223344, window 65535, ip id 0x1234, DF,
/// options mss 16344 + MP_CAPABLE v1 flags 0x01. tcpdump: "cksum 0x434b (correct)".
const KNOWN_SYN: &str = "450000301234400040062a927f0000017f0000019c400d0511223344000000007002ffff434b000002043fd81e040101";

fn known_syn_fields() -> serde_json::Value {
    json!({
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 40000,
        "dst_port": 3333,
        "seq": 0x11223344u32,
        "ack": 0,
        "flags": ["syn"],
        "window": 65535,
        "ip_id": 0x1234,
        "ttl": 64,
        "options": [
            {"kind": "mss", "value": 16344},
            {"kind": "mp_capable", "version": 1, "flags": 1}
        ]
    })
}

fn loopback_session() -> LinkSession {
    LinkSession {
        link_type: Some(LinkType::Null),
        loopback: true,
        defaults: BuildDefaults {
            dst_ip: Some(Ipv4Addr::LOCALHOST),
            dst_port: Some(3333),
        },
    }
}

/// The SYN-ACK a Linux or macOS listener sends back, without MP_CAPABLE, with the TCP checksum
/// as the kernel leaves it on loopback (0) or correct.
fn syn_ack(zero_checksum: bool, mp_capable: bool) -> Vec<u8> {
    let mut options = vec![json!({"kind": "mss", "value": 16344})];
    if mp_capable {
        options.push(json!({"kind": "mp_capable", "version": 1, "flags": 1, "sender_key": "0x0102030405060708"}));
    }
    let mut packet = build_ipv4_tcp(
        &json!({
            "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
            "src_port": 3333, "dst_port": 40000,
            "seq": 7, "ack": 0x11223345u32, "flags": ["syn", "ack"],
            "ip_id": 0, "options": options
        }),
        &BuildDefaults::default(),
    )
    .unwrap()
    .packet;
    if zero_checksum {
        packet[20 + 16] = 0;
        packet[20 + 17] = 0;
    }
    let mut frame = AF_INET.to_ne_bytes().to_vec();
    frame.extend_from_slice(&packet);
    frame
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

#[test]
fn the_known_good_syn_is_built_byte_for_byte_with_both_checksums() {
    let built = build_ipv4_tcp(&known_syn_fields(), &BuildDefaults::default()).unwrap();
    assert_eq!(hex::encode(&built.packet), KNOWN_SYN);
    assert_eq!(&built.packet[10..12], &[0x2a, 0x92], "IPv4 header checksum");
    assert_eq!(
        &built.packet[36..38],
        &[0x43, 0x4b],
        "TCP checksum, as tcpdump verified it"
    );
    assert_eq!(
        built.flow,
        TcpFlow {
            src_ip: Ipv4Addr::LOCALHOST,
            dst_ip: Ipv4Addr::LOCALHOST,
            src_port: 40000,
            dst_port: 3333
        }
    );
}

#[test]
fn checksums_verify_to_zero_over_the_known_packet() {
    let p = hex::decode(KNOWN_SYN).unwrap();
    assert_eq!(ipv4_header_checksum(&p[..20]), 0);
    assert_eq!(
        tcp_checksum_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, &p[20..]),
        0
    );
}

#[test]
fn send_ipv4_tcp_on_loopback_gets_the_af_inet_header_and_no_macs() {
    let session = loopback_session();
    let (frame, _) = build_tcp_frame(&known_syn_fields(), &session).unwrap();
    assert_eq!(
        &frame[..4],
        &AF_INET.to_ne_bytes(),
        "DLT_NULL: AF_INET in host order"
    );
    assert_eq!(hex::encode(&frame[4..]), KNOWN_SYN);

    let p = DataLinkClientProtocol::with_session(session.clone());
    let mut with_macs = known_syn_fields();
    with_macs["dst_mac"] = json!("ff:ff:ff:ff:ff:ff");
    with_macs["src_mac"] = json!("00:11:22:33:44:55");
    with_macs["type"] = json!("send_ipv4_tcp");
    let err = format!("{:#}", p.execute_action(with_macs).unwrap_err());
    assert!(err.contains("NULL") && err.contains("MAC"), "{err}");
}

#[test]
fn send_ipv4_tcp_on_ethernet_needs_the_macs_and_puts_them_first() {
    let session = LinkSession {
        link_type: Some(LinkType::Ethernet),
        ..Default::default()
    };
    let err = format!(
        "{:#}",
        build_tcp_frame(&known_syn_fields(), &session).unwrap_err()
    );
    assert!(err.contains("dst_mac"), "{err}");

    let mut f = known_syn_fields();
    f["dst_mac"] = json!("aa:bb:cc:dd:ee:ff");
    f["src_mac"] = json!("00:11:22:33:44:55");
    let (frame, _) = build_tcp_frame(&f, &session).unwrap();
    assert_eq!(hex::encode(&frame[..14]), "aabbccddeeff0011223344550800");
    assert_eq!(hex::encode(&frame[14..]), KNOWN_SYN);
}

#[test]
fn destination_defaults_from_remote_addr_and_source_from_loopback() {
    let session = loopback_session();
    let (frame, flow) = build_tcp_frame(&json!({"src_port": 40000}), &session).unwrap();
    assert_eq!(flow.dst_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(flow.dst_port, 3333);
    assert_eq!(flow.src_ip, Ipv4Addr::LOCALHOST);
    let decoded = decode_frame(&frame, LinkType::Null, true);
    assert_eq!(
        decoded["tcp"]["flags"],
        json!(["syn"]),
        "SYN is the default"
    );

    let err = format!(
        "{:#}",
        build_tcp_frame(&json!({}), &LinkSession::default()).unwrap_err()
    );
    assert!(err.contains("dst_ip"), "{err}");
    let err = format!(
        "{:#}",
        build_ipv4_tcp(
            &json!({"dst_ip": "10.0.0.2", "dst_port": 80}),
            &BuildDefaults::default()
        )
        .unwrap_err()
    );
    assert!(
        err.contains("src_ip"),
        "a non-loopback source is never guessed: {err}"
    );
}

#[test]
fn bad_fields_are_refused_by_name() {
    let d = BuildDefaults::default();
    for (field, value) in [
        ("flags", json!(["syn", "bogus"])),
        ("dst_port", json!(70000)),
        ("src_ip", json!("::1")),
        ("options", json!([{"kind": "mss"}])),
        ("options", json!([{"kind": "wibble"}])),
    ] {
        let mut f = known_syn_fields();
        f[field] = value.clone();
        let err = format!("{:#}", build_ipv4_tcp(&f, &d).unwrap_err());
        assert!(
            err.to_lowercase().contains(field.trim_end_matches('s'))
                || err.contains("mss")
                || err.contains("wibble")
                || err.contains("bogus"),
            "{field}={value}: {err}"
        );
    }
    let mut f = known_syn_fields();
    f["payload"] = json!("hello");
    assert!(format!("{:#}", build_ipv4_tcp(&f, &d).unwrap_err()).contains("payload_encoding"));
}

#[test]
fn options_over_forty_bytes_are_refused() {
    let many: Vec<_> = (0..5)
        .map(|_| json!({"kind": "timestamps", "tsval": 1, "tsecr": 2}))
        .collect();
    let err = format!("{:#}", encode_tcp_options(&many).unwrap_err());
    assert!(err.contains("40"), "{err}");
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

#[test]
fn every_named_option_round_trips_through_the_decoder() {
    let options = vec![
        json!({"kind": "mss", "value": 1460}),
        json!({"kind": "sack_perm"}),
        json!({"kind": "timestamps", "tsval": 123456, "tsecr": 0}),
        json!({"kind": "nop"}),
        json!({"kind": "wscale", "shift": 7}),
    ];
    let bytes = encode_tcp_options(&options).unwrap();
    assert_eq!(bytes.len() % 4, 0);
    assert_eq!(
        hex::encode(&bytes),
        "020405b40402080a0001e2400000000001030307"
    );
    assert_eq!(decode_tcp_options(&bytes), options);
}

#[test]
fn mp_capable_is_encoded_and_decoded_with_its_fields() {
    let bytes =
        encode_tcp_options(&[json!({"kind": "mp_capable", "version": 1, "flags": 1})]).unwrap();
    assert_eq!(hex::encode(&bytes), "1e040101");
    let decoded = decode_tcp_options(&bytes);
    assert_eq!(decoded[0]["kind"], "mp_capable");
    assert_eq!(decoded[0]["version"], 1);
    assert_eq!(decoded[0]["flags"], 1);
    assert_eq!(decoded[0]["flag_names"], json!(["hmac_sha256"]));

    // Named flags and the ACK form with both keys.
    let bytes = encode_tcp_options(&[json!({
        "kind": "mp_capable", "version": 1,
        "flags": ["checksum_required", "hmac_sha256"],
        "sender_key": "0x0102030405060708", "receiver_key": 1
    })])
    .unwrap();
    assert_eq!(bytes[0..4], [30, 20, 0x01, 0x81]);
    let d = &decode_tcp_options(&bytes)[0];
    assert_eq!(d["sender_key"], "0x0102030405060708");
    assert_eq!(d["receiver_key"], "0x0000000000000001");

    let err = format!(
        "{:#}",
        encode_tcp_options(&[json!({"kind": "mp_capable", "receiver_key": 1})]).unwrap_err()
    );
    assert!(err.contains("sender_key"), "{err}");
}

#[test]
fn other_mptcp_subtypes_are_named_and_unknown_kinds_kept_as_data() {
    // MP_JOIN (subtype 1) SYN: 12 bytes.
    let join = [30u8, 12, 0x10, 0x05, 1, 2, 3, 4, 5, 6, 7, 8];
    let d = decode_tcp_options(&join);
    assert_eq!(d[0]["kind"], "mptcp");
    assert_eq!(d[0]["subtype"], "mp_join");
    // ...and it re-encodes from what the decoder said.
    assert_eq!(encode_tcp_options(&d).unwrap(), join);

    let generic = encode_tcp_options(&[json!({"kind": 254, "data_hex": "f989"})]).unwrap();
    assert_eq!(generic, [254, 4, 0xf9, 0x89]);
    assert_eq!(
        decode_tcp_options(&generic),
        vec![json!({"kind": 254, "data_hex": "f989"})]
    );

    // An impossible length is reported, not over-read.
    assert_eq!(
        decode_tcp_options(&[2, 9, 0]),
        vec![json!({"kind": 2, "malformed": true})]
    );
}

// ---------------------------------------------------------------------------
// Link types
// ---------------------------------------------------------------------------

#[test]
fn link_types_come_from_the_dlt_and_carry_their_pcap_names() {
    assert_eq!(LinkType::from_dlt(0), LinkType::Null);
    assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
    assert_eq!(LinkType::from_dlt(12), LinkType::Raw);
    assert_eq!(LinkType::from_dlt(108), LinkType::Loop);
    assert_eq!(LinkType::Null.name(), "NULL");
    assert_eq!(LinkType::Ethernet.name(), "EN10MB");
    assert_eq!(LinkType::Raw.name(), "RAW");
    assert_eq!(LinkType::Loop.name(), "LOOP");
    assert_eq!(LinkType::from_dlt(147).name(), "DLT_147");
}

#[test]
fn loopback_headers_use_host_order_for_null_and_network_order_for_loop() {
    assert_eq!(
        link_header(LinkType::Null, 0x0800, None).unwrap(),
        AF_INET.to_ne_bytes()
    );
    assert_eq!(
        link_header(LinkType::Loop, 0x0800, None).unwrap(),
        AF_INET.to_be_bytes()
    );
    assert_eq!(
        link_header(LinkType::Null, 0x86dd, None).unwrap(),
        AF_INET6.to_ne_bytes()
    );
    #[cfg(target_os = "macos")]
    assert_eq!(AF_INET6, 30);
    assert!(link_header(LinkType::Raw, 0x0800, None).unwrap().is_empty());

    let err = format!(
        "{:#}",
        link_header(LinkType::Null, 0x0806, None).unwrap_err()
    );
    assert!(
        err.contains("ipv4") && err.contains("NULL"),
        "ARP cannot go on lo0: {err}"
    );
    let err = format!(
        "{:#}",
        link_header(LinkType::LinuxSll, 0x0800, None).unwrap_err()
    );
    assert!(err.contains("LINUX_SLL"), "{err}");
}

#[test]
fn inject_frame_builds_the_family_header_on_loopback_and_refuses_macs() {
    let ip = hex::decode(KNOWN_SYN).unwrap();
    let frame = build_frame_for_link(
        &json!({"type": "inject_frame", "ethertype": "ipv4", "payload": KNOWN_SYN, "payload_encoding": "hex"}),
        LinkType::Null,
    )
    .unwrap();
    assert_eq!(&frame[..4], &AF_INET.to_ne_bytes());
    assert_eq!(&frame[4..], &ip[..]);

    let err = format!(
        "{:#}",
        build_frame_for_link(
            &json!({"dst_mac": "ff:ff:ff:ff:ff:ff", "src_mac": "00:11:22:33:44:55", "ethertype": "ipv4"}),
            LinkType::Null
        )
        .unwrap_err()
    );
    assert!(err.contains("no MAC"), "{err}");
    let err = format!(
        "{:#}",
        build_frame_for_link(
            &json!({"payload": "00", "payload_encoding": "hex"}),
            LinkType::Null
        )
        .unwrap_err()
    );
    assert!(err.contains("ethertype"), "{err}");

    // RAW: the payload is the frame.
    let raw = build_frame_for_link(
        &json!({"payload": KNOWN_SYN, "payload_encoding": "hex"}),
        LinkType::Raw,
    )
    .unwrap();
    assert_eq!(raw, ip);
}

// ---------------------------------------------------------------------------
// Decoding and the event payload
// ---------------------------------------------------------------------------

#[test]
fn a_null_frame_is_decoded_as_family_and_ip_not_as_fake_macs() {
    let mut frame = AF_INET.to_ne_bytes().to_vec();
    frame.extend_from_slice(&hex::decode(KNOWN_SYN).unwrap());
    let ev = frame_event_fields_for_link(&frame, LinkType::Null, true);

    assert_eq!(ev["link_type"], "NULL");
    assert_eq!(ev["family"], "AF_INET");
    assert!(ev["dst_mac"].is_null() && ev["src_mac"].is_null());
    assert_eq!(ev["ethertype"], "0x0800");
    assert_eq!(
        ev["payload"], KNOWN_SYN,
        "the payload is everything after the 4-byte header"
    );
    assert_eq!(ev["ip"]["src"], "127.0.0.1");
    assert_eq!(ev["ip"]["checksum_ok"], true);
    let tcp = &ev["tcp"];
    assert_eq!(tcp["src_port"], 40000);
    assert_eq!(tcp["dst_port"], 3333);
    assert_eq!(tcp["seq"], 0x11223344u32);
    assert_eq!(tcp["flags"], json!(["syn"]));
    assert_eq!(tcp["checksum"], "0x434b");
    assert_eq!(tcp["checksum_ok"], true);
    assert_eq!(tcp["options"][0], json!({"kind": "mss", "value": 16344}));
    assert_eq!(tcp["options"][1]["kind"], "mp_capable");

    // And it hands straight back to inject_frame on the same link.
    let again = build_frame_for_link(
        &json!({"ethertype": ev["ethertype"], "payload": ev["payload"], "payload_encoding": ev["payload_encoding"]}),
        LinkType::Null,
    )
    .unwrap();
    assert_eq!(again, frame);
}

#[test]
fn the_same_bytes_read_as_ethernet_are_what_the_old_decoder_showed() {
    // What used to happen on lo0: four family bytes and the IP header read as MACs.
    let mut frame = AF_INET.to_ne_bytes().to_vec();
    frame.extend_from_slice(&hex::decode(KNOWN_SYN).unwrap());
    let wrong = decode_link(&frame, LinkType::Ethernet);
    assert!(
        wrong.dst_mac.is_some(),
        "Ethernet decoding invents MACs from any 14 bytes"
    );
    let right = decode_link(&frame, LinkType::Null);
    assert!(right.dst_mac.is_none());
    assert_eq!(right.l3_offset, Some(4));
}

#[test]
fn a_zero_checksum_on_loopback_is_called_offload_not_an_error() {
    let ev = frame_event_fields_for_link(&syn_ack(true, false), LinkType::Null, true);
    let tcp = &ev["tcp"];
    assert_eq!(tcp["checksum"], "0x0000");
    assert!(tcp["checksum_ok"].is_null(), "{tcp}");
    assert!(tcp["checksum_note"].as_str().unwrap().contains("offload"));

    // Off loopback the same zero is a failed checksum.
    let off = frame_event_fields_for_link(&syn_ack(true, false), LinkType::Null, false);
    assert_eq!(off["tcp"]["checksum_ok"], false);

    let ok = frame_event_fields_for_link(&syn_ack(false, false), LinkType::Null, true);
    assert_eq!(ok["tcp"]["checksum_ok"], true);
}

#[test]
fn a_reply_is_matched_to_its_flow_and_echoed_options_are_reported() {
    let flow = TcpFlow {
        src_ip: Ipv4Addr::LOCALHOST,
        dst_ip: Ipv4Addr::LOCALHOST,
        src_port: 40000,
        dst_port: 3333,
    };
    let reply = decode_frame(&syn_ack(true, true), LinkType::Null, true);
    assert!(reply_matches(&reply, &flow));
    let mut own = AF_INET.to_ne_bytes().to_vec();
    own.extend_from_slice(&hex::decode(KNOWN_SYN).unwrap());
    assert!(
        !reply_matches(&decode_frame(&own, LinkType::Null, true), &flow),
        "our own SYN on lo0 is not a reply"
    );
    assert_eq!(
        flow.reply_filter(),
        "(tcp and src host 127.0.0.1 and src port 3333 and dst host 127.0.0.1 and dst port \
         40000) or (icmp and dst host 127.0.0.1)"
    );

    let sent = decode_tcp_options(&hex::decode("02043fd81e040101").unwrap());
    let with = reply["tcp"]["options"].as_array().unwrap().clone();
    assert_eq!(
        echoed_options(&sent, &with),
        (vec!["mss".into(), "mp_capable".into()], vec![])
    );
    let without = decode_frame(&syn_ack(true, false), LinkType::Null, true)["tcp"]["options"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(
        echoed_options(&sent, &without),
        (vec!["mss".into()], vec!["mp_capable".into()])
    );
}

// ---------------------------------------------------------------------------
// probe_tcp, remote_addr, filter
// ---------------------------------------------------------------------------

#[test]
fn probe_tcp_carries_the_frame_flow_and_bounds() {
    let p = DataLinkClientProtocol::with_session(loopback_session());
    let mut action = known_syn_fields();
    action["type"] = json!("probe_tcp");
    match p.execute_action(action.clone()).unwrap() {
        ClientActionResult::Custom { name, data } => {
            assert_eq!(name, "probe_tcp");
            assert_eq!(data["timeout_ms"], 1000);
            assert_eq!(data["max_replies"], 1);
            assert_eq!(data["flow"]["dst_port"], 3333);
        }
        other => panic!("expected the probe request, got {other:?}"),
    }
    action["timeout_ms"] = json!(60_000);
    assert!(format!(
        "{:#}",
        build_probe(&action, &loopback_session()).unwrap_err()
    )
    .contains("timeout_ms"));
}

#[test]
fn remote_addr_resolves_to_a_target_and_a_default_filter() {
    assert_eq!(
        parse_target("127.0.0.1:3333"),
        Some(("127.0.0.1".parse().unwrap(), Some(3333)))
    );
    assert_eq!(
        parse_target("10.0.0.2"),
        Some(("10.0.0.2".parse().unwrap(), None))
    );
    assert_eq!(
        parse_target("127.0.0.1:0"),
        Some(("127.0.0.1".parse().unwrap(), None))
    );
    assert_eq!(parse_target("localhost:80").map(|t| t.1), Some(Some(80)));
    assert_eq!(parse_target("eth0"), None);

    assert_eq!(
        resolve_capture_filter("127.0.0.1:3333", None),
        (Some("host 127.0.0.1 and port 3333".to_string()), true)
    );
    assert_eq!(
        resolve_capture_filter("127.0.0.1:3333", Some("arp")),
        (Some("arp".to_string()), false),
        "an explicit filter wins"
    );
    assert_eq!(
        resolve_capture_filter("127.0.0.1:3333", Some("")),
        (None, false)
    );
    assert_eq!(resolve_capture_filter("eth0", None), (None, false));
}
