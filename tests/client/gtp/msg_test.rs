//! The GTP client's octets and decode bounds, without a peer: literal encodings, the refusals
//! that keep a malformed or oversized answer away from the model, and the validation that
//! keeps a malformed request off the wire.
use netget::client::gtp::msg::{self, BearerQos, CreateParams, Role};
use netget::server::gtp::codec::{self, GtpVersion};
use serde_json::json;
use std::net::Ipv4Addr;

#[test]
fn plmn_is_tbcd_with_filler_for_a_two_digit_mnc() {
    assert_eq!(msg::encode_plmn("001", "01"), vec![0x00, 0xF1, 0x10]);
    assert_eq!(msg::encode_plmn("310", "410"), vec![0x13, 0x00, 0x14]);
}

#[test]
fn bearer_qos_octets() {
    let q = BearerQos {
        qci: 9,
        arp_priority_level: 2,
        pre_emption_capability: true,
        pre_emption_vulnerability: false,
        mbr_uplink_kbps: 1000,
        mbr_downlink_kbps: 0xFF_FFFF_FFFF,
        gbr_uplink_kbps: 0,
        gbr_downlink_kbps: 1,
    };
    // spare|PCI=0|PL=2|spare|PVI=1, QCI, four 40-bit rates.
    assert_eq!(
        q.encode_v2(),
        vec![
            0x09, 9, 0, 0, 0, 0x03, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1
        ]
    );
    assert_eq!(q.encode_v1(), vec![2, 0x0B, 0x92, 0x1F]);
    assert!(BearerQos::from_json(Some(&json!({"mbr_uplink_kbps": 0x100_0000_0000u64}))).is_err());
    assert!(BearerQos::from_json(Some(&json!({"qci": 0}))).is_err());
    assert!(BearerQos::from_json(Some(&json!({"arp_priority_level": 16}))).is_err());
}

#[test]
fn rfc1071_checksum() {
    // RFC 1071 §3's worked example sums to 0xDDF2, so the checksum is its complement.
    assert_eq!(
        msg::checksum(&[&[0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]]),
        !0xDDF2u16
    );
}

#[test]
fn the_inner_packet_carries_correct_checksums() {
    let src = Ipv4Addr::new(10, 45, 0, 7);
    let dst = Ipv4Addr::new(10, 45, 0, 1);
    let p = msg::ipv4_packet(
        src,
        dst,
        64,
        0x1234,
        &msg::Inner::IcmpEcho {
            identifier: 7,
            sequence: 1,
        },
        b"abc",
    )
    .unwrap();
    assert_eq!(p.len(), 20 + 8 + 3);
    assert_eq!(
        &p[..12],
        &[0x45, 0, 0, 31, 0x12, 0x34, 0x40, 0, 64, 1, p[10], p[11]]
    );
    assert_eq!(msg::checksum(&[&p[..20]]), 0, "IPv4 header checksum");
    assert_eq!(msg::checksum(&[&p[20..]]), 0, "ICMP checksum");
    assert_eq!(&p[20..28], &[8, 0, p[22], p[23], 0, 7, 0, 1]);

    let u = msg::ipv4_packet(
        src,
        dst,
        64,
        1,
        &msg::Inner::Udp {
            source_port: 5000,
            destination_port: 53,
        },
        b"x",
    )
    .unwrap();
    let mut pseudo = vec![10, 45, 0, 7, 10, 45, 0, 1, 0, 17, 0, 9];
    pseudo.extend(&u[20..]);
    assert_eq!(
        msg::checksum(&[&pseudo]),
        0,
        "UDP checksum over the pseudo-header"
    );
    let j = msg::inner_json(&u);
    assert_eq!(j["udp_checksum_ok"], true, "{j}");
    assert_eq!(j["destination_port"], 53, "{j}");
    assert_eq!(j["payload"], "x", "{j}");

    assert!(msg::ipv4_packet(
        src,
        dst,
        64,
        1,
        &msg::Inner::IcmpEcho {
            identifier: 1,
            sequence: 1
        },
        &vec![0u8; msg::MAX_INNER_PAYLOAD + 1]
    )
    .is_err());
}

#[test]
fn a_large_tunnelled_payload_reaches_the_model_cut_and_counted() {
    let p = msg::ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        64,
        1,
        &msg::Inner::IcmpEcho {
            identifier: 1,
            sequence: 1,
        },
        &vec![b'a'; msg::MAX_EVENT_PAYLOAD + 10],
    )
    .unwrap();
    let j = msg::inner_json(&p);
    assert_eq!(j["payload"].as_str().unwrap().len(), msg::MAX_EVENT_PAYLOAD);
    assert_eq!(j["payload_length"], msg::MAX_EVENT_PAYLOAD + 10);
    assert_eq!(j["payload_truncated"], true);
    assert_eq!(msg::inner_json(&[0x60, 0])["decoded"], false);
}

fn v2_with_ies(n: usize) -> Vec<u8> {
    let mut ies = Vec::new();
    for _ in 0..n {
        ies.extend([3, 0, 1, 0, 0]);
    }
    let mut b = vec![0x40, 2];
    b.extend(((4 + ies.len()) as u16).to_be_bytes());
    b.extend([0, 0, 1, 0]);
    b.extend(ies);
    b
}

#[test]
fn malformed_and_oversized_answers_are_refused() {
    assert!(msg::decode_control(&v2_with_ies(msg::MAX_IES)).is_ok());
    let e = msg::decode_control(&v2_with_ies(msg::MAX_IES + 1)).unwrap_err();
    assert!(e.to_string().contains("IEs"), "{e}");
    assert!(msg::decode_control(&vec![0x40; msg::MAX_DATAGRAM + 1]).is_err());
    // Declared length past the datagram.
    assert!(msg::decode_control(&[0x40, 2, 0, 40, 0, 0, 1, 0]).is_err());
    // An IE that runs past the message.
    assert!(msg::decode_control(&[0x40, 2, 0, 9, 0, 0, 1, 0, 3, 0, 9, 0, 0]).is_err());
    // A GTPv1 fixed-length IE whose length is unknown cannot be skipped.
    assert!(msg::decode_control(&[0x32, 2, 0, 6, 0, 0, 0, 0, 0, 1, 0, 0, 100, 0]).is_err());
    // A GTPv1-C message without a sequence number cannot be matched to anything.
    assert!(msg::decode_control(&[0x30, 2, 0, 0, 0, 0, 0, 0]).is_err());
    // GTP' and unknown versions.
    assert!(msg::decode_control(&[0x22, 2, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0]).is_err());
    assert!(msg::decode_control(&[0x60, 2, 0, 0]).is_err());
    assert!(msg::decode_control(&[]).is_err());
}

#[test]
fn pco_dns_reads_containers_and_ipcp_and_stops_on_bad_lengths() {
    let mut pco = vec![0x80, 0x00, 0x0D, 4, 8, 8, 8, 8];
    // IPCP Configure-Nak with primary (129) and secondary (131) DNS.
    pco.extend([
        0x80, 0x21, 16, 3, 1, 0, 16, 129, 6, 1, 1, 1, 1, 131, 6, 9, 9, 9, 9,
    ]);
    assert_eq!(msg::pco_dns(&pco), vec!["8.8.8.8", "1.1.1.1", "9.9.9.9"]);
    // A zero option length inside IPCP, and a container running past the end: no loop, no panic.
    assert!(msg::pco_dns(&[0x80, 0x80, 0x21, 8, 3, 1, 0, 8, 129, 0, 0, 0]).is_empty());
    assert!(msg::pco_dns(&[0x80, 0x00, 0x0D, 200, 1]).is_empty());
}

fn create(a: serde_json::Value) -> anyhow::Result<CreateParams> {
    CreateParams::from_action(Role::S5, &a)
}

#[test]
fn a_create_request_the_wire_cannot_carry_is_refused() {
    assert!(create(json!({"imsi": "001010123456789", "apn": "internet"})).is_ok());
    assert!(create(json!({"imsi": "00101012345678a", "apn": "internet"})).is_err());
    assert!(create(json!({"imsi": "0010101234567890", "apn": "internet"})).is_err());
    assert!(create(json!({"imsi": "001010123456789", "apn": "a".repeat(64)})).is_err());
    assert!(create(json!({"imsi": "001010123456789", "apn": "a.".repeat(51)})).is_err());
    assert!(create(json!({"imsi": "001010123456789", "apn": "internet", "ebi": 4})).is_err());
    assert!(create(json!({"imsi": "001010123456789", "apn": "internet", "mnc": "1"})).is_err());
    assert!(
        create(json!({"imsi": "001010123456789", "apn": "internet", "pdn_type": "ipx"})).is_err()
    );
    assert!(
        create(json!({"imsi": "001010123456789", "apn": "internet", "rat_type": "5G"})).is_err()
    );
    assert!(CreateParams::from_action(
        Role::S11,
        &json!({"imsi": "001010123456789", "apn": "internet"})
    )
    .is_err());
    assert!(CreateParams::from_action(
        Role::Gn,
        &json!({"imsi": "001010123456789", "apn": "internet", "rat_type": "NR"})
    )
    .is_err());
}

#[test]
fn a_create_pdp_context_request_keeps_its_fixed_ies_in_order() {
    let p = CreateParams::from_action(
        Role::Gn,
        &json!({"imsi": "26201123456789", "apn": "internet", "msisdn": "4915112345678", "mei": "3534900698733190"}),
    )
    .unwrap();
    let local = msg::Local {
        control_ip: "127.0.0.1".parse().unwrap(),
        user_ip: "127.0.0.1".parse().unwrap(),
        control_teid: 0x11,
        data_teid: 0x22,
    };
    let b = msg::create_request(Role::Gn, &p, &local, 0x4242, 0).unwrap();
    let m = codec::GtpV1Message::decode(&b).unwrap();
    assert_eq!(m.header.message_type, codec::V1_CREATE_PDP_CONTEXT_REQUEST);
    assert_eq!(m.header.sequence, Some(0x4242));
    let ies = codec::parse_v1_ies(&m.body).unwrap();
    let types: Vec<u8> = ies.iter().map(|i| i.ie_type).collect();
    let mut sorted = types.clone();
    sorted.sort();
    assert_eq!(types, sorted, "TV IEs ascending, TLV after");
    assert_eq!(
        codec::find_v1(&ies, codec::V1_IE_IMSI).unwrap(),
        &[0x62, 0x02, 0x11, 0x32, 0x54, 0x76, 0x98, 0xFF]
    );
    assert_eq!(
        codec::find_v1(&ies, codec::V1_IE_SELECTION_MODE).unwrap(),
        &[0xFC]
    );
    assert_eq!(codec::find_v1(&ies, codec::V1_IE_NSAPI).unwrap(), &[5]);
    assert_eq!(codec::find_all_v1(&ies, codec::V1_IE_GSN_ADDRESS).len(), 2);
    assert_eq!(codec::find_v1(&ies, codec::V1_IE_MSISDN).unwrap()[0], 0x91);
}

#[test]
fn causes_by_name_and_number() {
    assert_eq!(msg::cause_name(GtpVersion::V2, 16), "request_accepted");
    assert_eq!(msg::cause_name(GtpVersion::V1, 128), "request_accepted");
    assert_eq!(msg::cause_name(GtpVersion::V2, 200), "cause_200");
    assert_eq!(
        msg::cause_value(GtpVersion::V1, &json!("system_failure")).unwrap(),
        204
    );
    assert_eq!(msg::cause_value(GtpVersion::V2, &json!(73)).unwrap(), 73);
    assert!(msg::cause_value(GtpVersion::V2, &json!(256)).is_err());
    assert!(msg::cause_value(GtpVersion::V2, &json!("fine")).is_err());
}
