//! The OpenFlow 1.3 codec on its own: round trips, the bounds every peer-chosen length and list
//! is held to, the JSON vocabulary the model writes, packet building against literal bytes, and
//! tshark's `openflow_v4` dissector over every message type NetGet encodes.
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::openflow::fields;
use netget::server::openflow::packet;
use netget::server::openflow::wire::{self, msg, Action, Instruction, Match, Oxm, Rd};
use serde_json::json;

fn table_miss() -> wire::FlowMod {
    netget::server::openflow::actions::flow_mod_from_json(&json!({
        "priority": 0, "match": {}, "actions": [{"type": "output", "port": "controller"}]
    }))
    .unwrap()
}

#[test]
fn the_table_miss_flow_mod_is_the_spec_bytes() {
    let fm = table_miss();
    let body = fm.encode();
    let msg = wire::encode(wire::VERSION_1_3, msg::FLOW_MOD, 7, &body).unwrap();
    // ofp_header + 40 bytes of fixed flow_mod + an empty 8-byte match + apply_actions(output).
    assert_eq!(msg.len(), 8 + 40 + 8 + 8 + 16);
    assert_eq!(&msg[..4], &[4, 14, 0, 80]);
    assert_eq!(&msg[8 + 16..8 + 18], &[0, 0], "table 0, command add");
    assert_eq!(&msg[8 + 22..8 + 24], &[0, 0], "priority 0");
    assert_eq!(&msg[8 + 24..8 + 28], &[0xff; 4], "OFP_NO_BUFFER");
    assert_eq!(&msg[48..56], &[0, 1, 0, 4, 0, 0, 0, 0], "empty OXM match");
    assert_eq!(
        &msg[56..80],
        &[
            0, 4, 0, 24, 0, 0, 0, 0, // apply_actions
            0, 0, 0, 16, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0, 0, 0, 0, 0,
            0 // output controller
        ]
    );
    assert_eq!(wire::FlowMod::parse(&body).unwrap(), fm);
}

#[test]
fn matches_round_trip_with_masks_and_completed_prerequisites() {
    let m = fields::match_from_json(&json!({
        "in_port": 3,
        "ipv4_dst": "10.1.0.0/16",
        "tcp_dst": 443,
        "vlan_vid": 100,
        "eth_src": {"value": "02:00:00:00:00:01", "mask": "ff:ff:ff:00:00:00"},
    }))
    .unwrap();
    // eth_type and ip_proto were implied; everything is in field-id order.
    let ids: Vec<u8> = m.oxms.iter().map(|o| o.field).collect();
    assert_eq!(ids, vec![0, 4, 5, 6, 10, 12, 14]);
    let j = fields::match_to_json(&m);
    assert_eq!(j["eth_type"], "0x0800");
    assert_eq!(j["ip_proto"], 6);
    assert_eq!(j["ipv4_dst"], "10.1.0.0/16");
    assert_eq!(j["vlan_vid"], 100);
    assert_eq!(j["eth_src"]["mask"], "ff:ff:ff:00:00:00");
    let mut b = Vec::new();
    m.encode(&mut b);
    assert_eq!(b.len() % 8, 0);
    let back = Match::parse(&mut Rd::new(&b)).unwrap();
    assert_eq!(back, m);
    // The value bits outside a mask are cleared rather than sent.
    let masked = fields::match_from_json(&json!({"ipv4_src": "10.1.2.3/8"})).unwrap();
    assert_eq!(fields::match_to_json(&masked)["ipv4_src"], "10.0.0.0/8");
}

#[test]
fn prerequisites_that_cannot_be_implied_or_contradict_are_refused() {
    for (bad, needle) in [
        (json!({"ip_dscp": 4}), "eth_type"),
        (json!({"tcp_dst": 80, "ip_proto": 17}), "contradicts"),
        (
            json!({"ipv4_dst": "10.0.0.1", "eth_type": "0x86dd"}),
            "contradicts",
        ),
        (json!({"vlan_pcp": 3}), "vlan_vid"),
        (json!({"in_phy_port": 1}), "in_port"),
        (json!({"no_such_field": 1}), "unknown match field"),
        (
            json!({"in_port": {"value": 1, "mask": 1}}),
            "cannot be masked",
        ),
        (json!({"vlan_vid": 5000}), "maximum"),
    ] {
        let err = format!("{:#}", fields::match_from_json(&bad).unwrap_err());
        assert!(err.contains(needle), "{bad}: {err}");
    }
}

#[test]
fn a_peers_match_is_checked_the_way_a_switch_checks_it() {
    // tcp_dst with no ip_proto: BAD_PREREQ.
    let m = Match {
        oxms: vec![Oxm::basic(14, vec![0, 80])],
    };
    assert_eq!(
        fields::check_prerequisites(&m).unwrap_err().0,
        wire::err::BAD_MATCH_BAD_PREREQ
    );
    // A field twice: DUP_FIELD at parse time.
    let dup = Match {
        oxms: vec![
            Oxm::basic(0, vec![0, 0, 0, 1]),
            Oxm::basic(0, vec![0, 0, 0, 2]),
        ],
    };
    let mut b = Vec::new();
    dup.encode(&mut b);
    assert_eq!(
        Match::parse(&mut Rd::new(&b)).unwrap_err().0,
        wire::err::BAD_MATCH_DUP_FIELD
    );
}

#[test]
fn every_peer_list_is_bounded() {
    // MAX_OXMS + 1 distinct experimenter-class OXMs (each 4 bytes, empty payload).
    let mut oxms = Vec::new();
    for i in 0..=wire::MAX_OXMS {
        oxms.push(Oxm {
            class: 0x0001,
            field: (i % 127) as u8,
            value: vec![(i / 127) as u8],
            mask: None,
        });
    }
    let mut b = Vec::new();
    Match { oxms }.encode(&mut b);
    let err = Match::parse(&mut Rd::new(&b)).unwrap_err();
    assert!(err.1.contains("more than"), "{err:?}");

    // MAX_ACTIONS + 1 actions.
    let many: Vec<Action> = (0..=wire::MAX_ACTIONS).map(|_| Action::PopVlan).collect();
    let bytes = wire::encode_actions(&many);
    let n = bytes.len();
    let err = wire::parse_actions(&mut Rd::new(&bytes), n).unwrap_err();
    assert_eq!(err.0, wire::err::BAD_ACTION_TOO_MANY);
    // Exactly MAX_ACTIONS is fine.
    let ok: Vec<Action> = (0..wire::MAX_ACTIONS).map(|_| Action::PopVlan).collect();
    let bytes = wire::encode_actions(&ok);
    let n = bytes.len();
    assert_eq!(
        wire::parse_actions(&mut Rd::new(&bytes), n).unwrap().len(),
        wire::MAX_ACTIONS
    );

    // An action whose length is not a multiple of eight, or shorter than its header.
    for len in [0u16, 4, 12] {
        let mut a = vec![0, 0];
        a.extend_from_slice(&len.to_be_bytes());
        a.extend_from_slice(&[0; 12]);
        let n = a.len();
        assert_eq!(
            wire::parse_actions(&mut Rd::new(&a), n).unwrap_err().0,
            wire::err::BAD_ACTION_BAD_LEN
        );
    }

    // A duplicated instruction type.
    let two = wire::encode_instructions(&[Instruction::ClearActions, Instruction::ClearActions]);
    assert!(wire::parse_instructions(&mut Rd::new(&two)).is_err());

    // A HELLO with more elements than the bound.
    let mut hello = Vec::new();
    for _ in 0..=wire::MAX_HELLO_ELEMENTS {
        hello.extend_from_slice(&[0, 9, 0, 8, 0, 0, 0, 0]);
    }
    assert!(wire::parse_hello_bitmap(&hello).is_err());

    // A message cannot be encoded past the 16-bit length.
    assert!(wire::encode(4, msg::PACKET_OUT, 1, &vec![0; wire::MAX_MESSAGE_LEN]).is_err());
    assert!(wire::encode(
        4,
        msg::PACKET_OUT,
        1,
        &vec![0; wire::MAX_MESSAGE_LEN - wire::HEADER_LEN]
    )
    .is_ok());
}

#[tokio::test]
async fn a_header_shorter_than_itself_is_refused_before_any_body_is_read() {
    let bytes: &[u8] = &[4, 0, 0, 4, 0, 0, 0, 1];
    let mut r = bytes;
    assert!(matches!(
        wire::read_message(&mut r).await,
        Err(wire::ReadError::BadLength(4))
    ));
}

#[test]
fn version_negotiation_follows_the_bitmap_rules() {
    let v13 = wire::parse_hello_bitmap(&wire::hello_body(&[4])).unwrap();
    assert_eq!(wire::negotiate(4, v13.as_deref()), Some(4));
    // 1.0 to 1.5 offered: 1.3 chosen.
    let many = wire::parse_hello_bitmap(&wire::hello_body(&[1, 2, 3, 4, 5, 6])).unwrap();
    assert_eq!(wire::negotiate(6, many.as_deref()), Some(4));
    // Only 1.0: refused.
    let v10 = wire::parse_hello_bitmap(&wire::hello_body(&[1])).unwrap();
    assert_eq!(wire::negotiate(1, v10.as_deref()), None);
    // No bitmap: the lower header version, which must be 1.3 or above.
    assert_eq!(wire::negotiate(5, None), Some(4));
    assert_eq!(wire::negotiate(1, None), None);
}

#[test]
fn the_connection_cap_refusal_is_a_well_formed_hello_failed() {
    let r = netget::server::openflow::CONNECTION_CAP_REFUSAL;
    let h = wire::Header::parse(r[..8].try_into().unwrap());
    assert_eq!(h.version, 4);
    assert_eq!(h.msg_type, msg::ERROR);
    assert_eq!(h.length as usize, r.len());
    let e = wire::ErrorMsg::parse(&r[8..]).unwrap();
    assert_eq!(e.etype, wire::err::HELLO_FAILED);
    assert_eq!(e.code, 1, "EPERM");
}

#[test]
fn built_packets_are_well_formed_and_described_back() {
    let arp = packet::build(&json!({
        "eth_src": "02:00:00:00:00:01",
        "arp": {"op": "request", "spa": "10.0.0.1", "tpa": "10.0.0.2"}
    }))
    .unwrap();
    assert_eq!(arp.len(), packet::MIN_FRAME);
    assert_eq!(&arp[0..6], &[0xff; 6], "an ARP request is broadcast");
    assert_eq!(&arp[12..14], &[0x08, 0x06]);
    let d = packet::describe(&arp);
    assert_eq!(d["arp"]["op"], "request");
    assert_eq!(d["arp"]["tpa"], "10.0.0.2");
    assert_eq!(d["arp"]["tha"], "00:00:00:00:00:00");

    let tcp = packet::build(&json!({
        "eth_src": "02:00:00:00:00:01", "eth_dst": "02:00:00:00:00:02",
        "vlan": {"vid": 42, "pcp": 5},
        "ipv6": {"src": "fd00::1", "dst": "fd00::2"},
        "tcp": {"src_port": 4000, "dst_port": 80, "flags": ["syn"], "seq": 9},
        "payload_text": "hi"
    }))
    .unwrap();
    let d = packet::describe(&tcp);
    assert_eq!(d["vlans"][0]["vid"], 42);
    assert_eq!(d["vlans"][0]["pcp"], 5);
    assert_eq!(d["ipv6"]["dst"], "fd00::2");
    assert_eq!(d["tcp"]["dst_port"], 80);
    assert_eq!(d["tcp"]["flags"], json!(["syn"]));
    assert_eq!(d["payload_text"], "hi");

    // A non-printable payload is described by length only, never as bytes.
    let mut raw = arp.clone();
    raw[12] = 0x88;
    raw[13] = 0xb5;
    raw.extend_from_slice(&[0, 1, 2, 0xff]);
    let d = packet::describe(&raw);
    assert!(d.get("payload_text").is_none(), "{d}");

    // A truncated frame is described as far as it goes.
    let d = packet::describe(&tcp[..20]);
    assert!(d["truncated"].is_string(), "{d}");

    // VLAN stacking past the bound stops.
    let mut deep = vec![0u8; 12];
    for _ in 0..5 {
        deep.extend_from_slice(&[0x81, 0x00, 0, 1]);
    }
    deep.extend_from_slice(&[0x08, 0x00]);
    let d = packet::describe(&deep);
    assert_eq!(d["vlans"].as_array().unwrap().len(), packet::MAX_VLAN_TAGS);
}

#[test]
fn built_packets_carry_checksums_tshark_verifies() {
    // Inside a PACKET_OUT, tshark's openflow_v4 dissector hands the data to eth, and the ICMP
    // and ICMPv6 dissectors verify their checksums: a wrong one is a Bad status here.
    let ping = packet::build(&json!({
        "eth_src": "02:00:00:00:00:01", "eth_dst": "02:00:00:00:00:02",
        "ipv4": {"src": "10.0.0.1", "dst": "10.0.0.2"},
        "icmp": {"type": 8, "id": 7, "seq": 1}, "payload_text": "ping"
    }))
    .unwrap();
    let ping6 = packet::build(&json!({
        "eth_src": "02:00:00:00:00:01", "eth_dst": "02:00:00:00:00:02",
        "ipv6": {"src": "fd00::1", "dst": "fd00::2"},
        "icmpv6": {"type": 128, "id": 3, "seq": 4}, "payload_text": "ping6"
    }))
    .unwrap();
    let mut oracle = PcapOracle::tcp("openflow");
    for (xid, frame) in [(1u32, &ping), (2, &ping6)] {
        let po = wire::PacketOut {
            buffer_id: wire::NO_BUFFER,
            in_port: wire::port::CONTROLLER,
            actions: vec![Action::Output {
                port: 1,
                max_len: 0,
            }],
            data: frame.clone(),
        };
        oracle = oracle.from_server(&wire::encode(4, msg::PACKET_OUT, xid, &po.encode()).unwrap());
    }
    let rows = oracle
        .fields(&["icmp.checksum.status", "icmpv6.checksum.status"])
        .unwrap();
    let statuses: Vec<String> = rows
        .into_iter()
        .flatten()
        .filter(|c| !c.is_empty())
        .collect();
    assert_eq!(
        statuses,
        vec!["1".to_string(), "1".to_string()],
        "checksum status Good"
    );
}

/// Every message type NetGet encodes, in both directions, through tshark's openflow_v4.
#[test]
fn tshark_reads_every_message_netget_encodes() {
    let fm = netget::server::openflow::actions::flow_mod_from_json(&json!({
        "command": "add", "priority": 100, "idle_timeout": 30, "cookie": 7,
        "flags": ["send_flow_rem"],
        "match": {"in_port": 1, "eth_dst": "02:00:00:00:00:02", "ipv4_src": "10.0.0.0/8", "udp_dst": 53},
        "instructions": [
            {"type": "apply_actions", "actions": [
                {"type": "push_vlan"}, {"type": "set_field", "field": "vlan_vid", "value": 10},
                {"type": "set_field", "field": "eth_dst", "value": "02:00:00:00:00:09"},
                {"type": "dec_nw_ttl"}, {"type": "output", "port": 2}
            ]},
            {"type": "write_metadata", "metadata": 1, "mask": 1},
            {"type": "goto_table", "table_id": 1}
        ]
    }))
    .unwrap();
    let frame = packet::build(&json!({
        "eth_src": "02:00:00:00:00:01", "eth_dst": "02:00:00:00:00:02",
        "ipv4": {"src": "10.0.0.1", "dst": "10.0.0.2"}, "icmp": {"id": 1, "seq": 1}
    }))
    .unwrap();
    let po = wire::PacketOut {
        buffer_id: wire::NO_BUFFER,
        in_port: 1,
        actions: vec![Action::Output {
            port: wire::port::FLOOD,
            max_len: 0,
        }],
        data: frame.clone(),
    };
    let pi = wire::PacketIn {
        buffer_id: wire::NO_BUFFER,
        total_len: frame.len() as u16,
        reason: 0,
        table_id: 0,
        cookie: 0,
        matched: Match {
            oxms: vec![Oxm::basic(0, vec![0, 0, 0, 1])],
        },
        data: frame,
    };
    let features = wire::Features {
        datapath_id: 0xabc,
        n_buffers: 0,
        n_tables: 254,
        auxiliary_id: 0,
        capabilities: 7,
    };
    let mut ports = Vec::new();
    crate::server::openflow::support::port(1, "p1").encode(&mut ports);
    let to_switch = [
        wire::encode(4, msg::HELLO, 1, &wire::hello_body(&[4])).unwrap(),
        wire::encode(4, msg::FEATURES_REQUEST, 2, &[]).unwrap(),
        wire::encode(
            4,
            msg::SET_CONFIG,
            3,
            &wire::config_body(0, wire::CML_NO_BUFFER),
        )
        .unwrap(),
        wire::encode(
            4,
            msg::MULTIPART_REQUEST,
            4,
            &wire::multipart_body(wire::mp::PORT_DESC, 0, &[]),
        )
        .unwrap(),
        wire::encode(4, msg::FLOW_MOD, 5, &fm.encode()).unwrap(),
        wire::encode(4, msg::PACKET_OUT, 6, &po.encode()).unwrap(),
        wire::encode(4, msg::ECHO_REQUEST, 7, b"x").unwrap(),
    ];
    let to_controller = [
        wire::encode(4, msg::HELLO, 1, &wire::hello_body(&[4])).unwrap(),
        wire::encode(4, msg::FEATURES_REPLY, 2, &features.encode()).unwrap(),
        wire::encode(
            4,
            msg::MULTIPART_REPLY,
            4,
            &wire::multipart_body(wire::mp::PORT_DESC, 0, &ports),
        )
        .unwrap(),
        wire::encode(4, msg::PACKET_IN, 8, &pi.encode()).unwrap(),
        wire::encode(
            4,
            msg::ERROR,
            5,
            &wire::error_body(
                wire::err::BAD_MATCH,
                wire::err::BAD_MATCH_BAD_PREREQ,
                &to_switch[4],
            ),
        )
        .unwrap(),
        wire::encode(4, msg::ECHO_REPLY, 7, b"x").unwrap(),
    ];
    let mut oracle = PcapOracle::tcp("openflow");
    for b in &to_controller {
        oracle = oracle.to_server(b);
    }
    for b in &to_switch {
        oracle = oracle.from_server(b);
    }
    oracle.also_named("openflow_v4").assert_clean();
}
