//! NetGet's OpenFlow switch against a raw controller written in this test from the wire
//! format: what Rust answers on its own (FEATURES, ECHO, BARRIER, GET_CONFIG, ROLE, the
//! multipart queries, split replies), what it refuses the way a switch must (bad prerequisites,
//! unknown ports, buffers it does not have, a full flow table), the model's PACKET_IN on the
//! wire, and that a model that cannot answer sends nothing. The third-party controllers are in
//! `real_server_test.rs`.
//!
//! No LLM calls: static and script handlers play the model, or an unreachable endpoint does.
use super::support::{self, HOST_A, HOST_B};
use netget::server::openflow::wire::{self, err, msg, Message, VERSION_1_3};
use netget::state::client_handles::ClientSendOutcome;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Ctl {
    s: TcpStream,
    xid: u32,
}

impl Ctl {
    async fn send(&mut self, t: u8, body: &[u8]) -> u32 {
        self.xid += 1;
        let b = wire::encode(VERSION_1_3, t, self.xid, body).unwrap();
        self.s.write_all(&b).await.unwrap();
        self.xid
    }

    async fn recv_within(&mut self, d: Duration) -> Option<Message> {
        tokio::time::timeout(d, wire::read_message(&mut self.s))
            .await
            .ok()?
            .ok()
    }

    async fn recv(&mut self) -> Message {
        self.recv_within(Duration::from_secs(30))
            .await
            .expect("the switch sent nothing within 30 s")
    }

    /// The next message of `t` (answering the switch's ECHOs on the way).
    async fn expect(&mut self, t: u8) -> Message {
        loop {
            let m = self.recv().await;
            if m.header.msg_type == t {
                return m;
            }
            if m.header.msg_type == msg::ECHO_REQUEST {
                let b = wire::encode(VERSION_1_3, msg::ECHO_REPLY, m.header.xid, &m.body).unwrap();
                self.s.write_all(&b).await.unwrap();
                continue;
            }
            panic!(
                "expected {}, got {}",
                wire::msg_name(t),
                wire::msg_name(m.header.msg_type)
            );
        }
    }

    /// An ERROR answering request `xid`, as (type, code).
    async fn expect_error(&mut self, xid: u32) -> (u16, u16) {
        let m = self.expect(msg::ERROR).await;
        assert_eq!(m.header.xid, xid);
        let e = wire::ErrorMsg::parse(&m.body).unwrap();
        (e.etype, e.code)
    }

    /// A BARRIER round trip, proving the switch sent nothing else before it.
    async fn barrier(&mut self) {
        let xid = self.send(msg::BARRIER_REQUEST, &[]).await;
        let m = self.recv().await;
        assert_eq!(
            m.header.msg_type,
            msg::BARRIER_REPLY,
            "the switch sent {} first",
            wire::msg_name(m.header.msg_type)
        );
        assert_eq!(m.header.xid, xid);
    }

    async fn flow_mod(&mut self, v: serde_json::Value) -> u32 {
        let fm = netget::server::openflow::actions::flow_mod_from_json(&v).unwrap();
        self.send(msg::FLOW_MOD, &fm.encode()).await
    }

    /// Every part of the multipart reply to `xid`, one body per part.
    async fn multipart_parts(&mut self, xid: u32) -> (u16, Vec<Vec<u8>>) {
        let mut parts = Vec::new();
        loop {
            let m = self.expect(msg::MULTIPART_REPLY).await;
            assert_eq!(m.header.xid, xid);
            assert!(m.body.len() + wire::HEADER_LEN <= wire::MAX_MESSAGE_LEN);
            let (t, flags, b) = wire::parse_multipart(&m.body).unwrap();
            parts.push(b.to_vec());
            if flags & wire::mp::MORE == 0 {
                return (t, parts);
            }
        }
    }

    /// The multipart reply to `xid`, bodies concatenated.
    async fn multipart(&mut self, xid: u32) -> (u16, Vec<u8>, usize) {
        let (t, parts) = self.multipart_parts(xid).await;
        let n = parts.len();
        (t, parts.concat(), n)
    }
}

/// A raw controller listening; returns its address and a future that accepts and does HELLO.
async fn controller(hello_versions: &'static [u8]) -> (String, tokio::task::JoinHandle<Ctl>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let h = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let mut c = Ctl { s, xid: 100 };
        let b = wire::encode(
            *hello_versions.last().unwrap(),
            msg::HELLO,
            1,
            &wire::hello_body(hello_versions),
        )
        .unwrap();
        c.s.write_all(&b).await.unwrap();
        let hello = c.recv().await;
        assert_eq!(hello.header.msg_type, msg::HELLO);
        assert_eq!(
            wire::bitmap_versions(&wire::parse_hello_bitmap(&hello.body).unwrap().unwrap()),
            vec![VERSION_1_3]
        );
        c
    });
    (addr, h)
}

#[tokio::test]
async fn the_switch_answers_a_controller_from_its_description() {
    let (addr, ctl) = controller(&[4]).await;
    let sw = support::connect(&addr, Some(support::quiet()), support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();

    let xid = c.send(msg::FEATURES_REQUEST, &[]).await;
    let f = c.expect(msg::FEATURES_REPLY).await;
    assert_eq!(f.header.xid, xid);
    let f = wire::Features::parse(&f.body).unwrap();
    assert_eq!(f.datapath_id, 0xabc);
    assert_eq!(f.n_tables, 254);
    assert_eq!(f.n_buffers, 0);

    let ev = sw.wait_for_events("openflow_controller_connected", 1).await;
    assert_eq!(ev[0]["datapath_id"], "0000000000000abc");
    assert_eq!(ev[0]["ports"][1]["name"], "eth2");

    // ECHO, SET_CONFIG then GET_CONFIG, ROLE.
    let xid = c.send(msg::ECHO_REQUEST, b"abc").await;
    let e = c.expect(msg::ECHO_REPLY).await;
    assert_eq!((e.header.xid, e.body.as_slice()), (xid, b"abc".as_slice()));
    c.send(msg::SET_CONFIG, &wire::config_body(0, 512)).await;
    let xid = c.send(msg::GET_CONFIG_REQUEST, &[]).await;
    let g = c.expect(msg::GET_CONFIG_REPLY).await;
    assert_eq!(g.header.xid, xid);
    assert_eq!(wire::parse_config(&g.body).unwrap(), (0, 512));
    let xid = c.send(msg::ROLE_REQUEST, &wire::role_body(2, 7)).await;
    let r = c.expect(msg::ROLE_REPLY).await;
    assert_eq!(r.header.xid, xid);
    assert_eq!(wire::parse_role(&r.body).unwrap(), (2, 7));

    // DESC and PORT_DESC.
    let xid = c
        .send(
            msg::MULTIPART_REQUEST,
            &wire::multipart_body(wire::mp::DESC, 0, &[]),
        )
        .await;
    let (_, body, _) = c.multipart(xid).await;
    assert_eq!(wire::parse_desc(&body).unwrap()[0].1, "NetGet");
    let xid = c
        .send(
            msg::MULTIPART_REQUEST,
            &wire::multipart_body(wire::mp::PORT_DESC, 0, &[]),
        )
        .await;
    let (_, body, _) = c.multipart(xid).await;
    let ports = wire::parse_ports(&body).unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].hw_addr, [2, 0xaa, 0, 0, 0, 1]);

    // An unsupported query is refused with BAD_MULTIPART.
    let xid = c
        .send(
            msg::MULTIPART_REQUEST,
            &wire::multipart_body(wire::mp::TABLE_FEATURES, 0, &[]),
        )
        .await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::BAD_REQUEST, err::BAD_REQUEST_BAD_MULTIPART)
    );
    c.barrier().await;
}

#[tokio::test]
async fn flow_mods_are_validated_kept_and_reported() {
    let (addr, ctl) = controller(&[4]).await;
    let sw = support::connect(&addr, Some(support::quiet()), support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();

    // A valid flow: reported to the model and kept.
    c.flow_mod(
        json!({"priority": 0, "match": {}, "actions": [{"type": "output", "port": "controller"}]}),
    )
    .await;
    c.flow_mod(
        json!({"priority": 9, "match": {"in_port": 1, "eth_dst": HOST_B},
                      "actions": [{"type": "output", "port": 2}]}),
    )
    .await;
    let ev = sw.wait_for_events("openflow_flow_mod_received", 2).await;
    assert_eq!(ev[0]["priority"], 0);
    assert_eq!(ev[0]["instructions"][0]["actions"][0]["port"], "controller");
    assert_eq!(ev[1]["match"], json!({"in_port": 1, "eth_dst": HOST_B}));
    assert_eq!(ev[1]["flow_count"], 2);

    // A match with a prerequisite missing: BAD_MATCH / BAD_PREREQ, nothing kept.
    let raw = wire::FlowMod {
        cookie: 0,
        cookie_mask: 0,
        table_id: 0,
        command: wire::flow_cmd::ADD,
        idle_timeout: 0,
        hard_timeout: 0,
        priority: 1,
        buffer_id: wire::NO_BUFFER,
        out_port: wire::port::ANY,
        out_group: wire::GROUP_ANY,
        flags: 0,
        matched: wire::Match {
            oxms: vec![wire::Oxm::basic(14, vec![0, 80])],
        },
        instructions: vec![],
    };
    let xid = c.send(msg::FLOW_MOD, &raw.encode()).await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::BAD_MATCH, err::BAD_MATCH_BAD_PREREQ)
    );
    // Output to a port the switch does not have: BAD_ACTION / BAD_OUT_PORT.
    let xid = c
        .flow_mod(json!({"priority": 3, "match": {}, "actions": [{"type": "output", "port": 9}]}))
        .await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::BAD_ACTION, err::BAD_ACTION_BAD_OUT_PORT)
    );
    // A table that does not exist.
    let xid = c
        .flow_mod(json!({"table_id": 254, "priority": 3, "match": {}, "actions": []}))
        .await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::FLOW_MOD_FAILED, err::FLOW_MOD_FAILED_BAD_TABLE_ID)
    );

    // Flow statistics see what was kept; a non-strict delete by match removes one.
    let req = wire::FlowStatsRequest {
        table_id: wire::TABLE_ALL,
        out_port: wire::port::ANY,
        out_group: wire::GROUP_ANY,
        cookie: 0,
        cookie_mask: 0,
        matched: wire::Match::default(),
    };
    let xid = c
        .send(
            msg::MULTIPART_REQUEST,
            &wire::multipart_body(wire::mp::FLOW, 0, &req.encode()),
        )
        .await;
    let (_, body, _) = c.multipart(xid).await;
    assert_eq!(wire::FlowStats::parse_all(&body).unwrap().len(), 2);
    c.flow_mod(json!({"command": "delete", "table_id": "all", "match": {"eth_dst": HOST_B}}))
        .await;
    let ev = sw.wait_for_events("openflow_flow_mod_received", 3).await;
    assert_eq!(ev[2]["command"], "delete");
    assert_eq!(ev[2]["flows_affected"], 1);
    assert_eq!(ev[2]["flow_count"], 1);
    c.barrier().await;
}

#[tokio::test]
async fn the_flow_table_is_bounded_and_large_replies_are_split() {
    let (addr, ctl) = controller(&[4]).await;
    let _sw = support::connect(&addr, Some(support::quiet()), support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();
    let max = netget::client::openflow::MAX_FLOWS;
    for i in 0..max {
        c.flow_mod(
            json!({"priority": 100, "match": {"udp_dst": i as u64, "eth_type": "0x0800"},
                          "actions": [{"type": "output", "port": 1}]}),
        )
        .await;
    }
    c.barrier().await;
    let xid = c
        .flow_mod(json!({"priority": 100, "match": {"udp_dst": 60000, "eth_type": "0x0800"}, "actions": []}))
        .await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::FLOW_MOD_FAILED, err::FLOW_MOD_FAILED_TABLE_FULL)
    );
    let req = wire::FlowStatsRequest {
        table_id: wire::TABLE_ALL,
        out_port: wire::port::ANY,
        out_group: wire::GROUP_ANY,
        cookie: 0,
        cookie_mask: 0,
        matched: wire::Match::default(),
    };
    let xid = c
        .send(
            msg::MULTIPART_REQUEST,
            &wire::multipart_body(wire::mp::FLOW, 0, &req.encode()),
        )
        .await;
    let (_, parts) = c.multipart_parts(xid).await;
    assert!(parts.len() > 1, "{max} flows fit one 64 KiB message?");
    let total: usize = parts
        .iter()
        .map(|p| wire::FlowStats::parse_all(p).unwrap().len())
        .sum();
    assert_eq!(total, max);
}

#[tokio::test]
async fn packet_outs_are_checked_and_reported_and_the_models_packet_in_reaches_the_wire() {
    let (addr, ctl) = controller(&[4]).await;
    let sw = support::connect(&addr, Some(support::quiet()), support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();
    let frame = netget::server::openflow::packet::build(&json!({
        "eth_src": HOST_B, "eth_dst": HOST_A,
        "arp": {"op": "reply", "spa": "10.0.0.2", "tpa": "10.0.0.1"}
    }))
    .unwrap();
    let po = |buffer_id: u32, in_port: u32| wire::PacketOut {
        buffer_id,
        in_port,
        actions: vec![wire::Action::Output {
            port: 1,
            max_len: 0,
        }],
        data: if buffer_id == wire::NO_BUFFER {
            frame.clone()
        } else {
            vec![]
        },
    };
    let xid = c.send(msg::PACKET_OUT, &po(5, 1).encode()).await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::BAD_REQUEST, err::BAD_REQUEST_BUFFER_UNKNOWN)
    );
    let xid = c
        .send(msg::PACKET_OUT, &po(wire::NO_BUFFER, 7).encode())
        .await;
    assert_eq!(
        c.expect_error(xid).await,
        (err::BAD_REQUEST, err::BAD_REQUEST_BAD_PORT)
    );
    c.send(
        msg::PACKET_OUT,
        &po(wire::NO_BUFFER, wire::port::CONTROLLER).encode(),
    )
    .await;
    let ev = sw.wait_for_events("openflow_packet_out_received", 1).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["in_port"], "controller");
    assert_eq!(ev[0]["actions"][0]["port"], 1);
    assert_eq!(ev[0]["packet"]["arp"]["op"], "reply");

    // The model's PACKET_IN, put on the wire through the operator's channel.
    let out = sw
        .send(
            json!({"type": "openflow_packet_in", "in_port": 2, "packet": {
            "eth_src": HOST_B, "eth_dst": HOST_A, "ipv4": {"src": "10.0.0.2", "dst": "10.0.0.1"},
            "udp": {"src_port": 5000, "dst_port": 53}, "payload_text": "q"}}),
        )
        .await;
    assert!(matches!(out, ClientSendOutcome::Sent { .. }), "{out:?}");
    let pi = c.expect(msg::PACKET_IN).await;
    let pi = wire::PacketIn::parse(&pi.body).unwrap();
    assert_eq!(pi.in_port(), Some(2));
    assert_eq!(pi.buffer_id, wire::NO_BUFFER);
    assert_eq!(pi.total_len as usize, pi.data.len());
    let d = netget::server::openflow::packet::describe(&pi.data);
    assert_eq!(d["udp"]["dst_port"], 53);
    assert_eq!(d["payload_text"], "q");
    // A port the switch does not have is refused before anything is sent.
    let out = sw
        .send(json!({"type": "openflow_packet_in", "in_port": 9, "packet": {"eth_src": HOST_A, "arp": {"spa": "10.0.0.1", "tpa": "10.0.0.2"}}}))
        .await;
    assert!(matches!(out, ClientSendOutcome::Rejected { .. }), "{out:?}");
    // A port change is announced and the port list follows it.
    let out = sw
        .send(json!({"type": "openflow_port_status", "reason": "modify", "port_no": 2, "link_down": true}))
        .await;
    assert!(matches!(out, ClientSendOutcome::Sent { .. }), "{out:?}");
    let ps = c.expect(msg::PORT_STATUS).await;
    let (reason, port) = wire::parse_port_status(&ps.body).unwrap();
    assert_eq!((reason, port.port_no, port.name.as_str()), (2, 2, "eth2"));
    assert_eq!(
        port.state & wire::PORT_STATE_LINK_DOWN,
        wire::PORT_STATE_LINK_DOWN
    );
    c.barrier().await;
}

#[tokio::test]
async fn the_models_answer_is_acted_on_and_no_answer_sends_nothing() {
    // The policy answers the table-miss FLOW_MOD with a PACKET_IN.
    let (addr, ctl) = controller(&[1, 4, 5]).await;
    let _sw = support::connect(&addr, Some(support::policy()), support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();
    c.flow_mod(
        json!({"priority": 0, "match": {}, "actions": [{"type": "output", "port": "controller"}]}),
    )
    .await;
    let pi = wire::PacketIn::parse(&c.expect(msg::PACKET_IN).await.body).unwrap();
    assert_eq!(pi.in_port(), Some(1));
    let d = netget::server::openflow::packet::describe(&pi.data);
    assert_eq!(d["eth_dst"], HOST_B);
    assert_eq!(d["icmp"]["type"], 8);

    // No routing and an unreachable model: the same FLOW_MOD produces nothing.
    let (addr, ctl) = controller(&[4]).await;
    let sw = support::connect(&addr, None, support::params())
        .await
        .unwrap();
    let mut c = ctl.await.unwrap();
    c.send(msg::FEATURES_REQUEST, &[]).await;
    c.expect(msg::FEATURES_REPLY).await;
    c.flow_mod(
        json!({"priority": 0, "match": {}, "actions": [{"type": "output", "port": "controller"}]}),
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while sw
        .log_text()
        .matches("decision=fail_closed_llm_error")
        .count()
        < 2
    {
        assert!(tokio::time::Instant::now() < deadline, "{}", sw.log_text());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    c.barrier().await;
}

#[tokio::test]
async fn a_controller_without_1_3_is_refused() {
    let (addr, ctl) = controller(&[1]).await;
    let err = support::connect(&addr, Some(support::quiet()), support::params())
        .await
        .err()
        .expect("a 1.0-only controller was accepted");
    assert!(format!("{err:#}").contains("1.3"), "{err:#}");
    let mut c = ctl.await.unwrap();
    let m = c.expect(msg::ERROR).await;
    let e = wire::ErrorMsg::parse(&m.body).unwrap();
    assert_eq!(
        (e.etype, e.code),
        (err::HELLO_FAILED, err::HELLO_INCOMPATIBLE)
    );
    let mut buf = [0u8; 1];
    assert_eq!(
        c.s.read(&mut buf).await.unwrap_or(0),
        0,
        "the switch hung up"
    );
}
