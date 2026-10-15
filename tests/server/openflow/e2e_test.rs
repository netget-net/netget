//! The OpenFlow controller's own guarantees, driven from a raw switch socket: the handshake,
//! the model's flows and PACKET_OUTs reaching the wire byte for byte, xid matching and
//! multipart reassembly, error attribution, the bounds, and the fail-closed paths (nothing is
//! sent — no flood, no flow — when the model cannot answer). Open vSwitch drives it in
//! `real_peer_test.rs`.
//!
//! A python policy (`support::POLICY`) plays the model, except in the last test, where a mocked
//! LLM answers the NetGet binary: 2 LLM calls.
use super::support::{self, ping, RawSwitch, BLOCKED, HOST_B};
use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::server::openflow::wire::{self, err, msg, Action, Instruction, VERSION_1_3};
use netget::state::client_handles::ClientSendOutcome;
use serde_json::json;
use std::time::Duration;

fn flow_mod(m: &wire::Message) -> wire::FlowMod {
    assert_eq!(m.header.msg_type, msg::FLOW_MOD);
    wire::FlowMod::parse(&m.body).unwrap()
}

/// Handshake, then read and check the table-miss flow the policy installs on connect.
async fn connected(c: &support::Controller) -> RawSwitch {
    let mut sw = RawSwitch::connect(c.addr()).await;
    let config = sw.handshake().await;
    assert_eq!(config, (0, wire::CML_NO_BUFFER), "whole packets were asked for");
    let fm = flow_mod(&sw.expect(msg::FLOW_MOD).await);
    assert_eq!(fm.priority, 0);
    assert!(fm.matched.oxms.is_empty());
    assert_eq!(
        fm.instructions,
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: wire::port::CONTROLLER,
            max_len: wire::CML_NO_BUFFER
        }])]
    );
    sw
}

#[tokio::test]
async fn the_handshake_announces_the_switch_and_the_models_table_miss_flow_reaches_it() {
    let c = support::start(support::policy(), json!({})).await;
    let mut sw = connected(&c).await;
    let ev = c.wait_for_events("openflow_switch_connected", 1).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["datapath_id"], "0000000000000abc");
    assert_eq!(ev[0]["version"], "1.3");
    assert_eq!(ev[0]["n_tables"], 254);
    assert_eq!(ev[0]["ports"][0]["name"], "p1");
    assert_eq!(ev[0]["ports"][1]["hw_addr"], "02:aa:00:00:00:02");
    assert_eq!(ev[0]["description"]["mfr_desc"], "Raw");
    assert!(c.wait_for_log("decision=model_answer").await);
    sw.nothing_before_echo(900).await;
    support::oracle(&sw.chunks).assert_clean();
}

#[tokio::test]
async fn a_packet_in_reaches_the_model_decoded_and_its_flow_and_packet_out_reach_the_switch() {
    let c = support::start(support::policy(), json!({})).await;
    let mut sw = connected(&c).await;

    // A packet for HOST_B: a flow to port 2 and the packet itself sent there.
    let frame = ping(HOST_B);
    sw.packet_in(10, 1, &frame).await;
    let fm = flow_mod(&sw.expect(msg::FLOW_MOD).await);
    assert_eq!(fm.priority, 10);
    assert_eq!(fm.idle_timeout, 30);
    let m = netget::server::openflow::fields::match_to_json(&fm.matched);
    assert_eq!(m, json!({"in_port": 1, "eth_dst": HOST_B}));
    let po = sw.expect(msg::PACKET_OUT).await;
    let po = wire::PacketOut::parse(&po.body).unwrap();
    assert_eq!(po.buffer_id, wire::NO_BUFFER);
    assert_eq!(po.in_port, 1);
    assert_eq!(po.data, frame, "the packet went out byte for byte");
    assert_eq!(po.actions, vec![Action::Output { port: 2, max_len: wire::CML_NO_BUFFER }]);
    let ev = c.wait_for_events("openflow_packet_in", 1).await;
    assert_eq!(ev[0]["in_port"], 1);
    assert_eq!(ev[0]["reason"], "no_match");
    assert_eq!(ev[0]["buffered"], false);
    assert_eq!(ev[0]["packet"]["eth_dst"], HOST_B);
    assert_eq!(ev[0]["packet"]["ipv4"]["dst"], "10.0.0.2");
    assert_eq!(ev[0]["packet"]["icmp"]["name"], "echo_request");
    assert!(ev[0]["packet"]["payload_text"]
        .as_str()
        .unwrap()
        .starts_with("netget openflow test"));

    // An unknown destination is flooded.
    sw.packet_in(11, 2, &ping("02:00:00:00:00:77")).await;
    let po = wire::PacketOut::parse(&sw.expect(msg::PACKET_OUT).await.body).unwrap();
    assert_eq!(po.in_port, 2);
    assert_eq!(po.actions, vec![Action::Output { port: wire::port::FLOOD, max_len: wire::CML_NO_BUFFER }]);

    // A blocked destination is dropped: nothing at all reaches the switch.
    sw.packet_in(12, 1, &ping(BLOCKED)).await;
    assert!(c.wait_for_log("decision=model_reject").await);
    sw.nothing_before_echo(901).await;

    support::oracle(&sw.chunks).assert_clean();
}

#[tokio::test]
async fn with_no_answer_from_the_model_nothing_is_sent_no_flow_and_no_flood() {
    // No routing: every event goes to a model at 127.0.0.1:1, which is not there.
    let c = support::start(None, json!({})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    sw.packet_in(10, 1, &ping(HOST_B)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while c.log_text().matches("decision=fail_closed_llm_error").count() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "{}", c.log_text());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The switch_connected and the packet_in both failed closed: no FLOW_MOD, no PACKET_OUT.
    sw.nothing_before_echo(902).await;
    assert!(!c.log_text().contains("decision=model_answer"));
}

#[tokio::test]
async fn a_silent_or_invalid_answer_sends_nothing_and_says_which() {
    let c = support::start(support::static_rule(json!([])), json!({})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    sw.packet_in(10, 1, &ping(HOST_B)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while c.log_text().matches("decision=model_silent").count() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "{}", c.log_text());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sw.nothing_before_echo(903).await;

    // A FLOW_MOD whose match names no such field, and a PACKET_OUT to port "any".
    let c = support::start(
        support::static_rule(json!([
            {"type": "openflow_flow_mod", "match": {"no_such_field": 1}, "actions": []},
            {"type": "openflow_packet_out", "actions": [{"type": "output", "port": "any"}]}
        ])),
        json!({}),
    )
    .await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    assert!(c.wait_for_log("decision=fail_closed_bad_action").await);
    sw.nothing_before_echo(904).await;
}

#[tokio::test]
async fn only_openflow_1_3_is_negotiated() {
    let c = support::start(support::policy(), json!({})).await;

    // A switch that only speaks 1.0 is refused with HELLO_FAILED / INCOMPATIBLE.
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.send_raw(&wire::encode(1, msg::HELLO, 1, &wire::hello_body(&[1])).unwrap())
        .await;
    let hello = sw.recv().await;
    assert_eq!(hello.header.msg_type, msg::HELLO);
    let e = sw.recv().await;
    assert_eq!(e.header.msg_type, msg::ERROR);
    let e = wire::ErrorMsg::parse(&e.body).unwrap();
    assert_eq!((e.etype, e.code), (err::HELLO_FAILED, err::HELLO_INCOMPATIBLE));
    assert!(String::from_utf8_lossy(&e.data).contains("1.3"));
    assert!(sw.closed_within(Duration::from_secs(10)).await);
    assert!(c.wait_for_log("decision=protocol_reject_version").await);

    // 1.0 to 1.5 in the bitmap under a 1.5 header: 1.3 is chosen.
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.send_raw(&wire::encode(6, msg::HELLO, 1, &wire::hello_body(&[1, 4, 5, 6])).unwrap())
        .await;
    assert_eq!(sw.expect(msg::HELLO).await.header.version, VERSION_1_3);
    assert_eq!(sw.expect(msg::FEATURES_REQUEST).await.header.version, VERSION_1_3);

    // No bitmap and a 1.4 header: the lower version, 1.3.
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.send_raw(&wire::encode(5, msg::HELLO, 1, &[]).unwrap()).await;
    sw.expect(msg::HELLO).await;
    assert_eq!(sw.expect(msg::FEATURES_REQUEST).await.header.version, VERSION_1_3);

    // After negotiation, a message of another version is refused with BAD_VERSION.
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    sw.expect(msg::FLOW_MOD).await;
    sw.send_raw(&wire::encode(5, msg::ECHO_REQUEST, 77, &[]).unwrap()).await;
    let e = sw.expect(msg::ERROR).await;
    let e = wire::ErrorMsg::parse(&e.body).unwrap();
    assert_eq!((e.etype, e.code), (err::BAD_REQUEST, err::BAD_REQUEST_BAD_VERSION));
}

#[tokio::test]
async fn replies_are_matched_to_requests_by_xid_and_multipart_is_reassembled() {
    let c = support::start(support::script(support::STATS_POLICY), json!({})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    sw.expect(msg::FLOW_MOD).await;
    let req = sw.expect(msg::MULTIPART_REQUEST).await;
    let (t, _, body) = wire::parse_multipart(&req.body).unwrap();
    assert_eq!(t, wire::mp::FLOW);
    let filter = wire::FlowStatsRequest::parse(body).unwrap();
    assert_eq!(filter.table_id, wire::TABLE_ALL);
    let xid = req.header.xid;

    let entry = |priority: u16| {
        let mut b = Vec::new();
        wire::FlowStats {
            table_id: 0,
            duration_sec: 5,
            duration_nsec: 0,
            priority,
            idle_timeout: 0,
            hard_timeout: 0,
            flags: 0,
            cookie: 0,
            packet_count: 3,
            byte_count: 300,
            matched: wire::Match::default(),
            instructions: vec![Instruction::ApplyActions(vec![Action::Output {
                port: 2,
                max_len: 0,
            }])],
        }
        .encode(&mut b);
        b
    };
    // A reply nobody asked for (wrong xid), and a FEATURES_REPLY nobody asked for: ignored.
    sw.send(msg::MULTIPART_REPLY, xid + 1000, &wire::multipart_body(wire::mp::FLOW, 0, &entry(99)))
        .await;
    sw.send(msg::FEATURES_REPLY, xid + 1001, &[0; 24]).await;
    // The real reply, in two parts.
    sw.send(msg::MULTIPART_REPLY, xid, &wire::multipart_body(wire::mp::FLOW, wire::mp::MORE, &entry(1)))
        .await;
    sw.send(msg::MULTIPART_REPLY, xid, &wire::multipart_body(wire::mp::FLOW, 0, &entry(2)))
        .await;
    let ev = c.wait_for_events("openflow_stats_reply", 1).await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    let entries = ev[0]["entries"].as_array().unwrap();
    let priorities: Vec<u64> = entries.iter().map(|e| e["priority"].as_u64().unwrap()).collect();
    assert_eq!(priorities, vec![1, 2], "both parts, and not the unsolicited one");
    assert_eq!(entries[0]["packet_count"], 3);
    assert_eq!(entries[0]["instructions"][0]["actions"][0]["port"], 2);
    assert!(c.log_text().contains("decision=protocol_unsolicited_reply"));
    // The xid is spent: the same reply again raises nothing new.
    sw.send(msg::MULTIPART_REPLY, xid, &wire::multipart_body(wire::mp::FLOW, 0, &entry(3)))
        .await;
    sw.nothing_before_echo(905).await;
    assert_eq!(c.events("openflow_stats_reply").await.len(), 1);
}

#[tokio::test]
async fn a_switch_error_is_traced_back_to_the_models_flow_mod() {
    let c = support::start(support::policy(), json!({})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    let fm = sw.expect(msg::FLOW_MOD).await;
    sw.send(
        msg::ERROR,
        fm.header.xid,
        &wire::error_body(err::BAD_MATCH, err::BAD_MATCH_BAD_PREREQ, &fm.raw()),
    )
    .await;
    let ev = c.wait_for_events("openflow_error", 1).await;
    assert_eq!(ev[0]["error_type"], "BAD_MATCH");
    assert_eq!(ev[0]["error_code"], "BAD_PREREQ");
    assert_eq!(ev[0]["request"]["type"], "FLOW_MOD");
    assert!(ev[0]["request"]["what"].as_str().unwrap().contains("flow_mod add priority 0"));
}

#[tokio::test]
async fn a_chain_of_model_turns_stops_at_the_follow_up_depth() {
    // Every ERROR is answered with another FLOW_MOD, which the switch refuses again.
    let c = support::start(
        support::static_rule(json!([
            {"type": "openflow_flow_mod", "priority": 5, "match": {"in_port": 1}, "actions": []}
        ])),
        json!({}),
    )
    .await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    let mut flow_mods = 0;
    loop {
        let Some(m) = sw.recv_within(Duration::from_secs(5)).await else {
            break;
        };
        if m.header.msg_type == msg::FLOW_MOD {
            flow_mods += 1;
            sw.send(
                msg::ERROR,
                m.header.xid,
                &wire::error_body(err::FLOW_MOD_FAILED, err::FLOW_MOD_FAILED_UNKNOWN, &m.raw()),
            )
            .await;
        }
    }
    assert_eq!(
        flow_mods,
        netget::server::openflow::MAX_FOLLOWUP_DEPTH as usize,
        "one FLOW_MOD per depth 0..MAX_FOLLOWUP_DEPTH-1"
    );
    assert!(c.wait_for_log("decision=followup_depth").await);
}

#[tokio::test]
async fn bounds_hold_against_a_hostile_switch() {
    // A header claiming fewer than eight bytes ends the connection.
    let c = support::start(support::policy(), json!({"echo_interval_secs": 1})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.send_raw(&[4, 0, 0, 4, 0, 0, 0, 1]).await;
    assert!(sw.closed_within(Duration::from_secs(10)).await);

    // A PACKET_IN whose match carries more OXMs than the bound is refused with an ERROR.
    let mut sw = connected(&c).await;
    let mut oxms = Vec::new();
    for i in 0..=wire::MAX_OXMS {
        oxms.push(wire::Oxm { class: 1, field: (i % 127) as u8, value: vec![(i / 127) as u8], mask: None });
    }
    let pi = wire::PacketIn {
        buffer_id: wire::NO_BUFFER,
        total_len: 0,
        reason: 0,
        table_id: 0,
        cookie: 0,
        matched: wire::Match { oxms },
        data: Vec::new(),
    };
    sw.send(msg::PACKET_IN, 50, &pi.encode()).await;
    let e = sw.expect(msg::ERROR).await;
    assert_eq!(e.header.xid, 50);
    let e = wire::ErrorMsg::parse(&e.body).unwrap();
    assert_eq!((e.etype, e.code), (err::BAD_REQUEST, err::BAD_REQUEST_BAD_LEN));
    assert!(c.events("openflow_packet_in").await.is_empty());

    // A switch that stops answering ECHO is disconnected (echo_interval_secs 1).
    let mut silent = RawSwitch::connect(c.addr()).await;
    silent.handshake().await;
    silent.expect(msg::FLOW_MOD).await;
    let started = std::time::Instant::now();
    let echo = silent.recv().await;
    assert_eq!(echo.header.msg_type, msg::ECHO_REQUEST, "a quiet switch is probed");
    assert!(silent.closed_within(Duration::from_secs(10)).await);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(c.wait_for_log("decision=protocol_timeout").await);
    drop(sw);

    // A multipart reply past MAX_MULTIPART_BYTES is discarded, and the model is told.
    let c = support::start(support::script(support::STATS_POLICY), json!({})).await;
    let mut sw = RawSwitch::connect(c.addr()).await;
    sw.handshake().await;
    sw.expect(msg::FLOW_MOD).await;
    let req = sw.expect(msg::MULTIPART_REQUEST).await;
    let part = vec![0u8; 60_000];
    let parts = netget::server::openflow::MAX_MULTIPART_BYTES / part.len() + 1;
    for _ in 0..parts {
        sw.send(msg::MULTIPART_REPLY, req.header.xid, &wire::multipart_body(wire::mp::FLOW, wire::mp::MORE, &part))
            .await;
    }
    assert!(c.wait_for_log("decision=fail_closed_multipart_too_large").await);
    let ev = c.wait_for_events("openflow_stats_reply", 1).await;
    assert!(ev[0]["error"].as_str().unwrap().contains("discarded"), "{ev:?}");
    sw.nothing_before_echo(906).await;
}

#[tokio::test]
async fn an_operator_can_message_and_disconnect_a_switch() {
    let c = support::start(support::policy(), json!({})).await;
    let mut sw = connected(&c).await;
    let conn = c.connections().await[0];
    let outcome = c
        .state
        .send_to_peer(
            c.id,
            conn,
            json!({"type": "openflow_flow_mod", "priority": 7, "match": {"eth_type": "0x0800", "udp_dst": 53},
                   "actions": [{"type": "output", "port": "normal"}]}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ClientSendOutcome::Executed { .. }), "{outcome:?}");
    let fm = flow_mod(&sw.expect(msg::FLOW_MOD).await);
    assert_eq!(fm.priority, 7);
    let m = netget::server::openflow::fields::match_to_json(&fm.matched);
    assert_eq!(m, json!({"eth_type": "0x0800", "ip_proto": 17, "udp_dst": 53}));

    let bad = c
        .state
        .send_to_peer(
            c.id,
            conn,
            json!({"type": "openflow_packet_out", "actions": []}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(bad, ClientSendOutcome::Rejected { .. }), "{bad:?}");

    let gone = c
        .state
        .send_to_peer(c.id, conn, json!({"type": "openflow_disconnect_switch"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(matches!(gone, ClientSendOutcome::Disconnected));
    assert!(sw.closed_within(Duration::from_secs(10)).await);
}

/// The model's own path: a mocked LLM installs the table-miss flow and answers a PACKET_IN for
/// the NetGet binary.
#[tokio::test]
async fn the_model_drives_the_controller_through_the_binary() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via openflow").with_mock(|mock| {
        mock.on_instruction_containing("via openflow")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "openflow",
                "instruction": "Install a table-miss flow; send every packet to port 2"
            }]))
            .expect_calls(1)
            .and()
            .on_event("openflow_switch_connected")
            .respond_with_actions(json!([{
                "type": "openflow_flow_mod", "priority": 0, "match": {},
                "actions": [{"type": "output", "port": "controller"}]
            }]))
            .expect_calls(1)
            .and()
            .on_event("openflow_packet_in")
            .respond_with_actions_from_event(|e| {
                json!([{
                    "type": "openflow_packet_out",
                    "packet_in_id": e["packet_in_id"],
                    "actions": [{"type": "output", "port": 2}]
                }])
            })
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let mut sw = RawSwitch::connect(([127, 0, 0, 1], server.port).into()).await;
    sw.handshake().await;
    sw.expect(msg::FLOW_MOD).await;
    let frame = ping(HOST_B);
    sw.packet_in(20, 1, &frame).await;
    let po = wire::PacketOut::parse(&sw.expect(msg::PACKET_OUT).await.body).unwrap();
    assert_eq!(po.data, frame);
    assert_eq!(po.actions, vec![Action::Output { port: 2, max_len: wire::CML_NO_BUFFER }]);
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
