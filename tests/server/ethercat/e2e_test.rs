//! NetGet's EtherCAT slave over EtherCAT-in-UDP with a python policy standing in for the model.
//!
//! The first test is driven by ethercrab 0.7 — an independent Rust EtherCAT MainDevice whose
//! frames reach the slave through `support::crab`'s UDP bridge, which changes the
//! encapsulation and nothing else. The others use a hand-built master for the paths a
//! well-behaved master never takes (an unreachable model, bounds). Every payload both ways goes
//! through tshark's ecatf / ecat / ecat_mailbox dissectors. No LLM calls.
use super::support::*;
use crate::helpers::pcap_oracle::PcapOracle;
use ethercrab::std::ethercat_now;
use netget::server::ethercat::frame::{self, cmd, Datagram};
use serde_json::json;
use std::time::Duration;

fn oracle(payloads: &[(bool, Vec<u8>)]) -> PcapOracle {
    let mut o = PcapOracle::udp("ethercat").port(frame::UDP_PORT);
    for (to_slave, p) in payloads {
        o = if *to_slave {
            o.to_server(p)
        } else {
            o.from_server(p)
        };
    }
    o
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ethercrab_scans_configures_and_runs_the_slave_to_op() {
    let mut params = slave_params();
    // The default 128-octet mailbox carries the 58-octet string in one normal transfer.
    // (ethercrab 0.7 drops the data of an initiate response when segments follow — SOEM and
    // ETG.1000.6 keep it — so the segmented path is not one ethercrab can be evidence for.)
    params["mailbox_size"] = json!(128);
    let seg = start_segment(script(SLAVE_POLICY), params).await;
    let (md, record, bridge) = crab::main_device(seg.addr);

    let group = md
        .init_single_group::<4, 64>(ethercat_now)
        .await
        .unwrap_or_else(|e| panic!("ethercrab init: {e}\n{}", seg.log_text()));
    assert_eq!(
        group.len(),
        1,
        "one slave counted by the BRD working counter"
    );
    {
        let s = group.iter(&md).next().unwrap();
        assert_eq!(
            s.name(),
            "NetGet Test Slave",
            "the name from the SII strings"
        );
        let id = s.identity();
        assert_eq!(
            (id.vendor_id, id.product_id, id.revision, id.serial),
            (0xABC, 0x12345, 7, 99)
        );
        assert_eq!(s.configured_address(), 0x1000, "ethercrab's own address");
        // Rust answers the identity object; the model answers the declared ones.
        assert_eq!(s.sdo_read::<u32>(0x1018, 1).await.unwrap(), 0xABC);
        assert_eq!(s.sdo_read::<u16>(0x8000, 1).await.unwrap(), 1500);
        s.sdo_write(0x8000, 1, 1200u16).await.unwrap();
        let refused = s.sdo_write(0x8000, 1, 4000u16).await;
        assert!(refused.is_err(), "the model aborts a value over 3000");
        let text = s.sdo_read::<[u8; 58]>(0x2001, 0).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&text).unwrap(),
            "NetGet EtherCAT slave, serial text that needs SDO segments"
        );
        assert!(
            s.sdo_read::<u32>(0x3000, 0).await.is_err(),
            "not in the dictionary"
        );
    }
    let writes = seg.events("ethercat_sdo_write").await;
    assert!(
        writes.iter().any(|e| e["value"] == json!(1200)),
        "{writes:?}"
    );

    let group = group
        .into_safe_op(&md)
        .await
        .unwrap_or_else(|e| panic!("SAFE-OP: {e}\n{}", seg.log_text()));
    let r = group.tx_rx(&md).await.unwrap();
    assert_eq!(r.working_counter, 3, "outputs +2, inputs +1");
    {
        let s = group.subdevice(&md, 0).unwrap();
        assert_eq!(&s.inputs_raw()[..], &[42, 0, 1], "count 42, ready");
        // motor_on and setpoint 300, packed after the 1-bit bool.
        s.outputs_raw_mut().copy_from_slice(&[0x59, 0x02, 0x00]);
    }
    for _ in 0..5 {
        group.tx_rx(&md).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let group = group.request_into_op(&md).await.unwrap();
    let mut reached = false;
    let mut count = 0;
    for _ in 0..1000 {
        let r = group.tx_rx(&md).await.unwrap();
        assert_eq!(r.working_counter, 3);
        let s = group.subdevice(&md, 0).unwrap();
        count = u16::from_le_bytes([s.inputs_raw()[0], s.inputs_raw()[1]]);
        if r.all_op() && count == 301 {
            reached = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reached,
        "OP with the model's reply to the outputs (count {count})\n{}",
        seg.log_text()
    );
    let out = seg
        .wait_event("ethercat_outputs_changed", |e| {
            e["outputs"]["setpoint"] == json!(300)
        })
        .await
        .expect("the outputs reached the model");
    assert_eq!(out["outputs"]["motor_on"], json!(true));
    assert_eq!(out["station_address"], json!(0x1000));
    let log = seg.log_text();
    assert!(log.contains("decision=model_accept"), "{log}");
    assert!(log.contains("decision=model_reject"), "{log}");

    let group = group.into_safe_op(&md).await.unwrap();
    let group = group.into_pre_op(&md).await.unwrap();
    let _ = group.into_init(&md).await.unwrap();
    bridge.abort();

    let payloads = record.lock().unwrap().clone();
    oracle(&payloads).assert_clean();
    let rows = oracle(&payloads)
        .fields(&["ecat.cmd", "ecat.cnt", "ecat_mailbox.coe.sdoidx"])
        .expect("tshark");
    let col = |r: &Vec<String>, i: usize| r.get(i).cloned().unwrap_or_default();
    // A frame may carry several datagrams: tshark joins each field's occurrences with ','.
    let lrw_wkc_3 = rows.iter().any(|r| {
        col(r, 0)
            .split(',')
            .zip(col(r, 1).split(','))
            .any(|(c, n)| c == "0x0c" && n == "3")
    });
    assert!(
        lrw_wkc_3,
        "tshark reads an LRW that came back with working counter 3: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| col(r, 2) == "0x2001"),
        "tshark read the CoE SDO index of the string upload: {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_model_refuses_the_state_change_and_aborts_the_sdo() {
    // No handlers: every question goes to a model at 127.0.0.1:1, which is not there.
    let seg = start_segment(None, slave_params()).await;
    let mut m = UdpMaster::new(seg.addr).await;
    let d = m
        .one(Datagram::physical(cmd::BRD, 0, 0x0000, vec![0]))
        .await;
    assert_eq!(d.wkc, 1);
    assert_eq!(
        m.one(Datagram::physical(cmd::APWR, 0, 0x0010, vec![0x01, 0x10]))
            .await
            .wkc,
        1
    );
    let mut sms = Vec::new();
    for (start, ctl) in [(0x1000u16, 0x26u8), (0x1080, 0x22)] {
        sms.extend_from_slice(&start.to_le_bytes());
        sms.extend_from_slice(&128u16.to_le_bytes());
        sms.extend_from_slice(&[ctl, 0, 1, 0]);
    }
    assert_eq!(m.fpwr(0x1001, 0x0800, sms).await, 1);
    assert_eq!(m.fpwr(0x1001, 0x0120, vec![0x02, 0]).await, 1);
    let (st, code) = m.wait_al_change(0x1001, 0x01, 60).await;
    assert_eq!(st, 0x11, "INIT with the error bit: refused, not taken");
    assert_eq!(code, 0x0001, "unspecified error");
    assert!(
        seg.wait_for_log("decision=fail_closed_llm_error").await,
        "{}",
        seg.log_text()
    );
    // Acknowledge and take PRE-OP… the model is still unreachable, so the same answer.
    assert_eq!(m.fpwr(0x1001, 0x0120, vec![0x12, 0]).await, 1);
    let (st, _) = m.wait_al_change(0x1001, 0x01, 60).await;
    assert_eq!(st, 0x11);
    let payloads = m.payloads.clone();
    oracle(&payloads).assert_clean();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_sdo_is_aborted_and_frames_out_of_bounds_get_no_answer() {
    // State changes are accepted by a static rule; SDOs go to the unreachable model.
    let handlers = Some(vec![
        json!({"event_pattern": "ethercat_state_change_request", "handler": {"type": "static",
            "actions": [{"type": "ethercat_accept_state_change"}]}}),
    ]);
    let seg = start_segment(handlers, slave_params()).await;
    let mut m = UdpMaster::new(seg.addr).await;
    m.one(Datagram::physical(cmd::APWR, 0, 0x0010, vec![0x01, 0x10]))
        .await;
    let mut sms = Vec::new();
    for (start, ctl) in [(0x1000u16, 0x26u8), (0x1080, 0x22)] {
        sms.extend_from_slice(&start.to_le_bytes());
        sms.extend_from_slice(&128u16.to_le_bytes());
        sms.extend_from_slice(&[ctl, 0, 1, 0]);
    }
    m.fpwr(0x1001, 0x0800, sms).await;
    m.fpwr(0x1001, 0x0120, vec![0x02, 0]).await;
    assert_eq!(m.wait_al_change(0x1001, 0x01, 30).await.0, 0x02);
    use netget::server::ethercat::coe;
    let req = coe::coe_mailbox(1, coe::upload_request(0x8000, 1)).encode(128);
    assert_eq!(m.fpwr(0x1001, 0x1000, req).await, 1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let reply = loop {
        let d = m.fprd(0x1001, 0x1080, 128).await;
        if d.wkc == 1 {
            break d.data;
        }
        assert!(tokio::time::Instant::now() < deadline, "{}", seg.log_text());
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mbx = coe::Mailbox::parse(&reply).unwrap();
    assert_eq!(
        coe::parse_response(&mbx.data).unwrap(),
        coe::SdoResponse::Abort {
            code: coe::abort::TRANSFER
        }
    );
    assert!(seg.wait_for_log("decision=fail_closed_llm_error").await);

    // 65 datagrams: refused whole, so no answer at all.
    let mut many = frame::encode(
        &(0..64)
            .map(|_| Datagram::physical(cmd::NOP, 0, 0, vec![]))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let last = many.len() - 12;
    many[last + 7] |= 0x80;
    many.extend_from_slice(&[0; 12]);
    let len = (many.len() - 2) as u16 | 0x1000;
    many[..2].copy_from_slice(&len.to_le_bytes());
    m.send_raw(&many).await;
    assert!(
        m.recv_raw(500).await.is_none(),
        "an over-long frame is dropped"
    );
    // 64 is answered.
    let ok = frame::encode(
        &(0..64)
            .map(|_| Datagram::physical(cmd::BRD, 0, 0, vec![0]))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    m.send_raw(&ok).await;
    let back = m.recv_raw(2000).await.expect("64 datagrams are processed");
    assert!(frame::decode(&back).unwrap().iter().all(|d| d.wkc == 1));
    // A frame whose header claims more than it carries.
    let mut lie = frame::encode(&[Datagram::physical(cmd::BRD, 0, 0, vec![0; 2])]).unwrap();
    lie[0] = 0xF0;
    m.send_raw(&lie).await;
    assert!(m.recv_raw(500).await.is_none());
    let mut payloads = m.payloads.clone();
    // The malformed frames are the test's own; judge the exchange without them.
    payloads.retain(|(to, p)| !*to || frame::parse(p).is_ok());
    payloads.retain(|(_, p)| frame::parse(p).is_ok());
    oracle(&payloads).assert_clean();
}
