//! NetGet's PROFINET IO device over the lab transport, driven by a hand-built controller
//! (`support::LabPeer` for the Ethernet frames, `support::RpcPeer` for PNIO RPC) and a python
//! policy standing in for the model. Every frame and datagram both ways goes through tshark's
//! pn_dcp / pn_io / pn_rt dissectors. No LLM calls.
use super::support::*;
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::profinet::{blocks, dcp, rpc, rt};
use serde_json::json;
use std::time::Duration;

fn name_of(pdu: &dcp::Pdu) -> Option<String> {
    dcp::DiscoveredDevice::from_blocks([0; 6], &pdu.blocks).name_of_station
}

fn set_name(xid: u32, name: &str) -> Vec<u8> {
    dcp::Pdu {
        frame_id: dcp::frame_id::GET_SET,
        service_id: dcp::service::SET,
        service_type: dcp::service_type::REQUEST,
        xid,
        response_delay: 0,
        blocks: vec![dcp::set_request_block(
            dcp::opt::DEVICE,
            dcp::sub::DEVICE_NAME_OF_STATION,
            true,
            name.as_bytes(),
        )],
    }
    .encode()
    .unwrap()
}

fn oracle_frames(frames: &[(bool, Vec<u8>)]) {
    let mut o = PcapOracle::ethernet("profinet");
    for (_, f) in frames {
        o = o.frame(f);
    }
    o.assert_clean();
}

/// PNIO-CM rides DCE/RPC, and Wireshark's `pn_io` decodes it as a DCE/RPC interface rather
/// than as a protocol layer, so `frame.protocols` stops at `dcerpc`. The expert check runs
/// on the whole exchange; that `pn_io` really read every datagram is asserted from its own
/// fields (an opnum on every one).
fn oracle_rpc(datagrams: &[(bool, Vec<u8>)]) -> Vec<Vec<String>> {
    let build = || {
        let mut o = PcapOracle::udp("profinet").also_named("dcerpc");
        for (to_server, d) in datagrams {
            o = if *to_server {
                o.to_server(d)
            } else {
                o.from_server(d)
            };
        }
        o
    };
    build().assert_clean();
    let rows = build()
        .fields(&["pn_io.opnum", "pn_io.block_type"])
        .expect("tshark");
    assert_eq!(rows.len(), datagrams.len());
    for (i, r) in rows.iter().enumerate() {
        assert!(
            !r[0].is_empty(),
            "datagram #{} was not read by pn_io: {rows:?}",
            i + 1
        );
    }
    rows
}

#[tokio::test]
async fn dcp_identify_get_and_set_go_through_the_model() {
    let dev = start_device(
        script(DEVICE_POLICY),
        json!({"name_of_station": "press-7", "vendor_id": 42, "device_id": 9, "ip": "10.1.2.3",
               "netmask": "255.255.0.0", "type_of_station": "NetGet test press"}),
    )
    .await;
    let mut peer = LabPeer::new(dev.lab.expect("lab link address")).await;
    let mac = peer.mac;

    // Identify All: the configured identity, in the blocks a controller reads.
    let r = peer.identify(1, None).await.expect("no Identify response");
    assert_eq!(
        (r.frame_id, r.service_type, r.xid),
        (dcp::frame_id::IDENTIFY_RESPONSE, 1, 1)
    );
    let d = dcp::DiscoveredDevice::from_blocks(mac, &r.blocks);
    assert_eq!(d.name_of_station.as_deref(), Some("press-7"));
    assert_eq!((d.vendor_id, d.device_id), (Some(42), Some(9)));
    assert_eq!(d.type_of_station.as_deref(), Some("NetGet test press"));
    let ip = d.ip.unwrap();
    assert_eq!(
        (ip.ip.to_string(), ip.netmask.to_string()),
        ("10.1.2.3".into(), "255.255.0.0".into())
    );

    // A name filter that is not ours is silence; ours is answered.
    assert!(peer.identify(2, Some("other")).await.is_none());
    // A ResponseDelayFactor spreads the answer over factor x 10 ms; it still arrives.
    let delayed = dcp::identify_request(21, None, 10).encode().unwrap();
    peer.send_payload(dcp::MULTICAST_IDENTIFY, &delayed).await;
    assert_eq!(
        peer.recv_dcp(3)
            .await
            .expect("no delayed Identify response")
            .xid,
        21
    );
    assert_eq!(
        name_of(&peer.identify(3, Some("press-7")).await.unwrap()).as_deref(),
        Some("press-7")
    );

    // Get answers from the identity without asking the model.
    let get = dcp::Pdu {
        frame_id: dcp::frame_id::GET_SET,
        service_id: dcp::service::GET,
        service_type: 0,
        xid: 4,
        response_delay: 0,
        blocks: vec![
            dcp::Block::new(dcp::opt::DEVICE, dcp::sub::DEVICE_NAME_OF_STATION, vec![]),
            dcp::Block::new(dcp::opt::DHCP, 61, vec![]),
        ],
    };
    let dev_mac = {
        let f = peer.frames.iter().rev().find(|(sent, _)| !sent).unwrap();
        rt::parse_eth(&f.1).unwrap().src
    };
    // Unicast to another MAC is not for this device.
    peer.send_payload([0x02, 0x77, 0, 0, 0, 9], &get.encode().unwrap())
        .await;
    assert!(
        peer.recv_dcp(1).await.is_none(),
        "a Get to another MAC was answered"
    );
    peer.send_payload(dev_mac, &get.encode().unwrap()).await;
    let g = peer.recv_dcp(3).await.expect("no Get response");
    assert_eq!(name_of(&g).as_deref(), Some("press-7"));
    let unsupported = g
        .block(dcp::opt::CONTROL, dcp::sub::CONTROL_RESPONSE)
        .unwrap();
    assert_eq!(
        unsupported.value[..3],
        [
            dcp::opt::DHCP,
            61,
            dcp::block_error::SUBOPTION_NOT_SUPPORTED
        ]
    );

    // Set: the model takes line-* and refuses anything else.
    peer.send_payload(dev_mac, &set_name(5, "line-3")).await;
    let ok = peer.recv_dcp(10).await.expect("no Set response");
    assert_eq!(
        dcp::parse_set_response(&ok).unwrap(),
        vec![((dcp::opt::DEVICE, dcp::sub::DEVICE_NAME_OF_STATION), 0)]
    );
    assert_eq!(
        name_of(&peer.identify(6, None).await.unwrap()).as_deref(),
        Some("line-3")
    );
    peer.send_payload(dev_mac, &set_name(7, "rogue")).await;
    let no = peer.recv_dcp(10).await.expect("no Set response");
    assert_eq!(
        dcp::parse_set_response(&no).unwrap(),
        vec![(
            (dcp::opt::DEVICE, dcp::sub::DEVICE_NAME_OF_STATION),
            dcp::block_error::SET_NOT_POSSIBLE
        )]
    );
    assert_eq!(
        name_of(&peer.identify(8, None).await.unwrap()).as_deref(),
        Some("line-3")
    );
    // An invalid name never reaches the model.
    peer.send_payload(dev_mac, &set_name(9, "Line_3")).await;
    let bad = peer.recv_dcp(10).await.unwrap();
    assert_eq!(
        dcp::parse_set_response(&bad).unwrap()[0].1,
        dcp::block_error::SET_NOT_POSSIBLE
    );
    let asked = dev.events("profinet_dcp_set_request").await;
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0]["name_of_station"], "line-3");
    assert_eq!(asked[1]["current"]["name_of_station"], "line-3");
    assert!(dev.log_text().contains("decision=model_accept"));
    assert!(dev.log_text().contains("decision=model_reject"));
    assert!(dev.log_text().contains("decision=protocol_reject"));

    oracle_frames(&peer.frames);
}

#[tokio::test]
async fn connect_prm_end_application_ready_and_cyclic_data() {
    let dev = start_device(script(DEVICE_POLICY), json!({"name_of_station": "press-7"})).await;
    let mut l2 = LabPeer::new(dev.lab.unwrap()).await;
    let ident = l2.identify(1, None).await.unwrap();
    assert_eq!(name_of(&ident).as_deref(), Some("press-7"));
    let dev_mac = rt::parse_eth(&l2.frames.last().unwrap().1).unwrap().src;
    let mut rpc_peer = RpcPeer::new(dev.rpc).await;

    // Connect, little-endian NDR as a Siemens controller sends it.
    let ar_uuid = rpc::random_uuid();
    let (blocks_req, input, output) = default_connect(l2.mac, "plc-1", ar_uuid);
    let (_, status, res) = rpc_peer.call(rpc::opnum::CONNECT, &blocks_req, true).await;
    assert!(status.is_ok(), "Connect refused: {}", status.describe());
    let raw = blocks::split_blocks(&res).unwrap();
    let ar_res = blocks::ArBlockRes::parse(raw[0].body).unwrap();
    assert_eq!(
        (ar_res.ar_uuid, ar_res.session_key, ar_res.responder_mac),
        (ar_uuid, 7, dev_mac)
    );
    let iocrs: Vec<blocks::IocrBlockRes> = raw
        .iter()
        .filter(|b| b.block_type == blocks::block_type::IOCR_RES)
        .map(|b| blocks::IocrBlockRes::parse(b.body).unwrap())
        .collect();
    assert_eq!(iocrs[0].frame_id, 0xc010);
    let out_fid = iocrs[1].frame_id;
    assert!(
        rt::RT_CLASS_1_FRAME_IDS.contains(&out_fid) && out_fid != 0xc010,
        "{out_fid:#x}"
    );
    assert!(raw
        .iter()
        .any(|b| b.block_type == blocks::block_type::ALARM_CR_RES));
    assert!(
        !raw.iter()
            .any(|b| b.block_type == blocks::block_type::MODULE_DIFF),
        "a matching layout has no diff"
    );
    let asked = dev.wait_for_events("profinet_connect_request", 1).await;
    assert_eq!(asked[0]["controller"]["station_name"], "plc-1");
    assert_eq!(asked[0]["submodules"][3]["inputs"][0]["name"], "inputs");

    // The provider runs before PrmEnd: data status STOP, the model's input already set.
    let first = l2
        .recv_rt(0xc010, input.data_length, 5)
        .await
        .expect("no input frame");
    assert_eq!(first.data_status & rt::data_status::PROVIDER_RUN, 0);

    // PrmEnd → Done, then the device's own ApplicationReady to us, which we confirm.
    let prm_end = blocks::ControlBlock {
        block_type: blocks::block_type::PRM_END_REQ,
        ar_uuid,
        session_key: 7,
        control_command: blocks::control_command::PRM_END,
        properties: 0,
    };
    let (_, st, done) = rpc_peer
        .call(rpc::opnum::CONTROL, &prm_end.encode(), false)
        .await;
    assert!(st.is_ok());
    let done = blocks::ControlBlock::parse(&blocks::split_blocks(&done).unwrap()[0]).unwrap();
    assert_eq!(
        (done.block_type, done.control_command),
        (
            blocks::block_type::PRM_END_RES,
            blocks::control_command::DONE
        )
    );
    let app_ready = rpc_peer.recv_raw(10).await.expect("no ApplicationReady");
    let (h, body) = rpc::parse(&app_ready).unwrap();
    assert_eq!(
        (h.ptype, h.interface, h.opnum),
        (rpc::ptype::REQUEST, rpc::IF_CONTROLLER, rpc::opnum::CONTROL)
    );
    let (_, b) = rpc::parse_ndr_request(body, h.little_endian).unwrap();
    let c = blocks::ControlBlock::parse(&blocks::split_blocks(b).unwrap()[0]).unwrap();
    assert_eq!(
        (c.block_type, c.ar_uuid, c.control_command),
        (
            blocks::block_type::APP_READY_REQ,
            ar_uuid,
            blocks::control_command::APPLICATION_READY
        )
    );
    let reply = rpc::encode(
        &h.response_to(rpc::ptype::RESPONSE, 0),
        &rpc::ndr_response(rpc::PnioStatus::OK, 64, &c.done().encode()),
    )
    .unwrap();
    rpc_peer.datagrams.push((true, reply.clone()));
    rpc_peer.sock.send_to(&reply, dev.rpc).await.unwrap();
    assert!(!dev
        .wait_for_events("profinet_ar_established", 1)
        .await
        .is_empty());

    // Our outputs: slot 1 = 9 with IOPS good, at the device's assigned FrameID.
    let obj = *output.object(1, 1).unwrap();
    let mut counter = 0u16;
    let send_outputs = |l2: &mut LabPeer, counter: u16| {
        let mut c_sdu = vec![0u8; output.data_length];
        c_sdu[obj.offset] = 9;
        c_sdu[obj.iops_offset()] = rt::IOXS_GOOD;
        for i in &output.iocs {
            c_sdu[i.offset] = rt::IOXS_GOOD;
        }
        let f = rt::build_eth(
            dev_mac,
            l2.mac,
            Some(0xc000),
            &rt::build_rt(out_fid, &c_sdu, counter, rt::data_status::GOOD),
        );
        f
    };
    // Keep feeding the consumer while waiting so the watchdog stays quiet.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut seen = None;
    while tokio::time::Instant::now() < deadline {
        counter = counter.wrapping_add(128);
        let f = send_outputs(&mut l2, counter);
        l2.send_frame(f).await;
        if let Some(fr) = l2.recv_rt(0xc010, input.data_length, 1).await {
            let o = input.object(1, 1).unwrap();
            if fr.c_sdu[o.offset] == 10 && fr.c_sdu[o.iops_offset()] == rt::IOXS_GOOD {
                seen = Some(fr);
                break;
            }
        }
    }
    let fr = seen.unwrap_or_else(|| {
        panic!(
            "the model's answer to output 9 (input 10) never appeared\n{}",
            dev.log_text()
        )
    });
    assert_eq!(fr.data_status, rt::data_status::GOOD);
    // The DAP's no-IO submodules are good; our output submodule's IOCS is good.
    for o in &input.objects {
        assert_eq!(
            fr.c_sdu[o.iops_offset()],
            rt::IOXS_GOOD,
            "slot {}/{:#x}",
            o.slot,
            o.subslot
        );
    }
    for i in &input.iocs {
        assert_eq!(fr.c_sdu[i.offset], rt::IOXS_GOOD);
    }
    let outs = dev.wait_for_events("profinet_outputs_changed", 1).await;
    assert_eq!(outs[0]["outputs"][0]["values"]["outputs"], 9, "{outs:?}");
    assert_eq!(dev.connections().await.len(), 1);

    // I&M0 through the AR, and a user record write.
    let read = blocks::RecordRequest {
        write: false,
        seq: 1,
        ar_uuid,
        api: 0,
        slot: 0,
        subslot: 1,
        index: 0xaff0,
        record_data_length: 4096,
        target_ar_uuid: [0; 16],
    };
    let (_, st, res) = rpc_peer.call(rpc::opnum::READ, &read.encode(), false).await;
    assert!(st.is_ok(), "{}", st.describe());
    let (_, record) = blocks::parse_read_response(&res).unwrap();
    let im0 = blocks::Im0::parse(&record).unwrap();
    assert_eq!(
        (
            im0.order_id.as_str(),
            im0.serial_number.as_str(),
            im0.hardware_revision
        ),
        ("NG-PN-1", "SN-0042", 3)
    );
    assert_eq!(im0.software_revision_text(), "V2.1.0");
    let write = blocks::RecordRequest {
        write: true,
        seq: 2,
        ar_uuid,
        api: 0,
        slot: 1,
        subslot: 1,
        index: 123,
        record_data_length: 4,
        target_ar_uuid: [0; 16],
    };
    let mut w = write.encode();
    w.extend_from_slice(&7u32.to_be_bytes());
    let (_, st, _) = rpc_peer.call(rpc::opnum::WRITE, &w, false).await;
    assert!(st.is_ok());
    let written = dev.wait_for_events("profinet_write_record", 1).await;
    assert_eq!(written[0]["decoded"]["u32"], 7);

    // Release: Done, the AR and its connection go.
    let release = blocks::ControlBlock {
        block_type: blocks::block_type::RELEASE_REQ,
        ar_uuid,
        session_key: 7,
        control_command: blocks::control_command::RELEASE,
        properties: 0,
    };
    let (_, st, _) = rpc_peer
        .call(rpc::opnum::RELEASE, &release.encode(), false)
        .await;
    assert!(st.is_ok());
    let closed = dev.wait_for_events("profinet_ar_closed", 1).await;
    assert_eq!(closed[0]["reason"], "released by the controller");
    assert!(dev.connections().await.is_empty());

    let rows = oracle_rpc(&rpc_peer.datagrams);
    // tshark read the Connect's blocks and the device's ApplicationReady as such.
    assert_eq!(rows[0][1], "0x0101,0x0102,0x0102,0x0103,0x0104,0x0104");
    assert!(rows.iter().any(|r| r[1] == "0x0112"), "{rows:?}");
    // The cyclic frames are judged against the Connect in the same capture: build one capture
    // with both, so pn_io knows the frame layout.
    oracle_frames(&l2.frames);
}

#[tokio::test]
async fn an_unreachable_model_refuses_everything_and_inputs_stay_bad() {
    // No handler: every question goes to a model at 127.0.0.1:1, which is not there.
    let dev = start_device(None, json!({"name_of_station": "press-7"})).await;
    let mut l2 = LabPeer::new(dev.lab.unwrap()).await;
    l2.identify(1, None).await.expect("Identify needs no model");
    let dev_mac = rt::parse_eth(&l2.frames.last().unwrap().1).unwrap().src;
    l2.send_payload(dev_mac, &set_name(2, "line-1")).await;
    let r = l2.recv_dcp(30).await.expect("no Set response");
    assert_eq!(
        dcp::parse_set_response(&r).unwrap()[0].1,
        dcp::block_error::SET_NOT_POSSIBLE
    );
    assert_eq!(
        name_of(&l2.identify(3, None).await.unwrap()).as_deref(),
        Some("press-7")
    );

    let mut rpc_peer = RpcPeer::new(dev.rpc).await;
    let (blocks_req, _, _) = default_connect(l2.mac, "plc-1", rpc::random_uuid());
    let (_, status, res) = rpc_peer.call(rpc::opnum::CONNECT, &blocks_req, false).await;
    assert_eq!(
        (status.code, status.decode, status.code1),
        (
            rpc::error_code::CONNECT,
            rpc::error_decode::PNIO,
            rpc::connect_error::RMPM
        ),
        "{}",
        status.describe()
    );
    assert!(res.is_empty());
    let read = blocks::RecordRequest {
        write: false,
        seq: 1,
        ar_uuid: [0; 16],
        api: 0,
        slot: 0,
        subslot: 1,
        index: 0xaff0,
        record_data_length: 4096,
        target_ar_uuid: [0; 16],
    };
    let (_, st, _) = rpc_peer
        .call(rpc::opnum::READ_IMPLICIT, &read.encode(), false)
        .await;
    assert_eq!(
        (st.code, st.decode, st.code1),
        (
            rpc::error_code::READ,
            rpc::error_decode::PNIORW,
            rpc::rw_error::RESOURCE_UNAVAILABLE
        )
    );
    assert!(dev.connections().await.is_empty());
    assert!(
        dev.log_text().contains("decision=fail_closed_llm_error"),
        "{}",
        dev.log_text()
    );
}

#[tokio::test]
async fn an_accepted_ar_whose_inputs_nobody_set_reports_iops_bad() {
    // Accept, and nothing else: the data submodule must never claim good data.
    let dev = start_device(
        static_rule(json!([{"type": "profinet_accept_connect"}])),
        json!({}),
    )
    .await;
    let mut l2 = LabPeer::new(dev.lab.unwrap()).await;
    l2.identify(1, None).await.unwrap();
    let mut rpc_peer = RpcPeer::new(dev.rpc).await;
    let (blocks_req, input, _) = default_connect(l2.mac, "plc-1", rpc::random_uuid());
    let (_, status, _) = rpc_peer.call(rpc::opnum::CONNECT, &blocks_req, false).await;
    assert!(status.is_ok());
    let f = l2
        .recv_rt(0xc010, input.data_length, 5)
        .await
        .expect("no input frame");
    let data = input.object(1, 1).unwrap();
    assert_eq!(
        f.c_sdu[data.iops_offset()],
        rt::IOXS_BAD,
        "IOPS good with no value from the model"
    );
    assert_eq!(f.c_sdu[data.offset], 0);
    let dap = input.object(0, 1).unwrap();
    assert_eq!(
        f.c_sdu[dap.iops_offset()],
        rt::IOXS_GOOD,
        "a no-IO submodule has nothing to fabricate"
    );
}
