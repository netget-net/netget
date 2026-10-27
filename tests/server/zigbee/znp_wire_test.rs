//! The Z-Stack (ZNP) co-processor over raw TCP: MT framing — the FCS, the length bound, the
//! bootloader-skip bytes —, every SREQ answered by its own SRSP in order, the RPC error for a
//! command or subsystem the firmware does not have, NV memory as Z-Stack keeps it, BDB
//! startup, and the network behind it: a join the model decides, an interview answered from
//! the description at no model cost, a cluster command the model answers, and the
//! fail-closed reply when it does not.
use super::support::*;
use netget::server::zigbee::mt::{self, kind, subsystem, Frame};
use netget::server::zigbee::znp::{self, cmd, nv};
use serde_json::json;
use std::time::Duration;

fn znp_formed() -> serde_json::Value {
    json!({"dialect": "znp", "network": formed(15), "network_key": NETWORK_KEY, "devices": devices()})
}

/// Connect, ping, register endpoint 1 and start the network the co-processor holds.
async fn up(params: serde_json::Value) -> (Started, MtHost) {
    let s = start(POLICY, params).await;
    let mut h = MtHost::connect(s.addr).await;
    let ping = h.sreq(subsystem::SYS, cmd::sys::PING, &[]).await;
    assert_eq!(ping, znp::CAPABILITIES.to_le_bytes());
    register_endpoint(&mut h).await;
    let rsp = h
        .sreq(
            subsystem::APP_CNF,
            cmd::app_cnf::BDB_START_COMMISSIONING,
            &[0x04],
        )
        .await;
    assert_eq!(rsp, vec![0]);
    let st = h
        .areq(subsystem::ZDO, cmd::zdo::STATE_CHANGE_IND, 5.0)
        .await
        .expect("state change");
    assert_eq!(st, vec![znp::state::STARTING_COORDINATOR]);
    let st = h
        .areq(subsystem::ZDO, cmd::zdo::STATE_CHANGE_IND, 5.0)
        .await
        .expect("state change");
    assert_eq!(st, vec![znp::state::COORDINATOR]);
    let note = h
        .areq(
            subsystem::APP_CNF,
            cmd::app_cnf::BDB_COMMISSIONING_NOTIFICATION,
            5.0,
        )
        .await
        .expect("commissioning notification");
    assert_eq!(
        note,
        vec![znp::bdb::FORMATION_FAILURE, znp::bdb::MODE_FORMATION, 0],
        "an already-formed network: formation 'fails', the node comes up on it"
    );
    (s, h)
}

async fn register_endpoint(h: &mut MtHost) {
    let mut p = vec![1];
    p.extend_from_slice(&0x0104u16.to_le_bytes());
    p.extend_from_slice(&0x0005u16.to_le_bytes());
    p.extend_from_slice(&[0, 0, 1]);
    p.extend_from_slice(&0x0006u16.to_le_bytes());
    p.push(0);
    assert_eq!(h.sreq(subsystem::AF, cmd::af::REGISTER, &p).await, vec![0]);
}

/// `ZDO_MGMT_PERMIT_JOIN_REQ` broadcast, and the trust-center joins the policy produces.
async fn permit_and_join(h: &mut MtHost, expect: usize) -> Vec<(u16, u64)> {
    let mut p = vec![0x0F];
    p.extend_from_slice(&0xFFFCu16.to_le_bytes());
    p.extend_from_slice(&[30, 1]);
    assert_eq!(
        h.sreq(subsystem::ZDO, cmd::zdo::MGMT_PERMIT_JOIN_REQ, &p)
            .await,
        vec![0]
    );
    let rsp = h
        .areq(subsystem::ZDO, cmd::zdo::MGMT_PERMIT_JOIN_RSP, 5.0)
        .await
        .expect("the coordinator's Mgmt_Permit_Joining_rsp");
    assert_eq!(rsp, vec![0, 0, 0], "from 0x0000, SUCCESS");
    let mut joined = Vec::new();
    for _ in 0..expect {
        let tc = h
            .areq(subsystem::ZDO, cmd::zdo::TC_DEV_IND, 15.0)
            .await
            .expect("ZDO_TC_DEV_IND");
        let nwk = u16::from_le_bytes([tc[0], tc[1]]);
        let ieee = u64::from_le_bytes(tc[2..10].try_into().unwrap());
        assert_eq!(&tc[10..], &[0, 0], "parent: the coordinator");
        let annce = h
            .areq(subsystem::ZDO, cmd::zdo::END_DEVICE_ANNCE_IND, 5.0)
            .await
            .expect("ZDO_END_DEVICE_ANNCE_IND");
        assert_eq!(u16::from_le_bytes([annce[0], annce[1]]), nwk, "source");
        assert_eq!(u16::from_le_bytes([annce[2], annce[3]]), nwk, "announced");
        assert_eq!(u64::from_le_bytes(annce[4..12].try_into().unwrap()), ieee);
        joined.push((nwk, ieee));
    }
    joined
}

/// `AF_DATA_REQUEST` from endpoint 1; returns the SRSP status.
async fn af(h: &mut MtHost, nwk: u16, cluster: u16, tsn: u8, data: &[u8]) -> u8 {
    let mut p = nwk.to_le_bytes().to_vec();
    p.extend_from_slice(&[1, 1]);
    p.extend_from_slice(&cluster.to_le_bytes());
    p.extend_from_slice(&[tsn, 0, 30, data.len() as u8]);
    p.extend_from_slice(data);
    h.sreq(subsystem::AF, cmd::af::DATA_REQUEST, &p).await[0]
}

/// The next `AF_INCOMING_MSG`: (cluster, source address, source endpoint, ZCL frame).
async fn incoming(h: &mut MtHost, secs: f64) -> Option<(u16, u16, u8, Vec<u8>)> {
    let d = h.areq(subsystem::AF, cmd::af::INCOMING_MSG, secs).await?;
    let cluster = u16::from_le_bytes([d[2], d[3]]);
    let src = u16::from_le_bytes([d[4], d[5]]);
    let len = d[16] as usize;
    Some((cluster, src, d[6], d[17..17 + len].to_vec()))
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_and_the_answers_to_commands_the_firmware_does_not_have() {
    let s = start(POLICY, json!({"dialect": "znp"})).await;
    let mut h = MtHost::connect(s.addr).await;
    // herdsman's and zigpy-znp's bootloader-skip bytes come before the first frame; they are
    // not a frame and get no answer.
    h.write(&[0xEF; 16]).await;
    let v = h.sreq(subsystem::SYS, cmd::sys::VERSION, &[]).await;
    assert_eq!(
        &v[..5],
        &[2, 1, 2, 7, 1],
        "transport 2, product 1 (Z-Stack 3.x.0), 2.7.1"
    );
    assert_eq!(u32::from_le_bytes(v[5..9].try_into().unwrap()), 20240710);
    let ext = h.sreq(subsystem::SYS, cmd::sys::GET_EXT_ADDR, &[]).await;
    assert_eq!(
        u64::from_le_bytes(ext[..].try_into().unwrap()),
        znp::DEFAULT_EUI64
    );
    let info = h
        .sreq(subsystem::UTIL, cmd::util::GET_DEVICE_INFO, &[])
        .await;
    assert_eq!(info[0], 0);
    assert_eq!(info[12], znp::state::HOLD, "not started yet");

    // A command the firmware's SYS subsystem does not have, and a subsystem it does not have:
    // the RPC error SRSP, naming the request.
    let unknown = Frame::new(kind::SREQ, subsystem::SYS, 0x7E, vec![1, 2]);
    h.write(&unknown.encode()).await;
    let r = h.srsp(5.0).await.expect("RPC error");
    assert_eq!((r.subsystem, r.id), (subsystem::RPC_ERROR, 0));
    assert_eq!(r.data, vec![mt::rpc_error::INVALID_COMMAND_ID, 0x21, 0x7E]);
    let mac = Frame::new(kind::SREQ, subsystem::MAC, 0x01, vec![]);
    h.write(&mac.encode()).await;
    let r = h.srsp(5.0).await.expect("RPC error");
    assert_eq!(r.data, vec![mt::rpc_error::INVALID_SUBSYSTEM, 0x22, 0x01]);
    // A known command with its data cut short.
    let short = Frame::new(
        kind::SREQ,
        subsystem::SYS,
        cmd::sys::OSAL_NV_LENGTH,
        vec![1],
    );
    h.write(&short.encode()).await;
    let r = h.srsp(5.0).await.expect("RPC error");
    assert_eq!(r.data, vec![mt::rpc_error::INVALID_LENGTH, 0x21, 0x13]);
    // An AREQ the firmware does not handle has no answer at all.
    h.write(&Frame::new(kind::AREQ, subsystem::ZDO, 0x77, vec![]).encode())
        .await;
    assert!(h.silent_for(0.5).await, "an unknown AREQ is not answered");
    // The link still works.
    assert_eq!(h.sreq(subsystem::SYS, cmd::sys::PING, &[]).await.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_fcs_and_an_impossible_length_are_dropped_and_not_executed() {
    let mut s = start(POLICY, json!({"dialect": "znp"})).await;
    let mut h = MtHost::connect(s.addr).await;
    // An NV write with its FCS off by one: dropped, so the item it would create never exists.
    let mut init = nv::HAS_CONFIGURED_ZSTACK3.to_le_bytes().to_vec();
    init.extend_from_slice(&1u16.to_le_bytes());
    init.extend_from_slice(&[1, 0x55]);
    let mut bad = Frame::new(
        kind::SREQ,
        subsystem::SYS,
        cmd::sys::OSAL_NV_ITEM_INIT,
        init.clone(),
    )
    .encode();
    *bad.last_mut().unwrap() ^= 0x01;
    h.write(&bad).await;
    assert!(
        h.silent_for(0.5).await,
        "no answer to a frame with a bad FCS"
    );
    let len = h
        .sreq(
            subsystem::SYS,
            cmd::sys::OSAL_NV_LENGTH,
            &nv::HAS_CONFIGURED_ZSTACK3.to_le_bytes(),
        )
        .await;
    assert_eq!(len, vec![0, 0], "the bad frame was not executed");

    // A length above 250 is not a frame: that SOF is skipped and the bytes after it are
    // read as what they are. Here a whole PING follows the impossible length.
    let mut bomb = vec![mt::SOF, 0xFF];
    bomb.extend(Frame::new(kind::SREQ, subsystem::SYS, cmd::sys::PING, vec![]).encode());
    h.write(&bomb).await;
    let r = h.srsp(5.0).await.expect("the PING after the bomb");
    assert_eq!((r.subsystem, r.id), (subsystem::SYS, cmd::sys::PING));
    // 251 exactly, the first length that is not a frame.
    let mut over = vec![mt::SOF, (mt::MAX_DATA + 1) as u8];
    over.extend(vec![0x21; mt::MAX_DATA + 4]);
    h.write(&over).await;
    assert!(
        h.silent_for(0.5).await,
        "nothing executes from an oversized frame"
    );
    assert_eq!(h.sreq(subsystem::SYS, cmd::sys::PING, &[]).await.len(), 2);
    drop(h);
    let line = wait_for_log(&mut s.logs, "closed; MT commands", 10).await;
    assert!(line.contains("bad_fcs=1"), "{line}");
    assert!(line.contains("too_long=2"), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_sreq_gets_its_own_srsp_in_order() {
    let s = start(POLICY, json!({"dialect": "znp"})).await;
    let mut h = MtHost::connect(s.addr).await;
    // Five SREQs in one write: five SRSPs, in order, each naming its command.
    let reqs: Vec<(u8, u8, Vec<u8>)> = vec![
        (subsystem::SYS, cmd::sys::PING, vec![]),
        (subsystem::SYS, cmd::sys::VERSION, vec![]),
        (
            subsystem::SYS,
            cmd::sys::OSAL_NV_LENGTH,
            nv::NIB.to_le_bytes().to_vec(),
        ),
        (subsystem::UTIL, cmd::util::GET_DEVICE_INFO, vec![]),
        (subsystem::SYS, cmd::sys::GET_EXT_ADDR, vec![]),
    ];
    let mut bytes = Vec::new();
    for (sub, id, data) in &reqs {
        bytes.extend(Frame::new(kind::SREQ, *sub, *id, data.clone()).encode());
    }
    h.write(&bytes).await;
    for (sub, id, _) in &reqs {
        let r = h.srsp(5.0).await.expect("an SRSP");
        assert_eq!(
            (r.subsystem, r.id),
            (*sub, *id),
            "answered in the order asked"
        );
    }
    assert!(h.silent_for(0.3).await, "one SRSP per SREQ, no more");
    let _ = s;
}

#[tokio::test(flavor = "multi_thread")]
async fn nv_memory_is_kept_as_z_stack_keeps_it() {
    let s = start(POLICY, znp_formed()).await;
    let mut h = MtHost::connect(s.addr).await;
    let osal = |id: u16| id.to_le_bytes().to_vec();
    // The formed network's NIB: 116 aligned bytes; its channel, PAN and extended PAN.
    let len = h
        .sreq(subsystem::SYS, cmd::sys::OSAL_NV_LENGTH, &osal(nv::NIB))
        .await;
    assert_eq!(u16::from_le_bytes([len[0], len[1]]), 116);
    let mut req = osal(nv::NIB);
    req.extend_from_slice(&0u16.to_le_bytes());
    let r = h
        .sreq(subsystem::SYS, cmd::sys::OSAL_NV_READ_EXT, &req)
        .await;
    assert_eq!((r[0], r[1]), (0, 116));
    let nib = znp::read_nib(&r[2..]).expect("a NIB");
    assert_eq!((nib.channel, nib.pan_id), (15, 0x1a62));
    assert_eq!(nib.epid_wire, [0xdd; 8]);
    // herdsman's alignment probe: NWKKEY is 24 bytes on an aligned (CC26xx) chip.
    let len = h
        .sreq(subsystem::SYS, cmd::sys::OSAL_NV_LENGTH, &osal(nv::NWKKEY))
        .await;
    assert_eq!(len, vec![24, 0]);
    // zigpy-znp's: an associated device is 36 bytes.
    let a = h
        .sreq(subsystem::UTIL, cmd::util::ASSOC_FIND_DEVICE, &[0])
        .await;
    assert_eq!(a.len(), 36);
    // Init a missing item: NV_ITEM_UNINIT; again: SUCCESS; write past its end: refused.
    let mut init = osal(0x0201);
    init.extend_from_slice(&4u16.to_le_bytes());
    init.extend_from_slice(&[2, 0xAA, 0xBB]);
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_ITEM_INIT, &init)
            .await,
        vec![znp::status::NV_ITEM_UNINIT]
    );
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_ITEM_INIT, &init)
            .await,
        vec![znp::status::SUCCESS]
    );
    let mut write = osal(0x0201);
    write.extend_from_slice(&2u16.to_le_bytes());
    write.extend_from_slice(&3u16.to_le_bytes());
    write.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_WRITE_EXT, &write)
            .await,
        vec![znp::status::NV_OPER_FAILED],
        "offset 2 + 3 bytes is past a 4-byte item"
    );
    let mut write = osal(0x0201);
    write.extend_from_slice(&2u16.to_le_bytes());
    write.extend_from_slice(&2u16.to_le_bytes());
    write.extend_from_slice(&[1, 2]);
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_WRITE_EXT, &write)
            .await,
        vec![0]
    );
    let mut read = osal(0x0201);
    read.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_READ_EXT, &read)
            .await,
        vec![0, 4, 0xAA, 0xBB, 1, 2]
    );
    // Deleting needs the right length.
    let mut del = osal(0x0201);
    del.extend_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_DELETE, &del).await,
        vec![znp::status::NV_BAD_ITEM_LEN]
    );
    let mut del = osal(0x0201);
    del.extend_from_slice(&4u16.to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_DELETE, &del).await,
        vec![0]
    );
    // An OSAL id above 0x03FF cannot be created over MT on Z-Stack 3.
    let mut high = osal(0x0F00);
    high.extend_from_slice(&1u16.to_le_bytes());
    high.extend_from_slice(&[1, 0x55]);
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_ITEM_INIT, &high)
            .await,
        vec![znp::status::NV_OPER_FAILED]
    );
    // The extended NV: the security material entry for the formed network.
    let key = [1u8, 7, 0, 0, 0];
    let len = h.sreq(subsystem::SYS, cmd::sys::NV_LENGTH, &key).await;
    assert_eq!(len, vec![12, 0, 0, 0]);
    let mut read = key.to_vec();
    read.extend_from_slice(&0u16.to_le_bytes());
    read.push(12);
    let r = h.sreq(subsystem::SYS, cmd::sys::NV_READ, &read).await;
    assert_eq!((r[0], r[1]), (0, 12));
    assert_eq!(
        &r[6..14],
        &[0xdd; 8],
        "the entry names the network's extended PAN"
    );
    // A reset with STARTUP_OPTION "clear state": the network is gone from NV.
    let mut opt = osal(nv::STARTUP_OPTION);
    opt.extend_from_slice(&0u16.to_le_bytes());
    opt.extend_from_slice(&1u16.to_le_bytes());
    opt.push(0x02);
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_WRITE_EXT, &opt)
            .await,
        vec![0]
    );
    h.write(&Frame::new(kind::AREQ, subsystem::SYS, cmd::sys::RESET_REQ, vec![1]).encode())
        .await;
    let ind = h
        .areq(subsystem::SYS, cmd::sys::RESET_IND, 5.0)
        .await
        .expect("SYS_RESET_IND");
    assert_eq!(&ind[1..], &[2, 1, 2, 7, 1]);
    let len = h
        .sreq(subsystem::SYS, cmd::sys::OSAL_NV_LENGTH, &osal(nv::NIB))
        .await;
    assert_eq!(len, vec![0, 0], "the NIB was cleared");
    let mut read = osal(nv::STARTUP_OPTION);
    read.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_READ_EXT, &read)
            .await,
        vec![0, 1, 0],
        "and the startup option reset"
    );
    assert!(
        s.state.get_server(s.id).await.is_some(),
        "the server is still running"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_joins_is_interviewed_for_free_and_its_cluster_command_is_the_models() {
    let (s, mut h) = up(znp_formed()).await;
    // The host asks for every ZDO message, as zigpy-znp does.
    assert_eq!(
        h.sreq(subsystem::ZDO, cmd::zdo::MSG_CB_REGISTER, &[0xFF, 0xFF])
            .await,
        vec![0]
    );
    let joined = permit_and_join(&mut h, 3).await;
    assert!(
        joined.contains(&(LAMP_NWK, 0x0012_4b00_1ca1_b201)),
        "{joined:?}"
    );
    assert_eq!(
        model_calls(&s.state, s.id, "zigbee_permit_joining")
            .await
            .len(),
        1,
        "one model call for the one permit"
    );

    // The interview, as herdsman does it: ZDO SREQs, answered by the ZDO_*_RSP indication
    // (and ZDO_MSG_CB_INCOMING, which the host registered for), from the description.
    let mut p = LAMP_NWK.to_le_bytes().to_vec();
    p.extend_from_slice(&LAMP_NWK.to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::ZDO, cmd::zdo::NODE_DESC_REQ, &p).await,
        vec![0]
    );
    let rsp = h
        .areq(subsystem::ZDO, 0x82, 5.0)
        .await
        .expect("ZDO_NODE_DESC_RSP");
    assert_eq!(u16::from_le_bytes([rsp[0], rsp[1]]), LAMP_NWK, "source");
    assert_eq!(rsp[2], 0, "SUCCESS");
    assert_eq!(rsp[5] & 0x07, 1, "a router");
    // Earlier ones (the permit response, the announcement) came the same way; the host
    // registered for every cluster.
    let mut seen = Vec::new();
    let cb = loop {
        let cb = h
            .areq(subsystem::ZDO, cmd::zdo::MSG_CB_INCOMING, 5.0)
            .await
            .unwrap_or_else(|| panic!("no ZDO_MSG_CB_INCOMING for 0x8002 after {seen:x?}"));
        let cluster = u16::from_le_bytes([cb[3], cb[4]]);
        if cluster == 0x8002 {
            break cb;
        }
        seen.push(cluster);
    };
    assert!(
        seen.contains(&0x8036) && seen.contains(&0x0013),
        "{seen:x?}"
    );
    assert_eq!(&cb[9..], &rsp[2..], "the same ZDO payload, without the TSN");
    let mut p = LAMP_NWK.to_le_bytes().to_vec();
    p.extend_from_slice(&LAMP_NWK.to_le_bytes());
    p.push(1);
    assert_eq!(
        h.sreq(subsystem::ZDO, cmd::zdo::SIMPLE_DESC_REQ, &p).await,
        vec![0]
    );
    let rsp = h
        .areq(subsystem::ZDO, 0x84, 5.0)
        .await
        .expect("ZDO_SIMPLE_DESC_RSP");
    // src, status, nwk, length, endpoint 1, profile 0x0104, device 0x0100.
    assert_eq!(&rsp[6..11], &[1, 0x04, 0x01, 0x00, 0x01]);
    // A Basic read over AF: confirmed, answered from the description.
    assert_eq!(
        af(&mut h, LAMP_NWK, 0x0000, 7, &zcl_read(7, &[0x0005])).await,
        0
    );
    let conf = h
        .areq(subsystem::AF, cmd::af::DATA_CONFIRM, 5.0)
        .await
        .expect("AF_DATA_CONFIRM");
    assert_eq!(conf, vec![0, 1, 7], "SUCCESS, endpoint 1, transaction 7");
    let (c, src, ep, zcl) = incoming(&mut h, 5.0).await.expect("the read's answer");
    assert_eq!((c, src, ep), (0x0000, LAMP_NWK, 1));
    assert_eq!(
        &zcl[3..],
        &[0x05, 0x00, 0x00, 0x42, 6, b'L', b'a', b'm', b'p', b'-', b'1']
    );
    assert!(
        model_calls(&s.state, s.id, "zigbee_zcl_request")
            .await
            .is_empty(),
        "the interview and the read cost no model call"
    );
    assert!(
        log_entries(&s.state, s.id, "zigbee_zdo_from_description")
            .await
            .len()
            >= 2
    );

    // On: the model sets on_off and reports it; the Default Response says SUCCESS.
    assert_eq!(af(&mut h, LAMP_NWK, 0x0006, 8, &zcl_on(42)).await, 0);
    assert_eq!(
        h.areq(subsystem::AF, cmd::af::DATA_CONFIRM, 5.0).await,
        Some(vec![0, 1, 8])
    );
    let mut default = None;
    let mut report = None;
    for _ in 0..2 {
        let (c, src, _, p) = incoming(&mut h, 10.0).await.expect("the device's answer");
        assert_eq!((c, src), (6, LAMP_NWK));
        match p[2] {
            0x0B => default = Some(p),
            0x0A => report = Some(p),
            other => panic!("unexpected ZCL command 0x{other:02x}"),
        }
    }
    assert_eq!(
        &default.expect("Default Response")[1..],
        &[42, 0x0B, 0x01, 0x00]
    );
    assert_eq!(&report.expect("Report")[3..], &[0x00, 0x00, 0x10, 0x01]);
    let calls = model_calls(&s.state, s.id, "zigbee_zcl_request").await;
    assert_eq!(calls.len(), 1, "one model call for the On command");
    assert_eq!(
        (calls[0]["cluster"].as_str(), calls[0]["command"].as_str()),
        (Some("on_off"), Some("on"))
    );

    // A frame to an address nobody has: confirmed as no route.
    assert_eq!(af(&mut h, 0x7777, 0x0006, 9, &zcl_on(43)).await, 0);
    assert_eq!(
        h.areq(subsystem::AF, cmd::af::DATA_CONFIRM, 5.0).await,
        Some(vec![znp::status::NWK_NO_ROUTE, 1, 9])
    );

    // A report injected through send_to_peer reaches the host as AF_INCOMING_MSG.
    let conn = s
        .state
        .get_server(s.id)
        .await
        .unwrap()
        .connections
        .keys()
        .next()
        .copied()
        .expect("the host's connection");
    let outcome = s
        .state
        .send_to_peer(
            s.id,
            conn.as_u32(),
            json!({"type": "zigbee_report_attributes", "device": "kitchen-lamp", "endpoint": 1,
                   "attributes": [{"cluster": "level_control", "attribute": 0, "value": 77}]}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(format!("{outcome:?}").contains("Executed"), "{outcome:?}");
    let (c, _, _, p) = incoming(&mut h, 5.0).await.expect("injected report");
    assert_eq!((c, p[2]), (0x0008, 0x0A));
    assert_eq!(&p[3..], &[0x00, 0x00, 0x20, 77]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_zcl_request_fails_closed() {
    let (mut s, mut h) = up(znp_formed()).await;
    permit_and_join(&mut h, 3).await;
    for (nwk, tsn, decision) in [
        (SILENT_NWK, 50u8, "decision=model_silent"),
        (INVALID_NWK, 51, "decision=fail_closed_invalid_reply"),
    ] {
        assert_eq!(af(&mut h, nwk, 0x0006, tsn, &zcl_on(tsn)).await, 0);
        assert_eq!(
            h.areq(subsystem::AF, cmd::af::DATA_CONFIRM, 5.0).await,
            Some(vec![0, 1, tsn]),
            "delivered: the APS acknowledgement came back"
        );
        let (c, src, _, p) = incoming(&mut h, 10.0).await.expect("the device's failure");
        assert_eq!((c, src), (6, nwk));
        assert_eq!(
            &p[1..],
            &[tsn, 0x0B, 0x01, 0x01],
            "Default Response FAILURE"
        );
        let line = wait_for_log(&mut s.logs, decision, 10).await;
        assert!(line.contains("cluster=on_off"), "{line}");
    }
    // The invalid answer changed nothing: on_off is still false.
    assert_eq!(
        af(&mut h, INVALID_NWK, 0x0006, 60, &zcl_read(60, &[0])).await,
        0
    );
    let (_, _, _, p) = incoming(&mut h, 5.0).await.expect("read");
    assert_eq!(&p[3..], &[0x00, 0x00, 0x00, 0x10, 0x00]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_forms_a_network_through_bdb_and_the_model_sees_it() {
    let s = start(POLICY, json!({"dialect": "znp", "devices": devices()})).await;
    let mut h = MtHost::connect(s.addr).await;
    let osal = |id: u16, v: &[u8]| {
        let mut p = id.to_le_bytes().to_vec();
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&(v.len() as u16).to_le_bytes());
        p.extend_from_slice(v);
        p
    };
    // No network: the NIB does not exist.
    assert_eq!(
        h.sreq(
            subsystem::SYS,
            cmd::sys::OSAL_NV_LENGTH,
            &nv::NIB.to_le_bytes()
        )
        .await,
        vec![0, 0]
    );
    // herdsman's commissioning items, then BDB formation on channel 20.
    let key = hex::decode(NETWORK_KEY).unwrap();
    for (id, v) in [
        (nv::PANID, 0x1a62u16.to_le_bytes().to_vec()),
        (nv::EXTENDED_PAN_ID, vec![0xdd; 8]),
        (nv::APS_USE_EXT_PANID, vec![0xdd; 8]),
        (nv::PRECFGKEY, key.clone()),
    ] {
        assert_eq!(
            h.sreq(subsystem::SYS, cmd::sys::OSAL_NV_WRITE_EXT, &osal(id, &v))
                .await,
            vec![0]
        );
    }
    let mut chan = vec![1];
    chan.extend_from_slice(&(1u32 << 20).to_le_bytes());
    assert_eq!(
        h.sreq(subsystem::APP_CNF, cmd::app_cnf::BDB_SET_CHANNEL, &chan)
            .await,
        vec![0]
    );
    register_endpoint(&mut h).await;
    assert_eq!(
        h.sreq(
            subsystem::APP_CNF,
            cmd::app_cnf::BDB_START_COMMISSIONING,
            &[0x04]
        )
        .await,
        vec![0]
    );
    let mut notes = Vec::new();
    while let Some(n) = h
        .areq(
            subsystem::APP_CNF,
            cmd::app_cnf::BDB_COMMISSIONING_NOTIFICATION,
            2.0,
        )
        .await
    {
        notes.push(n);
    }
    assert_eq!(
        notes.last(),
        Some(&vec![znp::bdb::SUCCESS, znp::bdb::MODE_FORMATION, 0]),
        "{notes:?}"
    );
    let info = h.sreq(subsystem::ZDO, cmd::zdo::EXT_NWK_INFO, &[]).await;
    assert_eq!(info[2], znp::state::COORDINATOR);
    assert_eq!(u16::from_le_bytes([info[3], info[4]]), 0x1a62);
    assert_eq!(&info[7..15], &[0xdd; 8]);
    assert_eq!(info[23], 20);
    // The network the host formed is the one the model is told about.
    permit_and_join(&mut h, 3).await;
    let permits = model_calls(&s.state, s.id, "zigbee_permit_joining").await;
    assert_eq!(permits.len(), 1);
    assert_eq!(permits[0]["channel"], 20);
    assert_eq!(permits[0]["pan_id"], "0x1a62");
    assert!(
        !permits[0].to_string().contains(NETWORK_KEY),
        "the key never reaches the model"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dialect_is_a_startup_decision() {
    for (params, needle) in [
        (json!({"dialect": "zboss"}), "dialect is ezsp or znp"),
        (
            json!({"dialect": "znp", "ezsp_version": 17}),
            "ezsp_version belongs to the EZSP dialect",
        ),
    ] {
        let state = netget::state::app_state::AppState::new_with_options(
            false,
            "http://127.0.0.1:1".into(),
        );
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let created = netget::cli::management::ServerForm {
            protocol: "zigbee".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            instruction: Some(String::new()),
            startup_params: Some(params.clone()),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let err = match created {
            Err(e) => e.to_string(),
            Ok(id) => {
                let mut status = String::new();
                for _ in 0..200 {
                    if let Some(s) = state.get_server(id).await {
                        if let netget::state::server::ServerStatus::Error(e) = &s.status {
                            status = e.clone();
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                status
            }
        };
        assert!(err.contains(needle), "{params}: {err}");
    }
    // An EZSP host on a Z-Stack co-processor is told why nothing answers.
    let mut s = start(POLICY, json!({"dialect": "znp"})).await;
    let mut h = MtHost::connect(s.addr).await;
    h.write(&[0x1A, 0xC0, 0x38, 0xBC, 0x7E]).await;
    let line = wait_for_log(&mut s.logs, "speaking ASH/EZSP", 10).await;
    assert!(line.contains("dialect znp"), "{line}");
    assert!(h.silent_for(0.3).await);
}
