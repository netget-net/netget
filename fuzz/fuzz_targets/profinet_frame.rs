//! `netget::server::profinet` — every decoder the PROFINET device and controller run on what a
//! peer sends: Ethernet framing with its 802.1Q tags, DCP PDUs and their Set/Identify blocks,
//! the connectionless DCE/RPC header and both NDR headers, the PNIO-CM block list and each
//! block parser (AR, IOCR, AlarmCR, ExpectedSubmodule, ModuleDiff, Control, record headers,
//! I&M0-3), the cyclic RT frame, a frame layout checked against declared lengths, and the
//! typed-value decoder.
//!
//! What round-trips is checked to round-trip: a DCP PDU, an RPC header, an IOCRBlockReq and
//! an I&M0 that decode must encode back to an equal value. Nothing here recurses; the corpus
//! carries the inputs that make the walks long instead — a stack of VLAN tags (`vlan_stack`),
//! a DCP PDU at its 32-block bound (`dcp_many_blocks`), and an ExpectedSubmoduleBlockReq
//! declaring far more submodules than it carries (`expected_count_lie`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::profinet::{blocks, dcp, rpc, rt, values};

fuzz_target!(|data: &[u8]| {
    if let Some(f) = rt::parse_eth(data) {
        let _ = rt::parse_rt(&f.payload, 40);
        let _ = dcp::Pdu::parse(&f.payload);
    }
    if let Ok(pdu) = dcp::Pdu::parse(data) {
        // A PDU whose last odd-length block ends at DCPDataLength 1488 without its pad byte
        // parses, and is one octet too long to encode with the pad: that refusal is correct.
        if let Ok(enc) = pdu.encode() {
            let again = dcp::Pdu::parse(&enc).expect("a re-encoded PDU parses");
            assert_eq!(again, pdu, "encode then parse changed the DCP PDU");
        }
        let _ = dcp::parse_set_request(&pdu.blocks);
        let _ = dcp::parse_set_response(&pdu);
        let _ = dcp::DiscoveredDevice::from_blocks([0; 6], &pdu.blocks);
    }
    if let Ok((h, body)) = rpc::parse(data) {
        let again = rpc::encode(&h, body).expect("a parsed datagram encodes");
        let (h2, b2) = rpc::parse(&again).expect("a re-encoded datagram parses");
        assert_eq!(
            (h2, b2),
            (h.clone(), body),
            "encode then parse changed the RPC datagram"
        );
        if let Ok((_, b)) = rpc::parse_ndr_request(body, h.little_endian) {
            walk(b);
        }
        if let Ok((_, b)) = rpc::parse_ndr_response(body, h.little_endian) {
            walk(b);
            let _ = blocks::parse_read_response(b);
        }
    }
    walk(data);
    let _ = blocks::split_write_request(data);
    let _ = blocks::parse_read_response(data);
    if let Ok(im0) = blocks::Im0::parse(data) {
        if let Ok(enc) = im0.encode() {
            assert_eq!(
                blocks::Im0::parse(&enc).expect("re-encoded I&M0 parses"),
                im0
            );
        }
    }
    let _ = blocks::ImText::parse(data);
    let fields = values::anonymous_fields(data.len().min(64));
    let _ = values::decode(&fields, data);
});

fn walk(data: &[u8]) {
    let Ok(list) = blocks::split_blocks(data) else {
        return;
    };
    for b in &list {
        let _ = blocks::ArBlockReq::parse(b.body);
        let _ = blocks::ArBlockRes::parse(b.body);
        if let Ok(r) = blocks::IocrBlockReq::parse(b.body) {
            let raw = r.encode();
            let again = blocks::split_blocks(&raw).expect("re-encoded IOCR splits");
            assert_eq!(
                blocks::IocrBlockReq::parse(again[0].body).expect("re-encoded IOCR parses"),
                r
            );
            if let Some(api) = r.apis.first() {
                let _ =
                    rt::CrLayout::from_request(r.data_length, &api.io_data, &api.iocs, |_, _| {
                        Some(8)
                    });
            }
        }
        let _ = blocks::IocrBlockRes::parse(b.body);
        let _ = blocks::AlarmCrBlockReq::parse(b.body);
        let _ = blocks::AlarmCrBlockRes::parse(b.body);
        let _ = blocks::parse_expected_submodules(b.body);
        let _ = blocks::parse_module_diff(b.body);
        let _ = blocks::ControlBlock::parse(b);
        let _ = blocks::RecordRequest::parse(b);
    }
}
