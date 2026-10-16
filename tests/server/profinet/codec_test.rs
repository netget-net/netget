//! The PROFINET codec against literal bytes from IEC 61158-6-10's layouts, and every bound a
//! peer's declared length or count could push past.
use netget::server::profinet::{blocks, dcp, rpc, rt, values};
use serde_json::json;

#[test]
fn identify_request_and_response_are_the_literal_layout() {
    let req = dcp::identify_request(0x0102_0304, None, 1)
        .encode()
        .unwrap();
    assert_eq!(
        req,
        [
            0xfe, 0xfe, // FrameID Identify request
            0x05, 0x00, // Identify, Request
            0x01, 0x02, 0x03, 0x04, // Xid
            0x00, 0x01, // ResponseDelayFactor
            0x00, 0x04, // DCPDataLength
            0xff, 0xff, 0x00, 0x00, // AllSelector, length 0
        ]
    );
    let by_name = dcp::identify_request(9, Some("press-7"), 0)
        .encode()
        .unwrap();
    assert_eq!(&by_name[12..], b"\x02\x02\x00\x07press-7\x00");

    let id = dcp::Identity {
        mac: [2, 0, 0, 0, 0, 1],
        name_of_station: "press-7".into(),
        type_of_station: "T".into(),
        vendor_id: 0x002a,
        device_id: 0x0105,
        role: dcp::role::IO_DEVICE,
        ip: dcp::IpParameters {
            ip: "192.168.0.50".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            gateway: "0.0.0.0".parse().unwrap(),
        },
        ip_set: true,
        instance: None,
    };
    // NameOfStation with BlockInfo 0, padded to even length.
    assert_eq!(
        id.block(dcp::opt::DEVICE, dcp::sub::DEVICE_NAME_OF_STATION)
            .unwrap()
            .value,
        b"\x00\x00press-7"
    );
    // IP parameter with BlockInfo "IP set".
    assert_eq!(
        id.block(dcp::opt::IP, dcp::sub::IP_PARAMETER)
            .unwrap()
            .value,
        [0, 1, 192, 168, 0, 50, 255, 255, 255, 0, 0, 0, 0, 0]
    );
    let resp = dcp::Pdu {
        frame_id: dcp::frame_id::IDENTIFY_RESPONSE,
        service_id: dcp::service::IDENTIFY,
        service_type: dcp::service_type::RESPONSE_SUCCESS,
        xid: 5,
        response_delay: 0,
        blocks: id.identify_blocks(),
    }
    .encode()
    .unwrap();
    // The name block sits where the first-but-one block goes, padded.
    let name_at = resp
        .windows(4)
        .position(|w| w == [0x02, 0x02, 0x00, 0x09])
        .expect("NameOfStation block header 02 02 00 09");
    assert_eq!(&resp[name_at + 4..name_at + 14], b"\x00\x00press-7\x00");
    let parsed = dcp::Pdu::parse(&resp).unwrap();
    let d = dcp::DiscoveredDevice::from_blocks(id.mac, &parsed.blocks);
    assert_eq!(d.name_of_station.as_deref(), Some("press-7"));
    assert_eq!(
        (d.vendor_id, d.device_id, d.ip_set),
        (Some(0x2a), Some(0x105), Some(true))
    );
    assert!(id.matches_filter(&dcp::Pdu::parse(&by_name).unwrap().blocks));
    let other = dcp::identify_request(9, Some("press-8"), 0)
        .encode()
        .unwrap();
    assert!(!id.matches_filter(&dcp::Pdu::parse(&other).unwrap().blocks));
}

#[test]
fn get_requests_are_bare_pairs_and_set_requests_carry_qualifiers() {
    let get = dcp::Pdu::parse(&[0xfe, 0xfd, 3, 0, 0, 0, 0, 7, 0, 0, 0, 4, 2, 2, 1, 2]).unwrap();
    assert_eq!(get.blocks.len(), 2);
    assert_eq!((get.blocks[1].option, get.blocks[1].suboption), (1, 2));

    let set = dcp::set_request_block(
        dcp::opt::DEVICE,
        dcp::sub::DEVICE_NAME_OF_STATION,
        true,
        b"line-3",
    );
    assert_eq!(set.value, b"\x00\x01line-3");
    let items = dcp::parse_set_request(&[
        set,
        dcp::set_request_block(dcp::opt::CONTROL, dcp::sub::CONTROL_SIGNAL, false, &[1, 0]),
    ])
    .unwrap();
    assert_eq!(
        items[0],
        dcp::SetItem::NameOfStation {
            name: "line-3".into(),
            permanent: true
        }
    );
    assert_eq!(items[1], dcp::SetItem::Signal);
    // A Set naming an illegal station name, or an IP with a broken mask, is refused whole.
    for bad in [
        dcp::set_request_block(
            dcp::opt::DEVICE,
            dcp::sub::DEVICE_NAME_OF_STATION,
            true,
            b"Line_3",
        ),
        dcp::set_request_block(
            dcp::opt::IP,
            dcp::sub::IP_PARAMETER,
            true,
            &[10, 0, 0, 1, 255, 0, 255, 0, 0, 0, 0, 0],
        ),
    ] {
        assert!(dcp::parse_set_request(&[bad]).is_err());
    }
}

#[test]
fn station_names_follow_the_standard() {
    for ok in ["a", "press-7", "line-1.hall-2", "x1", "port-xyz"] {
        dcp::validate_station_name(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let long = "a".repeat(241);
    let label = "a".repeat(64);
    for bad in [
        "",
        "Press",
        "a_b",
        "-a",
        "a-",
        "a..b",
        "10.0.0.1",
        "port-001",
        "port-001-00042",
        long.as_str(),
        label.as_str(),
        "a\nb",
    ] {
        assert!(dcp::validate_station_name(bad).is_err(), "{bad:?} accepted");
    }
}

#[test]
fn dcp_bounds_refuse_declared_lengths_past_the_frame() {
    // DCPDataLength past the frame.
    assert!(
        dcp::Pdu::parse(&[0xfe, 0xfe, 5, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0xff, 0xff, 0, 0]).is_err()
    );
    // DCPDataLength past what any Ethernet frame carries.
    let mut huge = vec![0xfe, 0xfe, 5, 0, 0, 0, 0, 1, 0, 0, 0x05, 0xd1];
    huge.resize(12 + 1489, 0);
    assert!(dcp::Pdu::parse(&huge).is_err());
    // A block declaring more than remains.
    assert!(
        dcp::Pdu::parse(&[0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0, 0, 6, 2, 2, 0, 9, 0, 0]).is_err()
    );
    // More blocks than the bound: 33 empty blocks.
    let mut many = vec![0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0];
    many.extend_from_slice(&((33 * 4) as u16).to_be_bytes());
    for _ in 0..33 {
        many.extend_from_slice(&[2, 7, 0, 0]);
    }
    let e = dcp::Pdu::parse(&many).unwrap_err().to_string();
    assert!(e.contains("more than 32"), "{e}");
    // 32 is fine.
    let mut ok = vec![0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0];
    ok.extend_from_slice(&((32 * 4) as u16).to_be_bytes());
    for _ in 0..32 {
        ok.extend_from_slice(&[2, 7, 0, 0]);
    }
    assert_eq!(dcp::Pdu::parse(&ok).unwrap().blocks.len(), 32);
    // Trailing Ethernet padding past DCPDataLength is ignored.
    let mut padded = dcp::identify_request(1, None, 0).encode().unwrap();
    padded.extend_from_slice(&[0; 30]);
    assert_eq!(dcp::Pdu::parse(&padded).unwrap().blocks.len(), 1);
}

#[test]
fn rpc_header_offsets_and_both_byte_orders() {
    let activity = rpc::parse_uuid("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let mut h = rpc::Header::request(
        rpc::object_uuid(1, 0x0105, 0x002a),
        rpc::IF_DEVICE,
        activity,
        0x11223344,
        rpc::opnum::CONNECT,
    );
    let be = rpc::encode(&h, &[0xaa; 3]).unwrap();
    assert_eq!(be.len(), 83);
    assert_eq!(&be[..8], &[4, 0, 0x20, 0, 0x00, 0, 0, 0]);
    // Object UUID DEA00000-6C97-11D1-8271-0001 0105 002A
    assert_eq!(
        &be[8..24],
        &[0xde, 0xa0, 0, 0, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0, 1, 0x01, 0x05, 0x00, 0x2a]
    );
    assert_eq!(&be[24..28], &[0xde, 0xa0, 0x00, 0x01]);
    assert_eq!(&be[64..68], &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(&be[74..76], &[0, 3]);
    h.little_endian = true;
    let le = rpc::encode(&h, &[0xaa; 3]).unwrap();
    assert_eq!(le[4], 0x10);
    // time_low, time_mid and time_hi_and_version swap; clock_seq and node do not.
    assert_eq!(
        &le[40..56],
        &[
            0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ]
    );
    assert_eq!(&le[64..68], &[0x44, 0x33, 0x22, 0x11]);
    let (back, body) = rpc::parse(&le).unwrap();
    assert_eq!(
        (back.activity, back.seqnum, body),
        (activity, 0x11223344, &[0xaa; 3][..])
    );
    // A body length past the datagram is refused, as is a datagram shorter than a header.
    let mut short = be.clone();
    short.truncate(82);
    assert!(rpc::parse(&short).is_err());
    assert!(rpc::parse(&be[..79]).is_err());
}

#[test]
fn ndr_header_lengths_must_agree() {
    let blocks = [1u8, 2, 3, 4];
    let body = rpc::ndr_request(1024, &blocks);
    let (ndr, b) = rpc::parse_ndr_request(&body, false).unwrap();
    assert_eq!((ndr.args_length, b), (4, &blocks[..]));
    // ActualCount disagreeing with ArgsLength.
    let mut bad = body.clone();
    bad[19] = 3;
    assert!(rpc::parse_ndr_request(&bad, false).is_err());
    // ArgsLength past the body.
    let mut past = rpc::ndr_request(1024, &blocks);
    past[7] = 9;
    past[19] = 9;
    assert!(rpc::parse_ndr_request(&past, false).is_err());
    // ArgsLength above ArgsMaximum.
    let mut over = rpc::ndr_request(1024, &blocks);
    over[0..4].copy_from_slice(&2u32.to_be_bytes());
    assert!(rpc::parse_ndr_request(&over, false).is_err());
}

fn expected_block(n_sub: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&0x32u32.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&n_sub.to_be_bytes());
    for i in 0..n_sub {
        b.extend_from_slice(&(i + 1).to_be_bytes());
        b.extend_from_slice(&0x132u32.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 1, 1, 1]);
    }
    blocks::block(blocks::block_type::EXPECTED_SUBMODULE_REQ, &b)
}

#[test]
fn block_bounds_refuse_counts_and_lengths() {
    let ok = expected_block(64);
    let raw = blocks::split_blocks(&ok).unwrap();
    assert_eq!(
        blocks::parse_expected_submodules(raw[0].body)
            .unwrap()
            .len(),
        64
    );
    let over = expected_block(65);
    let raw = blocks::split_blocks(&over).unwrap();
    assert!(blocks::parse_expected_submodules(raw[0].body)
        .unwrap_err()
        .to_string()
        .contains("exceeds 64"));
    // A declared count with nothing behind it.
    let mut lying = expected_block(1);
    lying[20..22].copy_from_slice(&60u16.to_be_bytes());
    let raw = blocks::split_blocks(&lying).unwrap();
    assert!(blocks::parse_expected_submodules(raw[0].body).is_err());
    // BlockLength past the data.
    let mut b = blocks::block(blocks::block_type::AR_REQ, &[0; 10]);
    b[3] = 40;
    assert!(blocks::split_blocks(&b).is_err());
    // More than 64 blocks.
    let many: Vec<u8> = (0..65).flat_map(|_| blocks::block(0x0108, &[])).collect();
    assert!(blocks::split_blocks(&many).is_err());
    // A station name longer than the standard allows.
    let mut ar = blocks::ArBlockReq {
        ar_type: 1,
        ar_uuid: [1; 16],
        session_key: 1,
        initiator_mac: [2; 6],
        initiator_object_uuid: [3; 16],
        ar_properties: 0x11,
        activity_timeout_factor: 100,
        initiator_udp_rt_port: 0x8892,
        station_name: "x".repeat(241),
    }
    .encode();
    let raw = blocks::split_blocks(&ar).unwrap();
    assert!(blocks::ArBlockReq::parse(raw[0].body).is_err());
    ar.clear();
}

#[test]
fn connect_blocks_round_trip() {
    let iocr = blocks::IocrBlockReq {
        iocr_type: 1,
        iocr_reference: 1,
        lt: 0x8892,
        properties: 1,
        data_length: 40,
        frame_id: 0xc001,
        send_clock_factor: 32,
        reduction_ratio: 32,
        phase: 1,
        sequence: 0,
        frame_send_offset: 0xffff_ffff,
        watchdog_factor: 3,
        data_hold_factor: 3,
        tag_header: 0xc000,
        multicast_mac: [0; 6],
        apis: vec![blocks::IocrApi {
            api: 0,
            io_data: vec![blocks::FrameDescriptor {
                slot: 1,
                subslot: 1,
                frame_offset: 0,
            }],
            iocs: vec![blocks::FrameDescriptor {
                slot: 1,
                subslot: 1,
                frame_offset: 2,
            }],
        }],
    };
    let enc = iocr.encode();
    // BlockLength 0x003c: 38 fixed octets after the header's length field + 2 + one API.
    assert_eq!(&enc[..6], &[0x01, 0x02, 0x00, (enc.len() - 4) as u8, 1, 0]);
    let raw = blocks::split_blocks(&enc).unwrap();
    assert_eq!(blocks::IocrBlockReq::parse(raw[0].body).unwrap(), iocr);
    assert_eq!(iocr.cycle_micros(), 32_000);

    let c = blocks::ControlBlock {
        block_type: blocks::block_type::PRM_END_REQ,
        ar_uuid: [7; 16],
        session_key: 3,
        control_command: blocks::control_command::PRM_END,
        properties: 0,
    };
    let enc = c.encode();
    assert_eq!(&enc[..6], &[0x01, 0x10, 0x00, 0x1c, 1, 0]);
    let back = blocks::ControlBlock::parse(&blocks::split_blocks(&enc).unwrap()[0]).unwrap();
    assert_eq!(back, c);
    assert_eq!(back.done().block_type, 0x8110);
}

#[test]
fn im0_is_sixty_octets_with_space_padded_strings() {
    let im0 = blocks::Im0 {
        vendor_id: 0x002a,
        order_id: "6ES7 151".into(),
        serial_number: "S1".into(),
        hardware_revision: 3,
        software_revision: blocks::parse_software_revision("V2.1.0").unwrap(),
        revision_counter: 0,
        profile_id: 0,
        profile_specific_type: 0,
        im_version: (1, 1),
        im_supported: 0x0002,
    };
    let enc = im0.encode().unwrap();
    assert_eq!(enc.len(), 60);
    assert_eq!(&enc[..8], &[0x00, 0x20, 0x00, 0x38, 1, 0, 0x00, 0x2a]);
    assert_eq!(&enc[8..28], b"6ES7 151            ");
    assert_eq!(&enc[46..50], &[b'V', 2, 1, 0]);
    assert_eq!(blocks::Im0::parse(&enc).unwrap(), im0);
    assert!(blocks::Im0 {
        order_id: "x".repeat(21),
        ..im0.clone()
    }
    .encode()
    .is_err());
    assert!(blocks::parse_software_revision("2.1.0").is_err());
}

#[test]
fn frame_layouts_are_checked_against_the_data_length() {
    let specs = values::default_layout();
    let input = rt::CrLayout::for_controller(&specs, true).unwrap();
    // Four objects (three DAP no-IO + slot 1's byte), one IOCS for slot 1's output.
    assert_eq!(input.objects.len(), 4);
    assert_eq!(input.iocs.len(), 1);
    assert_eq!(input.data_length, 40);
    let (io, iocs) = input.descriptors();
    let len_of = |slot: u16, subslot: u16| {
        specs
            .iter()
            .find(|s| s.slot == slot && s.subslot == subslot)
            .map(|s| s.input_len())
    };
    assert_eq!(
        rt::CrLayout::from_request(40, &io, &iocs, len_of).unwrap(),
        input
    );
    // Overlap, past the end, and a DataLength outside 40..=1440 are refused.
    let mut overlap = io.clone();
    overlap[1].frame_offset = 0;
    assert!(rt::CrLayout::from_request(40, &overlap, &iocs, len_of).is_err());
    let mut past = iocs.clone();
    past[0].frame_offset = 40;
    assert!(rt::CrLayout::from_request(40, &io, &past, len_of).is_err());
    assert!(rt::CrLayout::from_request(39, &io, &iocs, len_of).is_err());
    assert!(rt::CrLayout::from_request(1441, &io, &iocs, len_of).is_err());
}

#[test]
fn rt_frames_and_typed_values() {
    let p = rt::build_rt(0xc001, &[1, 0x80, 2, 0x80], 0x1234, rt::data_status::GOOD);
    assert_eq!(p, [0xc0, 0x01, 1, 0x80, 2, 0x80, 0x12, 0x34, 0x35, 0x00]);
    let f = rt::parse_rt(&p, 4).unwrap();
    assert_eq!((f.cycle_counter, f.data_status), (0x1234, 0x35));
    assert!(rt::parse_rt(&p, 5).is_err());
    let eth = rt::build_eth([1; 6], [2; 6], Some(0xc000), &p);
    assert_eq!(eth.len(), 60);
    assert_eq!(&eth[12..18], &[0x81, 0x00, 0xc0, 0x00, 0x88, 0x92]);
    assert_eq!(rt::parse_eth(&eth).unwrap().vlan_tci, Some(0xc000));

    let fields = values::parse_fields(
        Some(&json!([{"name": "t", "type": "i16"}, {"name": "on", "type": "bool"}, {"name": "f", "type": "f32"}])),
        "x",
    )
    .unwrap();
    let mut buf = vec![0u8; 7];
    values::encode_into(
        &fields,
        json!({"t": -2, "on": true, "f": 1.5}).as_object().unwrap(),
        &mut buf,
    )
    .unwrap();
    assert_eq!(buf, [0xff, 0xfe, 1, 0x3f, 0xc0, 0, 0]);
    assert_eq!(values::decode(&fields, &buf)["t"], -2);
    for bad in [
        json!({"t": 40000}),
        json!({"on": 2}),
        json!({"nope": 1}),
        json!({"t": "x"}),
    ] {
        assert!(
            values::encode_into(&fields, bad.as_object().unwrap(), &mut buf).is_err(),
            "{bad}"
        );
    }
}
