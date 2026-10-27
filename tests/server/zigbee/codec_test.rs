//! ASH and EZSP codecs against bytes another implementation wrote: frames bellows 0.46.2
//! put on the wire (captured from its debug log) and UG101's RST example, decoded and
//! re-encoded byte for byte; the deframer's bounds; EZSP header parsing; and the device
//! side's ZCL and ZDO encodings against the frame layouts of the Zigbee specification.
use netget::server::zigbee::{ash, device, ezsp};
use serde_json::json;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn deframe(wire: &[u8]) -> Vec<ash::Deframed> {
    let mut out = Vec::new();
    ash::Deframer::new().push(wire, &mut out);
    out
}

/// (frame number, ack number, EZSP frame, the bytes bellows wrote for it).
const BELLOWS_DATA: &[(u8, u8, &str, &str)] = &[
    (0, 0, "00000004", "004221a850ed2c7e"),
    (1, 1, "000001000011", "7d314221a9542a040fc77e"),
    (2, 2, "010001470003000000", "224321a97d332a16b25994e79e7e"),
    (3, 3, "020001aa003a", "334021a9fe2a2f65c67e"),
];

#[test]
fn bellows_data_frames_decode_and_reencode_byte_for_byte() {
    for (frm, ack, ezsp_hex, wire_hex) in BELLOWS_DATA {
        let wire = unhex(wire_hex);
        let ezsp = unhex(ezsp_hex);
        assert_eq!(
            ash::data_frame(*frm, false, *ack, &ezsp),
            wire,
            "{wire_hex}"
        );
        let d = deframe(&wire);
        let [ash::Deframed::Frame(raw)] = d.as_slice() else {
            panic!("one frame from {wire_hex}: {d:?}")
        };
        assert_eq!(
            ash::Frame::parse(raw).unwrap(),
            ash::Frame::Data {
                frm_num: *frm,
                re_tx: false,
                ack_num: *ack,
                ezsp: ezsp.clone()
            }
        );
    }
}

#[test]
fn control_frames_match_bellows_and_ug101() {
    // UG101's RST example, which bellows also sends, CANCEL first.
    assert_eq!(ash::rst_frame(), unhex("1ac038bc7e"));
    assert_eq!(
        ash::rstack_frame(ash::reset::SOFTWARE),
        unhex("c1020b0a527e")
    );
    for (n, hexs) in [(1u8, "8160597e"), (2, "82503a7e"), (3, "83401b7e")] {
        assert_eq!(ash::ack_frame(n, false), unhex(hexs));
        let d = deframe(&unhex(hexs));
        let [ash::Deframed::Frame(raw)] = d.as_slice() else {
            panic!()
        };
        assert_eq!(
            ash::Frame::parse(raw).unwrap(),
            ash::Frame::Ack {
                not_ready: false,
                ack_num: n
            }
        );
    }
    // CRC-CCITT (0x1021, initial 0xFFFF): the RST frame's.
    assert_eq!(ash::crc(&[0xC0]), 0x38BC);
    // The randomisation sequence UG101 prints: 42 21 A8 54 2A.
    let mut zeros = [0u8; 5];
    ash::randomize(&mut zeros);
    assert_eq!(zeros, [0x42, 0x21, 0xA8, 0x54, 0x2A]);
}

#[test]
fn a_corrupted_crc_is_refused() {
    let mut raw = match deframe(&unhex("004221a850ed2c7e")).remove(0) {
        ash::Deframed::Frame(r) => r,
        other => panic!("{other:?}"),
    };
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    assert_eq!(ash::Frame::parse(&raw), Err(ash::FrameError::BadCrc));
}

#[test]
fn the_deframer_is_bounded_and_handles_cancel_and_substitute() {
    // A maximal frame passes; one byte more is reported at once, before any flag.
    let max = ash::data_frame(0, false, 0, &vec![0u8; ash::MAX_DATA]);
    assert!(
        matches!(deframe(&max).as_slice(), [ash::Deframed::Frame(r)] if r.len() == ash::MAX_FRAME)
    );
    let mut out = Vec::new();
    let mut d = ash::Deframer::new();
    d.push(&vec![0x41; ash::MAX_FRAME + 1], &mut out);
    assert_eq!(out, vec![ash::Deframed::TooLong]);
    assert_eq!(d.held(), 0, "nothing is kept of an over-long frame");
    // A megabyte without a flag still holds nothing and reports once.
    out.clear();
    d.push(&vec![0x41; 1 << 20], &mut out);
    assert!(out.is_empty());
    assert_eq!(d.held(), 0);
    // The flag ends the discarding; the next frame is whole.
    d.push(&[ash::FLAG], &mut out);
    d.push(&unhex("8160597e"), &mut out);
    assert!(matches!(out.as_slice(), [ash::Deframed::Frame(_)]));
    // CANCEL drops a frame in progress; SUBSTITUTE spoils it up to the flag.
    let mut wire = vec![0x81, 0x60, ash::CANCEL];
    wire.extend(unhex("8160597e"));
    assert!(matches!(
        deframe(&wire).as_slice(),
        [ash::Deframed::Cancelled, ash::Deframed::Frame(_)]
    ));
    let wire = [0x81, ash::SUBSTITUTE, 0x60, 0x59, 0x7e];
    assert_eq!(deframe(&wire), vec![ash::Deframed::Corrupt]);
    // An escape of a byte that is not reserved is a corrupt frame.
    assert_eq!(
        deframe(&[0x81, ash::ESCAPE, 0x00, 0x7e]),
        vec![ash::Deframed::Corrupt]
    );
    // XON/XOFF are flow control, never data.
    assert!(
        matches!(deframe(&[0x81, ash::XON, 0x60, ash::XOFF, 0x59, 0x7e]).as_slice(), [ash::Deframed::Frame(r)] if r == &vec![0x81, 0x60, 0x59])
    );
}

#[test]
fn ezsp_headers() {
    let legacy = ezsp::parse_command(&[7, 0x00, 0x00, 4]).unwrap();
    assert!(legacy.legacy && legacy.frame_id == 0 && legacy.params == vec![4]);
    let ext = ezsp::parse_command(&[9, 0x00, 0x01, 0x14, 0x01, 0xAA]).unwrap();
    assert!(!ext.legacy && ext.frame_id == 0x0114 && ext.params == vec![0xAA]);
    assert_eq!(
        ezsp::parse_command(&[1, 0x80, 0x01, 0, 0]).unwrap_err().1,
        ezsp::HeaderError::WrongDirection
    );
    assert_eq!(
        ezsp::parse_command(&[1, 0x00, 0x81, 0, 0]).unwrap_err().1,
        ezsp::HeaderError::UnsupportedControl
    );
    assert_eq!(
        ezsp::parse_command(&[1, 0x00]).unwrap_err().1,
        ezsp::HeaderError::TooShort
    );
    assert_eq!(
        ezsp::response(&ext, &[1]),
        vec![9, 0x80, 0x01, 0x14, 0x01, 1]
    );
    assert_eq!(ezsp::response(&legacy, &[17]), vec![7, 0x80, 0x00, 17]);
    assert_eq!(
        ezsp::callback(3, 0x0019, &[0x15, 0, 0, 0]),
        vec![3, 0x90, 0x01, 0x19, 0x00, 0x15, 0, 0, 0]
    );
}

fn lamp() -> device::Device {
    device::parse_device(
        &json!({"name": "lamp", "ieee": "00:12:4b:00:01:02:03:04", "nwk": "0x1234",
                "manufacturer": "NetGet", "model": "Lamp-1",
                "endpoints": [{"id": 1, "device_type": 256, "in_clusters": ["basic", "on_off"], "out_clusters": ["ota"],
                               "attributes": [{"cluster": "on_off", "attribute": 0, "type": "bool", "value": true},
                                              {"cluster": "on_off", "attribute": 0x4003, "type": "enum8", "value": 255}]}]}),
        &[],
    )
    .unwrap()
}

#[test]
fn zdo_answers_follow_the_specification_layouts() {
    let d = lamp();
    // Simple_Desc_rsp: tsn, status, nwk, length, endpoint, profile, device, version, in, out.
    let r = device::zdo(&d, 0x0004, &[5, 0x34, 0x12, 1], false).unwrap();
    assert_eq!(r.cluster, 0x8004);
    assert_eq!(
        r.payload,
        vec![
            5, 0, 0x34, 0x12, 14, 1, 0x04, 0x01, 0x00, 0x01, 1, 2, 0x00, 0x00, 0x06, 0x00, 1, 0x19,
            0x00
        ]
    );
    // An endpoint the device does not have: NOT_ACTIVE with a zero length.
    let r = device::zdo(&d, 0x0004, &[6, 0x34, 0x12, 9], false).unwrap();
    assert_eq!(r.payload, vec![6, 0x83, 0x34, 0x12, 0]);
    // IEEE_addr_rsp carries the IEEE little-endian.
    let r = device::zdo(&d, 0x0001, &[7, 0x34, 0x12, 0, 0], false).unwrap();
    assert_eq!(
        r.payload,
        vec![7, 0, 4, 3, 2, 1, 0, 0x4b, 0x12, 0, 0x34, 0x12]
    );
    // NWK_addr_req broadcast for someone else: silence.
    assert!(device::zdo(&d, 0x0000, &[8, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0], true).is_none());
    // Device_annce: tsn, nwk, ieee, capability (router, mains, rx on, allocate).
    assert_eq!(
        device::device_announce(&d, 1),
        vec![1, 0x34, 0x12, 4, 3, 2, 1, 0, 0x4b, 0x12, 0, 0x8E]
    );
}

#[test]
fn zcl_read_configure_and_discover() {
    let d = lamp();
    let read = |p: &[u8]| match device::zcl(&d, 1, 6, p) {
        device::ZclOutcome::Reply(r) => r,
        other => panic!("{other:?}"),
    };
    // Read: on_off true, an unknown attribute unsupported; server-to-client, no default rsp.
    assert_eq!(
        read(&[0x00, 3, 0x00, 0x00, 0x00, 0x01, 0x00]),
        vec![0x18, 3, 0x01, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x86]
    );
    // Configure Reporting for a described attribute: a single SUCCESS.
    assert_eq!(
        read(&[0x00, 4, 0x06, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x2c, 0x01]),
        vec![0x18, 4, 0x07, 0x00]
    );
    // Discover Attributes from 0: complete, two attributes with their types.
    assert_eq!(
        read(&[0x00, 5, 0x0C, 0x00, 0x00, 10]),
        vec![0x18, 5, 0x0D, 1, 0x00, 0x00, 0x10, 0x03, 0x40, 0x30]
    );
    // A cluster command goes to the model, decoded.
    match device::zcl(&d, 1, 6, &[0x01, 6, 0x02]) {
        device::ZclOutcome::Ask(r) => assert_eq!((r.cluster, r.header.command), (6, 2)),
        other => panic!("{other:?}"),
    }
    // A general command NetGet does not implement: UNSUP_GENERAL_COMMAND.
    assert_eq!(
        read(&[0x00, 7, 0x15, 0, 0, 1]),
        vec![0x18, 7, 0x0B, 0x15, 0x82]
    );
    // Too short to carry a sequence number: nothing to reply to.
    assert!(matches!(
        device::zcl(&d, 1, 6, &[0x00]),
        device::ZclOutcome::Nothing
    ));
    // A Read Attributes Response is cut to one frame.
    let many: Vec<u8> = std::iter::once(0x00)
        .chain([8, 0x00])
        .chain((0..60u16).flat_map(|_| [0x00, 0x00]))
        .collect();
    assert!(read(&many).len() <= device::MAX_APS_PAYLOAD);
}

#[test]
fn descriptions_are_bounded() {
    let bad = [
        (
            json!({"ieee": "0012", "endpoints": [{"id": 1}]}),
            "16 hex digits",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "endpoints": []}),
            "1 to 8 endpoints",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "nwk": 0, "endpoints": [{"id": 1}]}),
            "coordinator",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "endpoints": [{"id": 241}]}),
            "application endpoint",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "endpoints": [{"id": 1, "in_clusters": [6],
            "attributes": [{"cluster": 6, "attribute": 0, "type": "uint8", "value": 256}]}]}),
            "does not fit",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "endpoints": [{"id": 1, "in_clusters": [6],
            "attributes": [{"cluster": 8, "attribute": 0, "type": "uint8", "value": 1}]}]}),
            "does not serve",
        ),
        (
            json!({"ieee": "00:12:4b:00:01:02:03:04", "endpoints": [{"id": 1, "in_clusters": [0],
            "attributes": [{"cluster": 0, "attribute": 5, "type": "string", "value": "x".repeat(65)}]}]}),
            "at most 64",
        ),
    ];
    for (v, why) in bad {
        let e = device::parse_device(&v, &[]).unwrap_err();
        assert!(format!("{e:#}").contains(why), "{why}: {e:#}");
    }
}
