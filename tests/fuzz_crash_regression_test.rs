//! Inputs the fuzzers found, replayed against the code they crashed.
//!
//! Each byte string below is a crash artefact from the first CI fuzz runs that actually built
//! (`fuzz.yml`, 23 and 24 October 2026). Until then every fuzz job was shut down while
//! compiling, so these had never been run against their decoders. A crash in a fuzz target is
//! a panic, or a malformed reply, that one peer frame triggers; each test fails on the code
//! before its fix.

use netget::server::ethercat::{device, esc, frame, sii};
use netget::server::scsi_common as scsi;
use netget::server::zigbee::device as zigbee_device;
use netget::server::zigbee::{ezsp, ncp};
use netget::utils::display::try_display;

/// `fuzz/artifacts/ethercat_frame/crash-625f5eb52f102ed96c84440cf599d8ca8b83c0f3`: a datagram
/// reading zero octets at 0x3F07, past the end of the 12 KiB ESC memory. The zero-length check
/// came before the bounds check, so the access was allowed and `mem[addr..addr]` panicked.
#[test]
fn ethercat_zero_length_access_past_the_end_is_refused_not_a_panic() {
    let input: &[u8] = &[
        0x0e, 0x10, 0x07, 0x3f, 0x0e, 0x10, 0x07, 0x3f, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let datagrams = frame::decode(input).expect("the crash input decodes as a frame");
    let mut chain: Vec<esc::Esc> = (0..2)
        .map(|i| esc::Esc::new(i, 2, device::default_device(i), sii::DEFAULT_MAILBOX))
        .collect();
    let mut buf = input.to_vec();
    esc::process_frame(&mut chain, &mut buf).expect("a frame that decodes is processed");
    assert_eq!(buf.len(), input.len());
    let after = frame::decode(&buf).expect("the processed frame still decodes");
    assert_eq!(after.len(), datagrams.len());
}

/// `fuzz/artifacts/zigbee_ash_ezsp/crash-a8cd80f3b450a023044f4f79582b3028827e5f84`: an
/// extended-header frame with id 0x0019, `stackStatusHandler`. That is a callback, which only
/// an NCP sends; `ezsp::name` knows it, so it passed the "unknown id" check and reached an
/// `unreachable!()` in the command dispatcher. It is now `invalidCommand` with
/// ERROR_INVALID_FRAME_ID, as for any id the NCP does not accept.
#[test]
fn zigbee_callback_id_from_the_host_is_an_invalid_frame_id_not_a_panic() {
    let input: &[u8] = &[
        0x06, 0x00, 0x01, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x34, 0x08, 0xf7,
        0x00, 0x2a, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00,
    ];
    let cmd = ezsp::parse_command(input).expect("the crash input parses as a command");
    assert_eq!(cmd.frame_id, ezsp::id::STACK_STATUS_HANDLER);

    let mut ram = ncp::Ram::new();
    ram.version = Some(ezsp::DEFAULT_VERSION);
    ram.up = true;
    let mut nv = ncp::Nvram {
        eui64: ncp::DEFAULT_EUI64,
        network: None,
        nwk_frame_counter: 0,
        aps_frame_counter: 0,
        joined: Vec::new(),
        waiting: Vec::new(),
        link_keys: Vec::new(),
    };
    let handled = ncp::handle(ezsp::DEFAULT_VERSION, &mut ram, &mut nv, &cmd);
    assert_eq!(
        handled.response,
        ezsp::invalid_command(&cmd, ezsp::ezsp_status::ERROR_INVALID_FRAME_ID),
        "a callback id from the host is answered invalidCommand / ERROR_INVALID_FRAME_ID"
    );
    assert!(handled.callbacks.is_empty());
}

/// `fuzz/artifacts/iscsi_pdu/crash-edbbd1f71011efc354f11ec8973fb5ac4f2297f6` held a 9-byte
/// READ(10), `28 ff ff df ff 2d 00 32 2d`: everything but the control byte. The decoder read
/// only the fields it used, so it accepted the CDB with a 12,845-block transfer. A CDB shorter
/// than its form is not a READ or WRITE.
#[test]
fn scsi_read_write_shorter_than_its_form_is_not_decoded() {
    let truncated_read_10: &[u8] = &[0x28, 0xff, 0xff, 0xdf, 0xff, 0x2d, 0x00, 0x32, 0x2d];
    assert!(scsi::decode_read_write(truncated_read_10).is_none());

    // Each form one byte short is refused, and the full form still decodes.
    for (op, form) in [(0x08u8, 6usize), (0x28, 10), (0xa8, 12), (0x88, 16)] {
        let mut cdb = vec![0u8; form];
        cdb[0] = op;
        assert!(
            scsi::decode_read_write(&cdb[..form - 1]).is_none(),
            "opcode {op:#04x} with {} of {form} bytes",
            form - 1
        );
        assert!(
            scsi::decode_read_write(&cdb).is_some(),
            "opcode {op:#04x} with all {form} bytes"
        );
    }

    let mut read_10 = [0u8; 10];
    read_10[0] = 0x28;
    read_10[2..6].copy_from_slice(&0x0001_0203u32.to_be_bytes());
    read_10[7..9].copy_from_slice(&8u16.to_be_bytes());
    let rw = scsi::decode_read_write(&read_10).expect("a whole READ(10) decodes");
    assert_eq!((rw.write, rw.lba, rw.blocks), (false, 0x0001_0203, 8));
}

/// `fuzz/artifacts/zigbee_ash_ezsp/` (24 October 2026): a Configure Reporting for the On/Off
/// cluster naming attributes the device does not describe. Every one failed, and the response
/// listed them all, 86 octets, past the 82 an APS frame carries. Like Read Attributes, it now
/// carries the records that fit.
#[test]
fn zigbee_configure_reporting_reply_fits_one_aps_frame() {
    let input: &[u8] = &[
        0x06, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x93, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x19, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x93, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x93, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    ];
    let cluster = u16::from(input[0]) | (u16::from(input[1] & 0x7F) << 8);
    let lamp = zigbee_device::parse_device(
        &serde_json::json!({"name": "lamp", "ieee": "00:12:4b:00:01:02:03:04", "nwk": "0x1234",
            "manufacturer": "NetGet", "model": "Lamp-1",
            "endpoints": [{"id": 1, "in_clusters": ["basic", "on_off", "level_control"], "out_clusters": ["ota"],
                "attributes": [{"cluster": "on_off", "attribute": 0, "type": "bool", "value": true},
                    {"cluster": "level_control", "attribute": 0, "type": "uint8", "value": 9}]}]}),
        &[],
    )
    .expect("the lamp parses");
    match zigbee_device::zcl(&lamp, 1, cluster, &input[2..]) {
        zigbee_device::ZclOutcome::Reply(r) => {
            assert!(
                r.len() <= zigbee_device::MAX_APS_PAYLOAD,
                "a {}-octet ZCL reply does not fit one APS frame",
                r.len()
            );
            assert_eq!(r[2], 0x07, "the reply is a Configure Reporting Response");
        }
        _ => panic!("a Configure Reporting for a described cluster is answered"),
    }
}

/// `fuzz/artifacts/dns_message/crash-cd477a70017bdc829af6ee6483f4d458745950fd`: a message
/// whose record data hickory-proto decodes but whose own `Display` then returns `Err`, which
/// `to_string()` turns into a panic. The DoH and DoQ clients printed every answer's data that
/// way, so a hostile server could stop them with one response; they now go through
/// `try_display`.
#[test]
fn dns_record_data_whose_display_fails_is_not_a_panic() {
    let input: &[u8] = &[
        0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0xf1,
        0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x31, 0x00, 0xff, 0xff, 0xfc, 0x00, 0x12, 0x34,
        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x12, 0xff, 0x34, 0x00, 0x00, 0x29, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0xf1, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    ];
    let msg = hickory_proto::op::Message::from_vec(input).expect("the crash input decodes");
    let shown: Vec<Option<String>> = msg
        .answers()
        .iter()
        .chain(msg.name_servers())
        .chain(msg.additionals())
        .filter_map(|r| r.data())
        .map(try_display)
        .collect();
    assert!(
        shown.iter().any(Option::is_none),
        "the input still holds record data hickory cannot print, or this test proves nothing"
    );
}

/// `zigbee_mt` (local run, 24 October 2026), input `01 00`: the target sends the bytes as a
/// command whose subsystem and id the first two name — here SYS 0x00, which is
/// `SYS_RESET_REQ`. That is an AREQ; sent as an SREQ it passed the "known name" check and
/// reached an `unreachable!()` in the firmware's dispatcher, killing the host's session. It is
/// now the RPC error SRSP for a command the firmware does not have as a request.
#[test]
fn zigbee_reset_req_sent_as_an_sreq_is_an_rpc_error_not_a_panic() {
    use netget::server::zigbee::mt::{self, kind, subsystem, Frame};
    use netget::server::zigbee::znp;

    let mut nv = ncp::Nvram {
        eui64: znp::DEFAULT_EUI64,
        network: None,
        nwk_frame_counter: 0,
        aps_frame_counter: 0,
        joined: Vec::new(),
        waiting: Vec::new(),
        link_keys: Vec::new(),
    };
    let mut flash = znp::Flash::initial(&nv);
    let mut ram = znp::Ram::new();
    let sreq = Frame::new(kind::SREQ, subsystem::SYS, 0x00, Vec::new());
    let handled = znp::handle(&mut ram, &mut flash, &mut nv, &sreq);
    assert_eq!(
        handled.response,
        Some(Frame::rpc_error(mt::rpc_error::INVALID_COMMAND_ID, &sreq)),
        "SYS_RESET_REQ as an SREQ is answered with the RPC error"
    );
    assert!(
        handled.areqs.is_empty() && handled.effects.is_empty(),
        "and does not reset"
    );
    // As the AREQ it is, it resets.
    let areq = Frame::new(kind::AREQ, subsystem::SYS, 0x00, vec![1]);
    let handled = znp::handle(&mut ram, &mut flash, &mut nv, &areq);
    assert!(handled.response.is_none());
    assert_eq!(handled.areqs.len(), 1, "SYS_RESET_IND");
}
