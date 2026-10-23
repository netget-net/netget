//! Inputs the fuzzers found, replayed against the code they crashed.
//!
//! Each byte string below is a crash artefact from the first CI fuzz run that actually built
//! (`fuzz.yml`, 23 October 2026). Until then every fuzz job was shut down while compiling, so
//! these three had never been run against their decoders. A crash in a fuzz target is a panic a
//! peer can trigger with one frame; each test fails, by panicking, on the code before its fix.

use netget::server::ethercat::{device, esc, frame, sii};
use netget::server::scsi_common as scsi;
use netget::server::zigbee::{ezsp, ncp};

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
