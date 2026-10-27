//! MT framing, the Z-Stack NV structures and the EZSP 8–13 encodings, on literal bytes.
//!
//! The MT vectors are TI's own (`SYS_RESET_REQ` from the Z-Stack Monitor and Test API
//! document) and what zigpy-znp and herdsman put on the wire; the NIB offsets are zigpy-znp's
//! aligned `NIB` struct (116 bytes on CC26xx), which herdsman's struct reproduces.
use netget::server::zigbee::legacy;
use netget::server::zigbee::mt::{self, kind, subsystem, Deframed, Deframer, Frame};
use netget::server::zigbee::ncp::{Callback, Nvram};
use netget::server::zigbee::znp::{self, cmd};

fn nvram() -> Nvram {
    Nvram {
        eui64: znp::DEFAULT_EUI64,
        network: None,
        nwk_frame_counter: 0,
        aps_frame_counter: 0,
        joined: Vec::new(),
        waiting: Vec::new(),
        link_keys: Vec::new(),
    }
}

#[test]
fn frames_encode_and_decode_byte_for_byte() {
    // TI's example: SYS_RESET_REQ, soft (AREQ 0x41 0x00, type 0).
    let reset = Frame::new(kind::AREQ, subsystem::SYS, 0x00, vec![0x00]);
    assert_eq!(reset.encode(), vec![0xFE, 0x01, 0x41, 0x00, 0x00, 0x40]);
    // zigpy-znp's and herdsman's SYS_PING.
    let ping = vec![0xFE, 0x00, 0x21, 0x01, 0x20];
    let f = Frame::decode(&ping).expect("a frame");
    assert_eq!(
        (f.kind, f.subsystem, f.id, f.data.len()),
        (kind::SREQ, subsystem::SYS, 1, 0)
    );
    assert_eq!(f.encode(), ping);
    // The RPC error for an SREQ the firmware does not have: [error, cmd0, cmd1] in
    // subsystem 0 (SRSP 0x60 0x00).
    assert_eq!(
        Frame::rpc_error(mt::rpc_error::INVALID_COMMAND_ID, &f).encode(),
        vec![0xFE, 0x03, 0x60, 0x00, 0x02, 0x21, 0x01, 0x41]
    );
    assert_eq!(mt::fcs(&[0x01, 0x41, 0x00, 0x00]), 0x40);
    // A bad FCS and an impossible length do not decode.
    assert_eq!(
        Frame::decode(&[0xFE, 0x00, 0x21, 0x01, 0x21]),
        Err(mt::Bad::Fcs)
    );
    let mut long = vec![0xFE, 251, 0x21, 0x01];
    long.extend(vec![0; 252]);
    assert_eq!(Frame::decode(&long), Err(mt::Bad::TooLong(251)));
    // A frame built with too much data is cut at the bound, never sent with a lying length.
    let big = Frame::srsp(subsystem::SYS, 0x08, vec![7; 300]).encode();
    assert_eq!(big.len(), mt::MAX_FRAME);
    assert_eq!(big[1] as usize, mt::MAX_DATA);
    assert!(Frame::decode(&big).is_ok());
}

#[test]
fn the_deframer_hunts_for_sof_and_never_holds_more_than_one_frame() {
    let mut d = Deframer::new();
    let mut out = Vec::new();
    // Bootloader-skip bytes, then a PING split across two reads.
    d.push(&[0xEF, 0xEF, 0xEF, 0xFE, 0x00], &mut out);
    assert_eq!(out, vec![Deframed::Skipped(3)]);
    assert_eq!(d.held(), 2);
    d.push(&[0x21, 0x01, 0x20], &mut out);
    assert!(matches!(&out[1], Deframed::Frame(f) if f.id == 1));
    assert_eq!(d.held(), 0);
    // A bad FCS is reported with the command it would have been, and dropped.
    out.clear();
    d.push(&[0xFE, 0x00, 0x21, 0x02, 0x00], &mut out);
    assert_eq!(
        out,
        vec![Deframed::BadFcs {
            cmd0: 0x21,
            cmd1: 0x02
        }]
    );
    // The length bomb: SOF and 0xFF. Not a frame; the next SOF starts one.
    out.clear();
    d.push(&[0xFE, 0xFF, 0xFE, 0x00, 0x21, 0x01, 0x20], &mut out);
    assert_eq!(out[0], Deframed::TooLong(0xFF));
    assert!(matches!(&out[1], Deframed::Frame(_)));
    // A megabyte of SOFs: each is followed by 0xFE (254 > 250), so nothing is ever held
    // beyond one byte; a megabyte without an SOF holds nothing at all.
    out.clear();
    d.push(&vec![0xFE; 1 << 20], &mut out);
    assert!(d.held() <= 1);
    d.push(&vec![0x00; 1 << 20], &mut out);
    assert_eq!(d.held(), 0);
    // A maximal frame is held whole, and no more.
    out.clear();
    let mut d = Deframer::new();
    let max = Frame::new(kind::SREQ, subsystem::SYS, 0x1D, vec![1; mt::MAX_DATA]).encode();
    d.push(&max[..max.len() - 1], &mut out);
    assert_eq!(d.held(), mt::MAX_FRAME - 1);
    d.push(&max[max.len() - 1..], &mut out);
    assert!(matches!(&out[0], Deframed::Frame(f) if f.data.len() == mt::MAX_DATA));
}

#[test]
fn the_nib_is_the_aligned_cc26xx_layout() {
    let nib = znp::build_nib(15, 0x1a62, [0xdd; 8], 1 << 15, 0x0012_4B00_0102_0304, 3);
    assert_eq!(nib.len(), 116);
    assert_eq!(nib[24], 15, "nwkLogicalChannel");
    assert_eq!(&nib[36..38], &[0x62, 0x1a], "nwkPanId");
    assert_eq!(&nib[40..44], &(1u32 << 15).to_le_bytes(), "channelList");
    assert_eq!(&nib[57..65], &[0xdd; 8], "extendedPANID");
    assert_eq!(nib[65], 1, "nwkKeyLoaded");
    assert_eq!(nib[114], 3, "nwkUpdateId");
    let v = znp::read_nib(&nib).unwrap();
    assert_eq!(
        (v.channel, v.pan_id, v.update_id, v.key_loaded),
        (15, 0x1a62, 3, true)
    );
    assert!(
        znp::read_nib(&nib[..115]).is_none(),
        "a short NIB is not a NIB"
    );
}

#[test]
fn the_firmware_answers_srsp_for_sreq_and_never_for_anything_else() {
    let mut nv = nvram();
    let mut flash = znp::Flash::initial(&nv);
    let mut ram = znp::Ram::new();
    let ping = Frame::new(kind::SREQ, subsystem::SYS, cmd::sys::PING, vec![]);
    let h = znp::handle(&mut ram, &mut flash, &mut nv, &ping);
    let r = h.response.expect("an SRSP");
    assert_eq!(
        (r.kind, r.subsystem, r.id),
        (kind::SRSP, subsystem::SYS, cmd::sys::PING)
    );
    for k in [kind::POLL, kind::SRSP, kind::AREQ] {
        let f = Frame::new(k, subsystem::SYS, cmd::sys::PING, vec![]);
        assert!(znp::handle(&mut ram, &mut flash, &mut nv, &f)
            .response
            .is_none());
    }
    // A reset answers with SYS_RESET_IND and clears what RAM held.
    ram.state = znp::state::COORDINATOR;
    let reset = Frame::new(kind::AREQ, subsystem::SYS, cmd::sys::RESET_REQ, vec![1]);
    let h = znp::handle(&mut ram, &mut flash, &mut nv, &reset);
    assert!(h.response.is_none());
    assert_eq!(h.areqs[0].id, cmd::sys::RESET_IND);
    assert_eq!(ram.state, znp::state::HOLD);
}

#[test]
fn ezsp_13_statuses_and_layouts() {
    use netget::server::zigbee::ezsp::{id, sl};
    // EmberStatus for the stack, EzspStatus for the configuration, unchanged for the
    // security manager.
    assert_eq!(legacy::ember_status(sl::NETWORK_UP), 0x90);
    assert_eq!(legacy::ember_status(sl::ZIGBEE_DELIVERY_FAILED), 0x66);
    assert_eq!(legacy::ezsp_status(sl::INVALID_PARAMETER), 0x37);
    assert_eq!(
        legacy::downgrade_params(13, id::FORM_NETWORK, &sl::INVALID_STATE.to_le_bytes()),
        vec![0x70]
    );
    assert_eq!(
        legacy::downgrade_params(13, id::GET_VALUE, &[0x21, 0, 0, 0, 1, 7]),
        vec![0x37, 1, 7]
    );
    assert_eq!(
        legacy::downgrade_params(13, id::GET_NETWORK_KEY_INFO, &[0, 0, 0, 0, 1]),
        vec![0, 0, 0, 0, 1]
    );
    assert!(legacy::downgrade_params(13, id::SET_EXTENDED_TIMEOUT, &[0, 0, 0, 0]).is_empty());
    // exportKey: status, key, context (v14) becomes key, status.
    let mut v14 = vec![0, 0, 0, 0];
    v14.extend(1..=16u8);
    v14.extend([9u8; 18]);
    let mut v13 = (1..=16u8).collect::<Vec<_>>();
    v13.extend([0, 0, 0, 0]);
    assert_eq!(legacy::downgrade_params(13, id::EXPORT_KEY, &v14), v13);
    // stackStatusHandler and messageSentHandler.
    let cb = legacy::callback(
        13,
        Callback {
            frame_id: id::STACK_STATUS_HANDLER,
            params: sl::NETWORK_DOWN.to_le_bytes().to_vec(),
        },
    );
    assert_eq!(cb.params, vec![0x91]);
    let mut sent = sl::ZIGBEE_DELIVERY_FAILED.to_le_bytes().to_vec();
    sent.push(0x00); // direct
    sent.extend_from_slice(&0x4a21u16.to_le_bytes());
    sent.extend([0xAA; 11]); // APS frame
    sent.extend_from_slice(&0x1234u16.to_le_bytes()); // tag
    sent.push(0); // no contents
    let cb = legacy::callback(
        13,
        Callback {
            frame_id: id::MESSAGE_SENT_HANDLER,
            params: sent,
        },
    );
    let mut want = vec![0x00, 0x21, 0x4a];
    want.extend([0xAA; 11]);
    want.extend([0x34, 0x66, 0]);
    assert_eq!(
        cb.params, want,
        "type, destination, APS, 8-bit tag, EmberStatus, contents"
    );
    // At 14 and later nothing changes.
    let raw = Callback {
        frame_id: id::STACK_STATUS_HANDLER,
        params: vec![0x15, 0, 0, 0],
    };
    assert_eq!(legacy::callback(14, raw.clone()), raw);
}
