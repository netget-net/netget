//! `netget::server::iscsi` and `netget::server::scsi_common` — everything the iSCSI target and
//! initiator run on what a peer sends: PDU framing (with and without CRC32C digests, under a
//! small and a large MaxRecvDataSegmentLength), login and text keys, both roles' negotiation of
//! every key a peer can propose, CHAP's binary values, and the SCSI answers an initiator
//! decodes (sense in both formats, INQUIRY, VPD designators, READ CAPACITY, REPORT LUNS, LUN
//! fields) and the CDBs a target decodes.
//!
//! What parses is checked to stay within its bound: a decoded PDU's data never longer than
//! the limit it was read under, text never more than MAX_KEYS keys of bounded length, a LUN
//! never past 16383, a CDB's block count never past 2^32. None of these decoders recurses, so
//! the corpus carries the long and repetitive inputs instead: a login of 128 keys, a train of
//! back-to-back PDUs, sense data whose descriptor list runs past its buffer, and a REPORT LUNS
//! list claiming more LUNs than it carries (`depth_bomb` is the deepest of these: a designator
//! list of 0-length entries that a recursive walker would descend through one by one).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::iscsi::{chap, pdu, text};
use netget::server::scsi_common as scsi;

fuzz_target!(|data: &[u8]| {
    for (digests, max) in [
        (pdu::Digests::default(), pdu::DEFAULT_MAX_RECV_DATA_SEGMENT),
        (
            pdu::Digests {
                header: true,
                data: true,
            },
            text::OUR_MAX_RECV_DATA_SEGMENT as usize,
        ),
    ] {
        let mut rest = data;
        for _ in 0..64 {
            match pdu::decode(rest, digests, max) {
                Ok(Some((p, used))) => {
                    assert!(p.data.len() <= max);
                    assert!(used > 0 && used <= rest.len());
                    peer_payload(&p);
                    rest = &rest[used..];
                }
                Ok(None) => break,
                Err(pdu::ReadError::Oversize { declared, limit }) => {
                    assert!(declared > limit);
                    break;
                }
                Err(_) => break,
            }
        }
    }
    // The data on its own, as each SCSI answer an initiator decodes.
    scsi_answers(data);
    for cdb in data.chunks(16) {
        if let Some(rw) = scsi::decode_read_write(cdb) {
            assert!(rw.blocks <= 256 || cdb.len() >= 10);
        }
    }
});

fn peer_payload(p: &pdu::Pdu) {
    if matches!(
        p.opcode(),
        pdu::op::LOGIN_REQUEST
            | pdu::op::LOGIN_RESPONSE
            | pdu::op::TEXT_REQUEST
            | pdu::op::TEXT_RESPONSE
    ) {
        if let Ok(pairs) = text::parse(&p.data) {
            assert!(pairs.len() <= text::MAX_KEYS);
            let mut target = text::Params::default();
            let mut initiator = text::Params::default();
            for (k, v) in &pairs {
                assert!(k.len() <= text::MAX_KEY && v.len() <= text::MAX_VALUE);
                let _ = text::negotiate_as_target(
                    &mut target,
                    k,
                    v,
                    &text::TargetOffer {
                        max_connections: 8,
                        error_recovery_level: 2,
                        ..Default::default()
                    },
                );
                let _ = text::apply_as_initiator(&mut initiator, k, v);
                if let Some(b) = chap::decode_binary(v) {
                    assert!(!b.is_empty() && b.len() <= chap::MAX_BINARY);
                }
            }
            assert!(target.first_burst <= target.max_burst);
        }
    }
    if let Some(n) = scsi::lun_from_field(&p.lun()) {
        assert!(n <= 16383);
    }
    scsi_answers(&p.data);
}

fn scsi_answers(d: &[u8]) {
    let _ = scsi::Sense::parse(d).map(|s| s.describe());
    if d.len() >= 2 {
        let n = u16::from_be_bytes([d[0], d[1]]) as usize;
        let _ = d.get(2..2 + n).and_then(scsi::Sense::parse);
    }
    let _ = scsi::parse_inquiry(d);
    if let Some((_, body)) = scsi::parse_vpd(d) {
        assert!(scsi::parse_designators(body).len() <= 32);
    }
    let _ = scsi::parse_read_capacity(d);
    for l in scsi::parse_report_luns(d).into_iter().flatten() {
        assert!(l <= 16383);
    }
}
