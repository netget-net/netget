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
//!
//! The decoded PDUs also drive what a session does with them, through its pure parts: the
//! CmdSN window (`session::CommandWindow`, fed every command-bearing PDU in order, with the
//! task management functions it carries plugging it), a write's received ranges
//! (`session::Coverage`, fed every Data-Out's offset and length) and the SNACK run arithmetic
//! (`pdu::SnackRequest::run`). The promises checked are the ones the target relies on: the
//! window never holds more than COMMAND_WINDOW commands and never runs one twice, a write is
//! never split into more than MAX_FRAGMENTS ranges and its ranges stay sorted and disjoint,
//! and a SNACK run never names a PDU that was not sent or was acknowledged.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::connection::ConnectionId;
use netget::server::iscsi::{chap, pdu, session, text, COMMAND_WINDOW};
use netget::server::scsi_common as scsi;

/// What one session's pure parts make of a train of PDUs.
struct Sessionish {
    window: session::CommandWindow,
    run: std::collections::HashSet<u32>,
    coverage: session::Coverage,
}

impl Sessionish {
    fn new() -> Self {
        Self {
            window: session::CommandWindow::new(1),
            run: Default::default(),
            coverage: Default::default(),
        }
    }

    fn take(&mut self, p: &pdu::Pdu) {
        let conn = ConnectionId::new(u32::from(p.bhs[1] & 1));
        match p.opcode() {
            pdu::op::SCSI_COMMAND
            | pdu::op::NOP_OUT
            | pdu::op::TEXT_REQUEST
            | pdu::op::LOGOUT_REQUEST
            | pdu::op::TASK_MGMT_REQUEST => {
                let lun = scsi::lun_from_field(&p.lun());
                let before = self.window.exp_cmd_sn;
                let a = self.window.admit(conn, p, COMMAND_WINDOW, lun);
                let mut ran = Vec::new();
                if a == session::Admission::Run && !p.immediate() {
                    ran.push(p.u32_at(24));
                    ran.extend(
                        self.window
                            .release(|q| scsi::lun_from_field(&q.lun()))
                            .iter()
                            .map(|(_, q)| q.u32_at(24)),
                    );
                }
                for c in ran {
                    // A CmdSN runs once (within one trip round the 32-bit space).
                    assert!(self.run.insert(c), "CmdSN {c} ran twice");
                }
                assert!(self.window.held() <= COMMAND_WINDOW as usize);
                assert!(pdu::sn_le(before, self.window.exp_cmd_sn));
                if p.opcode() == pdu::op::TASK_MGMT_REQUEST {
                    let t = pdu::TmfRequest::decode(p);
                    match t.function {
                        pdu::tmf::ABORT_TASK => {
                            self.window.abort_before_arrival(
                                t.ref_cmd_sn,
                                t.cmd_sn,
                                COMMAND_WINDOW,
                            );
                        }
                        pdu::tmf::TARGET_WARM_RESET | pdu::tmf::TARGET_COLD_RESET => {
                            self.window.plug_all(t.cmd_sn)
                        }
                        _ => {
                            self.window
                                .plug(lun, t.cmd_sn, |q| scsi::lun_from_field(&q.lun()));
                        }
                    }
                    assert!(self.window.held() <= COMMAND_WINDOW as usize);
                }
            }
            pdu::op::DATA_OUT => {
                let offset = p.u32_at(40);
                if let Some(end) = offset.checked_add(p.data.len() as u32) {
                    let before = self.coverage.clone();
                    if self.coverage.add(offset, end).is_err() {
                        assert_eq!(self.coverage, before, "a refused range changes nothing");
                    }
                    let r = self.coverage.ranges();
                    assert!(r.len() <= session::MAX_FRAGMENTS);
                    assert!(r.windows(2).all(|w| w[0].1 < w[1].0), "sorted, disjoint");
                    assert!(r.iter().all(|(s, e)| s < e));
                    let total = r.last().map_or(0, |(_, e)| *e);
                    if let Some((s, e)) = self.coverage.first_gap(total) {
                        assert!(s < e && e <= total && !self.coverage.overlaps(s, e));
                    } else {
                        assert!(self.coverage.complete(total));
                    }
                }
            }
            pdu::op::SNACK_REQUEST => {
                let s = pdu::SnackRequest::decode(p);
                for (sent, acked) in [(0u32, 0u32), (4, 0), (4, 2), (u32::MAX, 7)] {
                    if let Ok(r) = s.run(sent, acked) {
                        assert!(r.start >= acked.min(sent) && r.end <= sent && r.start <= r.end);
                    }
                }
            }
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut sessionish = Sessionish::new();
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
                    if !digests.header {
                        sessionish.take(&p);
                    }
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
