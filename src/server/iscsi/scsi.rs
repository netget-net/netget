//! SCSI commands of a normal session: dispatch on the CDB, Data-In (kept for retransmission at
//! error recovery level 1 and above), writes with immediate, unsolicited and R2T-solicited
//! data, and the data's recovery after a digest error.
//!
//! Everything here runs with the session locked and only builds PDUs; the caller sends them
//! once the lock is gone.
use super::lun::Lun;
use super::pdu::{op, reject, Pdu, RESERVED_TAG};
use super::session::{
    lock, Completed, Coverage, DataInPdu, PendingWrite, R2tState, ReadData, Session, Status, Task,
    TaskState,
};
use super::{outcome, Conn, MAX_COMMAND_BYTES};
use crate::server::scsi_common::{self as scsi, opcode, status, Sense};
use crate::utils::clock::Instant;
use anyhow::Result;

/// The fields of a SCSI Command a response needs.
#[derive(Clone, Copy, Debug)]
pub(super) struct Cmd {
    pub itt: u32,
    pub lun_field: [u8; 8],
    pub lun: u16,
    pub cmd_sn: u32,
    pub edtl: u32,
}

/// The length of a CDB by its operation code's group (SPC-4 §4.2.5.1), for the control byte.
fn cdb_length(op_code: u8) -> Option<usize> {
    match op_code >> 5 {
        0 => Some(6),
        1 | 2 => Some(10),
        4 => Some(16),
        5 => Some(12),
        _ => None,
    }
}

/// The Data-In PDUs of `total` bytes from `from`: (offset, length, ends a burst). Each is at
/// most the initiator's MaxRecvDataSegmentLength, and no sequence passes MaxBurstLength.
pub(super) fn segments(
    from: usize,
    total: usize,
    max_pdu: usize,
    max_burst: usize,
) -> Vec<(usize, usize, bool)> {
    let max_pdu = max_pdu.max(512);
    let burst = max_burst.max(max_pdu);
    let mut out = Vec::new();
    let mut offset = from;
    while offset < total {
        let burst_end = ((offset / burst) + 1) * burst;
        let end = (offset + max_pdu).min(total).min(burst_end);
        out.push((offset, end - offset, end == burst_end || end == total));
        offset = end;
    }
    out
}

impl Conn<'_> {
    pub(super) async fn scsi_command(&mut self, req: Pdu) -> Result<bool> {
        let Some(cell) = self.session.clone() else {
            return Ok(true);
        };
        let mut out = Vec::new();
        {
            let mut s = lock(&cell);
            self.scsi(&mut s, req, &mut out);
        }
        self.send_all(out).await?;
        Ok(!self.hang_up)
    }

    /// SCSI Response: status, sense, residual and how many Data-In PDUs went before it. Kept
    /// for retransmission at error recovery level >= 1.
    pub(super) fn respond(&mut self, s: &mut Session, cmd: &Cmd, st: Status, out: &mut Vec<Pdu>) {
        let mut r = response_pdu(cmd.itt, &st, 0);
        let stat_sn = self.stat_sn;
        self.stamp(&mut r, Some(s));
        out.push(r);
        self.retain(s, cmd, st, stat_sn, false, None);
    }

    fn check_condition(&mut self, s: &mut Session, cmd: &Cmd, sense: Sense, out: &mut Vec<Pdu>) {
        // Nothing moved, so all of the expected transfer is residual.
        let residual = if cmd.edtl > 0 {
            (0x02, cmd.edtl)
        } else {
            (0, 0)
        };
        self.respond(
            s,
            cmd,
            Status {
                status: status::CHECK_CONDITION,
                sense: Some(sense),
                residual,
                exp_data_sn: 0,
            },
            out,
        );
    }

    fn good(&mut self, s: &mut Session, cmd: &Cmd, out: &mut Vec<Pdu>) {
        let residual = if cmd.edtl > 0 {
            (0x02, cmd.edtl)
        } else {
            (0, 0)
        };
        self.respond(
            s,
            cmd,
            Status {
                status: status::GOOD,
                sense: None,
                residual,
                exp_data_sn: 0,
            },
            out,
        );
    }

    /// Keep a completed task for SNACK and reassignment (error recovery level >= 1 only).
    fn retain(
        &mut self,
        s: &mut Session,
        cmd: &Cmd,
        st: Status,
        stat_sn: u32,
        collapsed: bool,
        data: Option<ReadData>,
    ) {
        if self.erl() == 0 {
            return;
        }
        s.tasks.insert(
            cmd.itt,
            Task {
                itt: cmd.itt,
                conn: self.id,
                lun: cmd.lun,
                lun_field: cmd.lun_field,
                cmd_sn: cmd.cmd_sn,
                state: TaskState::Completed(Completed {
                    status: st,
                    stat_sn,
                    collapsed,
                    data,
                    data_dropped: false,
                    snack_tag: 0,
                    when: Instant::now(),
                }),
                retransmissions: 0,
            },
        );
        s.bound_retention();
    }

    /// Send `data` as Data-In for a command that expected `edtl` bytes, collapsing GOOD status
    /// into the last PDU. At error recovery level >= 1 the last PDU of each burst asks for a
    /// DataACK (the A bit, RFC 7143 §11.7.2) and the data is kept until acknowledged.
    fn data_in(&mut self, s: &mut Session, cmd: &Cmd, mut data: Vec<u8>, out: &mut Vec<Pdu>) {
        let edtl = cmd.edtl as usize;
        let send_len = data.len().min(edtl);
        let residual = if data.len() > edtl {
            (0x04u8, (data.len() - edtl) as u32)
        } else if data.len() < edtl {
            (0x02u8, (edtl - data.len()) as u32)
        } else {
            (0, 0)
        };
        if send_len == 0 {
            self.respond(
                s,
                cmd,
                Status {
                    status: status::GOOD,
                    sense: None,
                    residual,
                    exp_data_sn: 0,
                },
                out,
            );
            return;
        }
        data.truncate(send_len);
        let erl = self.erl();
        let ack_ttt = if erl >= 1 {
            s.issue_ttt()
        } else {
            RESERVED_TAG
        };
        let segs = segments(
            0,
            send_len,
            self.params.peer_max_recv_data_segment as usize,
            self.params.max_burst as usize,
        );
        let mut pdus = Vec::with_capacity(segs.len());
        let mut stat_sn = 0;
        for (data_sn, (offset, len, burst_end)) in segs.iter().copied().enumerate() {
            let last = offset + len == send_len;
            let mut flags = 0u8;
            if burst_end {
                flags |= 0x80;
            }
            if last {
                flags |= 0x01 | residual.0;
            } else if burst_end && erl >= 1 {
                flags |= 0x40;
            }
            let mut r = data_in_pdu(
                cmd,
                flags,
                data_sn as u32,
                offset,
                &data[offset..offset + len],
            );
            if flags & 0x40 != 0 {
                r.set_u32(20, ack_ttt);
            }
            if last {
                r.bhs[3] = status::GOOD;
                r.set_u32(44, residual.1);
                stat_sn = self.stat_sn;
                self.stamp(&mut r, Some(s));
            } else {
                self.window_fields(&mut r, Some(s));
            }
            pdus.push(DataInPdu {
                offset: offset as u32,
                length: len as u32,
                flags,
            });
            out.push(r);
        }
        let count = pdus.len() as u32;
        self.retain(
            s,
            cmd,
            Status {
                status: status::GOOD,
                sense: None,
                residual,
                exp_data_sn: count,
            },
            stat_sn,
            true,
            Some(ReadData {
                bytes: data,
                pdus,
                acked: 0,
                ack_ttt,
            }),
        );
    }

    /// One SCSI command, from its CDB.
    fn scsi(&mut self, s: &mut Session, req: Pdu, out: &mut Vec<Pdu>) {
        let lun_field = req.lun();
        let lun_number = scsi::lun_from_field(&lun_field);
        let cmd = Cmd {
            itt: req.itt(),
            lun_field,
            lun: lun_number.unwrap_or(u16::MAX),
            cmd_sn: req.u32_at(24),
            edtl: req.u32_at(20),
        };
        let cdb: [u8; 16] = req.bhs[32..48].try_into().expect("16 bytes");
        let op_code = cdb[0];
        if s.tasks.get(&cmd.itt).is_some_and(|t| t.is_write()) {
            // A new command under the tag of a write still in progress (RFC 7143 §11.17.1).
            outcome(
                self.ctx,
                self.id,
                "scsi",
                "protocol_refusal",
                &format!("ITT 0x{:08x} is a write still in progress", cmd.itt),
            );
            let r = self.reject_pdu(Some(s), &req, reject::TASK_IN_PROGRESS);
            out.push(r);
            return;
        }
        if !req.ahs.is_empty() {
            // An extended CDB (AHS type 1) or bidirectional read length: neither is supported.
            return self.check_condition(s, &cmd, Sense::INVALID_FIELD_IN_CDB, out);
        }
        if let Some(n) = cdb_length(op_code) {
            if cdb[n - 1] & 0x04 != 0 {
                // NACA: this target has no ACA (NormACA is 0 in its INQUIRY data), so a
                // command asking for one is refused (SPC-4 §4.3.4.2).
                return self.check_condition(s, &cmd, Sense::INVALID_FIELD_IN_CDB, out);
            }
        }
        let target = s.target.clone();
        let lun = lun_number.and_then(|n| target.lun(n)).cloned();
        if op_code == opcode::REPORT_LUNS {
            let alloc = u32::from_be_bytes(cdb[6..10].try_into().expect("4 bytes"));
            if alloc < 16 {
                return self.check_condition(s, &cmd, Sense::INVALID_FIELD_IN_CDB, out);
            }
            let numbers: Vec<u16> = target.luns.iter().map(|l| l.number).collect();
            let mut d = scsi::report_luns(&numbers);
            d.truncate(alloc as usize);
            return self.data_in(s, &cmd, d, out);
        }
        if op_code == opcode::INQUIRY && lun.is_none() {
            // INQUIRY answers for any LUN: qualifier 3 says nothing is there.
            let alloc = u16::from_be_bytes([cdb[3], cdb[4]]) as usize;
            let mut d = scsi::absent_lun_inquiry();
            d.truncate(alloc);
            return self.data_in(s, &cmd, d, out);
        }
        if op_code == opcode::REQUEST_SENSE && lun.is_none() {
            let alloc = cdb[4] as usize;
            let mut d = Sense::LUN_NOT_SUPPORTED.fixed().to_vec();
            d.truncate(alloc);
            return self.data_in(s, &cmd, d, out);
        }
        let Some(lun) = lun else {
            return self.check_condition(s, &cmd, Sense::LUN_NOT_SUPPORTED, out);
        };
        // A unit attention is reported on the next command to the LUN of each nexus, which
        // does not run (SPC-4 §5.14); INQUIRY never reports one, and REQUEST SENSE returns it
        // as its sense data.
        if op_code == opcode::REQUEST_SENSE {
            let alloc = cdb[4] as usize;
            let sense = s.take_unit_attention(lun.number).unwrap_or(Sense::NO_SENSE);
            let mut d = sense.fixed().to_vec();
            d.truncate(alloc);
            return self.data_in(s, &cmd, d, out);
        }
        if op_code != opcode::INQUIRY {
            if let Some(ua) = s.take_unit_attention(lun.number) {
                outcome(
                    self.ctx,
                    self.id,
                    "scsi",
                    "unit_attention",
                    &format!("LUN {}: {}", lun.number, ua.describe()),
                );
                return self.check_condition(s, &cmd, ua, out);
            }
        }
        match op_code {
            opcode::TEST_UNIT_READY
            | opcode::START_STOP_UNIT
            | opcode::PREVENT_ALLOW_MEDIUM_REMOVAL => self.good(s, &cmd, out),
            opcode::INQUIRY => {
                match inquiry(&self.target_name, self.params.max_burst, &lun, &cdb) {
                    Ok(d) => self.data_in(s, &cmd, d, out),
                    Err(e) => self.check_condition(s, &cmd, e, out),
                }
            }
            opcode::READ_CAPACITY_10 => {
                let d = scsi::read_capacity_10(lun.last_lba(), lun.block_size);
                self.data_in(s, &cmd, d.to_vec(), out)
            }
            opcode::SERVICE_ACTION_IN_16 if cdb[1] & 0x1F == scsi::SA_READ_CAPACITY_16 => {
                let alloc = u32::from_be_bytes(cdb[10..14].try_into().expect("4 bytes")) as usize;
                let mut d = scsi::read_capacity_16(lun.last_lba(), lun.block_size).to_vec();
                d.truncate(alloc);
                self.data_in(s, &cmd, d, out)
            }
            opcode::MODE_SENSE_6 | opcode::MODE_SENSE_10 => match mode_sense(&lun, &cdb) {
                Ok(d) => self.data_in(s, &cmd, d, out),
                Err(e) => self.check_condition(s, &cmd, e, out),
            },
            opcode::SYNCHRONIZE_CACHE_10 | opcode::SYNCHRONIZE_CACHE_16 => {
                let (lba, blocks) = if op_code == opcode::SYNCHRONIZE_CACHE_10 {
                    (
                        u32::from_be_bytes(cdb[2..6].try_into().expect("4 bytes")) as u64,
                        u16::from_be_bytes([cdb[7], cdb[8]]) as u64,
                    )
                } else {
                    (
                        u64::from_be_bytes(cdb[2..10].try_into().expect("8 bytes")),
                        u32::from_be_bytes(cdb[10..14].try_into().expect("4 bytes")) as u64,
                    )
                };
                // Zero blocks means "to the end of the medium".
                if !lun.in_range(lba, blocks.max(if lba < lun.blocks { 0 } else { 1 })) {
                    return self.check_condition(s, &cmd, Sense::LBA_OUT_OF_RANGE, out);
                }
                self.good(s, &cmd, out)
            }
            _ => match scsi::decode_read_write(&cdb) {
                Some(rw) if rw.write => self.write(s, &req, &cmd, &lun, rw, out),
                Some(rw) => {
                    if rw.protect != 0 {
                        return self.check_condition(s, &cmd, Sense::INVALID_FIELD_IN_CDB, out);
                    }
                    if !lun.in_range(rw.lba, rw.blocks as u64) {
                        return self.check_condition(s, &cmd, Sense::LBA_OUT_OF_RANGE, out);
                    }
                    let bytes = rw.blocks as u64 * lun.block_size as u64;
                    if bytes > MAX_COMMAND_BYTES {
                        return self.check_condition(s, &cmd, Sense::INVALID_FIELD_IN_CDB, out);
                    }
                    if let Some(e) = lun.failure(rw.lba, rw.blocks as u64, false) {
                        return self.check_condition(s, &cmd, e, out);
                    }
                    let d = lun.read(rw.lba, rw.blocks as u64, &s.overlay);
                    self.data_in(s, &cmd, d, out)
                }
                None => self.check_condition(s, &cmd, Sense::INVALID_OPCODE, out),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        s: &mut Session,
        req: &Pdu,
        cmd: &Cmd,
        lun: &Lun,
        rw: scsi::ReadWrite,
        out: &mut Vec<Pdu>,
    ) {
        if rw.protect != 0 {
            return self.check_condition(s, cmd, Sense::INVALID_FIELD_IN_CDB, out);
        }
        if !lun.in_range(rw.lba, rw.blocks as u64) {
            return self.check_condition(s, cmd, Sense::LBA_OUT_OF_RANGE, out);
        }
        let expected = rw.blocks as u64 * lun.block_size as u64;
        if expected > MAX_COMMAND_BYTES {
            return self.check_condition(s, cmd, Sense::INVALID_FIELD_IN_CDB, out);
        }
        if !lun.writable {
            return self.check_condition(s, cmd, Sense::WRITE_PROTECTED, out);
        }
        if expected == 0 {
            return self.good(s, cmd, out);
        }
        if cmd.edtl as u64 != expected {
            // The command and its iSCSI transfer length disagree about how much data comes;
            // refuse rather than write a guess, as LIO does (INVALID FIELD IN INFORMATION
            // UNIT), naming the difference as the residual. Any data the initiator still sends
            // for the task is discarded as belonging to no task.
            let residual = if (cmd.edtl as u64) < expected {
                (0x04, (expected - cmd.edtl as u64) as u32)
            } else {
                (0x02, (cmd.edtl as u64 - expected) as u32)
            };
            return self.respond(
                s,
                cmd,
                Status {
                    status: status::CHECK_CONDITION,
                    sense: Some(Sense::INVALID_FIELD_IN_IU),
                    residual,
                    exp_data_sn: 0,
                },
                out,
            );
        }
        let expected = expected as u32;
        let first_burst = self.params.first_burst.min(expected);
        if !req.data.is_empty()
            && (!self.params.immediate_data || req.data.len() as u32 > first_burst)
        {
            outcome(
                self.ctx,
                self.id,
                "write",
                "protocol_refusal",
                &format!(
                    "{} bytes of immediate data (ImmediateData {}, FirstBurstLength {})",
                    req.data.len(),
                    self.params.immediate_data,
                    self.params.first_burst
                ),
            );
            let r = self.reject_pdu(Some(s), req, reject::PROTOCOL_ERROR);
            out.push(r);
            self.hang_up = true;
            return;
        }
        let mut w = PendingWrite {
            lba: rw.lba,
            expected,
            buf: Vec::new(),
            have: Coverage::default(),
            unsolicited_open: !self.params.initial_r2t && !req.final_bit(),
            unsolicited_limit: if self.params.initial_r2t {
                req.data.len() as u32
            } else {
                first_burst
            },
            unsolicited_data_sn: 0,
            r2t: None,
            next_r2t_sn: 0,
            aborted: false,
            crc_failed: false,
        };
        let _ = w.put(0, &req.data);
        s.tasks.insert(
            cmd.itt,
            Task {
                itt: cmd.itt,
                conn: self.id,
                lun: lun.number,
                lun_field: cmd.lun_field,
                cmd_sn: cmd.cmd_sn,
                state: TaskState::Write(w),
                retransmissions: 0,
            },
        );
        self.advance_write(s, cmd.itt, out);
    }

    /// After data arrives (or is lost): finish the write, end it if a task management function
    /// or a digest error ended it, or solicit the first range still missing — the next burst,
    /// or (error recovery level >= 1) a recovery R2T for data a digest error lost.
    pub(super) fn advance_write(&mut self, s: &mut Session, itt: u32, out: &mut Vec<Pdu>) {
        enum Next {
            Wait,
            Finish,
            Aborted,
            CrcFailed,
            Solicit(u32, u32),
        }
        let max_burst = self.params.max_burst.max(512);
        let next = match s.tasks.get(&itt) {
            Some(Task {
                state: TaskState::Write(w),
                conn,
                ..
            }) if *conn == self.id => {
                if w.sequence_open() {
                    Next::Wait
                } else if w.aborted {
                    Next::Aborted
                } else if w.crc_failed {
                    Next::CrcFailed
                } else if w.have.complete(w.expected) {
                    Next::Finish
                } else {
                    match w.have.first_gap(w.expected) {
                        Some((at, end)) => Next::Solicit(at, (end - at).min(max_burst)),
                        None => Next::Finish,
                    }
                }
            }
            _ => Next::Wait,
        };
        match next {
            Next::Wait => {}
            Next::Aborted => {
                s.tasks.remove(&itt);
                s.sequence_ended(itt);
            }
            Next::CrcFailed => {
                if let Some(t) = s.tasks.remove(&itt) {
                    let cmd = Cmd {
                        itt,
                        lun_field: t.lun_field,
                        lun: t.lun,
                        cmd_sn: t.cmd_sn,
                        edtl: 0,
                    };
                    self.respond(
                        s,
                        &cmd,
                        Status {
                            status: status::CHECK_CONDITION,
                            sense: Some(Sense::PROTOCOL_SERVICE_CRC_ERROR),
                            residual: (0, 0),
                            exp_data_sn: 0,
                        },
                        out,
                    );
                }
            }
            Next::Finish => self.finish_write(s, itt, out),
            Next::Solicit(offset, length) => {
                let ttt = s.issue_ttt();
                let Some(Task {
                    state: TaskState::Write(w),
                    lun_field,
                    ..
                }) = s.tasks.get_mut(&itt)
                else {
                    return;
                };
                let r = R2tState {
                    ttt,
                    offset,
                    length,
                    r2t_sn: w.next_r2t_sn,
                    next_data_sn: 0,
                    resent: 0,
                };
                w.r2t = Some(r);
                w.next_r2t_sn += 1;
                let lun_field = *lun_field;
                let mut p = r2t_pdu(itt, lun_field, &r);
                // R2T carries StatSN without consuming one.
                p.set_u32(24, self.stat_sn);
                self.window_fields(&mut p, Some(s));
                out.push(p);
            }
        }
    }

    fn finish_write(&mut self, s: &mut Session, itt: u32, out: &mut Vec<Pdu>) {
        let Some(t) = s.tasks.remove(&itt) else {
            return;
        };
        let TaskState::Write(w) = t.state else {
            return;
        };
        let cmd = Cmd {
            itt,
            lun_field: t.lun_field,
            lun: t.lun,
            cmd_sn: t.cmd_sn,
            edtl: 0,
        };
        let target = s.target.clone();
        let Some(lun) = target.lun(t.lun) else {
            return self.check_condition(s, &cmd, Sense::LUN_NOT_SUPPORTED, out);
        };
        let blocks = (w.expected / lun.block_size) as u64;
        let fail = |e: Sense| Status {
            status: status::CHECK_CONDITION,
            sense: Some(e),
            residual: (0, 0),
            exp_data_sn: 0,
        };
        if let Some(e) = lun.failure(w.lba, blocks, true) {
            return self.respond(s, &cmd, fail(e), out);
        }
        match s.overlay.write(lun, w.lba, &w.buf) {
            Ok(()) => self.respond(
                s,
                &cmd,
                Status {
                    status: status::GOOD,
                    sense: None,
                    residual: (0, 0),
                    exp_data_sn: 0,
                },
                out,
            ),
            Err(e) => {
                outcome(
                    self.ctx,
                    self.id,
                    "write",
                    "protocol_refusal",
                    &format!(
                        "the session's write overlay is full ({} bytes)",
                        s.overlay.bytes()
                    ),
                );
                self.respond(s, &cmd, fail(e), out)
            }
        }
    }

    pub(super) async fn data_out(&mut self, req: Pdu) -> Result<bool> {
        let Some(cell) = self.session.clone() else {
            return Ok(true);
        };
        let mut out = Vec::new();
        {
            let mut s = lock(&cell);
            self.take_data(&mut s, &req, &mut out);
        }
        self.send_all(out).await?;
        Ok(true)
    }

    /// One Data-Out PDU. At error recovery level 0 its DataSN, offset and Target Transfer Tag
    /// must be exactly the next expected, and a violation ends the task with CHECK CONDITION.
    /// At level 1 and above, a DataSN or offset ahead of the expected one means earlier PDUs
    /// were lost (RFC 7143 §7.9): what arrives is kept and the missing range is asked for
    /// again with a recovery R2T once the sequence ends. Duplicates and data for an R2T
    /// already answered are dropped.
    fn take_data(&mut self, s: &mut Session, req: &Pdu, out: &mut Vec<Pdu>) {
        let itt = req.itt();
        let ttt = req.u32_at(20);
        let data_sn = req.u32_at(36);
        let offset = req.u32_at(40);
        let len = req.data.len() as u32;
        let last = req.final_bit();
        let erl = self.erl();
        let Some(task) = s.tasks.get_mut(&itt) else {
            // Data for a task already answered (refused before its data) or aborted.
            return;
        };
        if task.conn != self.id {
            outcome(
                self.ctx,
                self.id,
                "data_out",
                "protocol_refusal",
                &format!("Data-Out for ITT 0x{itt:08x} on a connection it is not allegiant to"),
            );
            return;
        }
        let TaskState::Write(w) = &mut task.state else {
            return;
        };
        let unsolicited = ttt == RESERVED_TAG;
        if w.aborted || w.crc_failed {
            // The data of an ended task is taken until its sequence ends.
            if last {
                if unsolicited {
                    w.unsolicited_open = false;
                } else if w.r2t.is_some_and(|r| r.ttt == ttt) {
                    w.r2t = None;
                }
            }
            return self.advance_write(s, itt, out);
        }
        let unexpected = Sense::UNEXPECTED_UNSOLICITED_DATA;
        let phase = Sense::DATA_PHASE_ERROR;
        let end = offset.checked_add(len);
        let mut violation: Option<(&str, Sense)> = None;
        let mut ignore = false;
        if unsolicited {
            if !w.unsolicited_open {
                violation = Some((
                    "unsolicited data after the unsolicited burst ended",
                    unexpected,
                ));
            } else if erl == 0 && data_sn != w.unsolicited_data_sn {
                violation = Some(("DataSN out of order", phase));
            } else if erl >= 1 && crate::server::iscsi::pdu::sn_lt(data_sn, w.unsolicited_data_sn) {
                ignore = true;
            } else if (erl == 0 && offset != w.have.prefix())
                || end.is_none_or(|e| e > w.unsolicited_limit)
            {
                violation = Some((
                    "unsolicited data beyond FirstBurstLength or out of order",
                    unexpected,
                ));
            }
        } else {
            match w.r2t {
                Some(r) if r.ttt == ttt => {
                    if erl == 0 && data_sn != r.next_data_sn {
                        violation = Some(("DataSN out of order", phase));
                    } else if erl >= 1 && crate::server::iscsi::pdu::sn_lt(data_sn, r.next_data_sn)
                    {
                        ignore = true;
                    } else if (erl == 0 && offset != w.have.prefix())
                        || offset < r.offset
                        || end.is_none_or(|e| e > r.offset + r.length)
                    {
                        violation = Some(("data outside the R2T it answers", phase));
                    }
                }
                _ if erl >= 1 => ignore = true,
                _ => violation = Some(("a Target Transfer Tag this target did not issue", phase)),
            }
        }
        if ignore {
            outcome(
                self.ctx,
                self.id,
                "data_out",
                "protocol_refusal",
                &format!(
                    "a duplicate or stale Data-Out (ITT 0x{itt:08x}, DataSN {data_sn}): dropped"
                ),
            );
            return;
        }
        if violation.is_none() && w.put(offset, &req.data).is_err() {
            violation = Some(("a write split into too many pieces", phase));
        }
        if let Some((why, sense)) = violation {
            outcome(
                self.ctx,
                self.id,
                "data_out",
                "protocol_refusal",
                &format!("{why} (ITT 0x{itt:08x}, DataSN {data_sn}, offset {offset})"),
            );
            // The PDU itself was read whole, so the connection is still in step: end only its
            // task, with CHECK CONDITION and nothing written, and keep the session. Any later
            // Data-Out for the task is discarded as belonging to no task.
            //
            // Both louder answers broke libiscsi's iSCSIDataSnInvalid on Linux. Closing the
            // connection (which error recovery level 0 allows) made it reconnect with its next
            // WRITE queued ahead of its Login, then send a WRITE on a fresh connection with no
            // Login at all and wait forever. A Reject for the Data-Out made it reset the
            // connection itself, with the same result. The task's own SCSI Response is what
            // it handles: the WRITE fails and the session goes on.
            let t = s.tasks.remove(&itt).expect("the task");
            s.sequence_ended(itt);
            let cmd = Cmd {
                itt,
                lun_field: t.lun_field,
                lun: t.lun,
                cmd_sn: t.cmd_sn,
                edtl: 0,
            };
            return self.respond(
                s,
                &cmd,
                Status {
                    status: status::CHECK_CONDITION,
                    sense: Some(sense),
                    residual: (0, 0),
                    exp_data_sn: 0,
                },
                out,
            );
        }
        let Some(Task {
            state: TaskState::Write(w),
            ..
        }) = s.tasks.get_mut(&itt)
        else {
            return;
        };
        if unsolicited {
            w.unsolicited_data_sn = data_sn.wrapping_add(1);
            if last {
                w.unsolicited_open = false;
            }
        } else if let Some(r) = w.r2t.as_mut() {
            r.next_data_sn = data_sn.wrapping_add(1);
            let covered = end.is_some_and(|e| e >= r.offset + r.length);
            if last || (erl == 0 && covered) {
                w.r2t = None;
            }
        }
        self.advance_write(s, itt, out)
    }

    /// A Data-Out PDU whose data digest failed: Reject it (RFC 7143 §7.8). At error recovery
    /// level >= 1 it counts as lost and its range is asked for again with a recovery R2T; at
    /// level 0 the task ends with CHECK CONDITION (PROTOCOL SERVICE CRC ERROR) once its
    /// outstanding sequence has ended.
    pub(super) async fn data_out_lost(&mut self, p: Pdu) -> Result<()> {
        let Some(cell) = self.session.clone() else {
            return self.reject(&p, reject::DATA_DIGEST_ERROR).await;
        };
        let itt = p.itt();
        let ttt = p.u32_at(20);
        let data_sn = p.u32_at(36);
        let last = p.final_bit();
        let erl = self.erl();
        let mut out = Vec::new();
        {
            let mut s = lock(&cell);
            let r = self.reject_pdu(Some(&s), &p, reject::DATA_DIGEST_ERROR);
            out.push(r);
            if let Some(Task {
                state: TaskState::Write(w),
                conn,
                ..
            }) = s.tasks.get_mut(&itt)
            {
                if *conn == self.id {
                    if erl == 0 {
                        w.crc_failed = true;
                    }
                    if ttt == RESERVED_TAG {
                        if data_sn == w.unsolicited_data_sn {
                            w.unsolicited_data_sn = data_sn.wrapping_add(1);
                        }
                        if last {
                            w.unsolicited_open = false;
                        }
                    } else if let Some(r) = w.r2t.as_mut().filter(|r| r.ttt == ttt) {
                        if data_sn == r.next_data_sn {
                            r.next_data_sn = data_sn.wrapping_add(1);
                        }
                        if last {
                            w.r2t = None;
                        }
                    }
                    outcome(
                        self.ctx,
                        self.id,
                        "data_out",
                        "protocol_refusal",
                        &format!(
                            "data digest error on Data-Out (ITT 0x{itt:08x}, DataSN {data_sn}): {}",
                            if erl == 0 {
                                "the task ends with PROTOCOL SERVICE CRC ERROR"
                            } else {
                                "its range will be asked for again"
                            }
                        ),
                    );
                    self.advance_write(&mut s, itt, &mut out);
                }
            }
        }
        self.send_all(out).await
    }
}

/// A SCSI Response PDU for a status (StatSN and the window are the caller's to fill).
pub(super) fn response_pdu(itt: u32, st: &Status, snack_tag: u32) -> Pdu {
    let mut r = Pdu::new(op::SCSI_RESPONSE);
    r.set_flags(0x80 | st.residual.0);
    r.bhs[2] = 0; // command completed at target
    r.bhs[3] = st.status;
    r.set_itt(itt);
    r.set_u32(20, snack_tag);
    r.set_u32(36, st.exp_data_sn);
    r.set_u32(44, st.residual.1);
    if let Some(e) = st.sense {
        let fixed = e.fixed();
        r.data = (fixed.len() as u16).to_be_bytes().to_vec();
        r.data.extend(fixed);
    }
    r
}

/// A Data-In PDU's fixed fields (StatSN, the window, TTT and residual are the caller's).
pub(super) fn data_in_pdu(cmd: &Cmd, flags: u8, data_sn: u32, offset: usize, data: &[u8]) -> Pdu {
    let mut r = Pdu::new(op::DATA_IN);
    r.set_flags(flags);
    r.set_lun(cmd.lun_field);
    r.set_itt(cmd.itt);
    r.set_u32(20, RESERVED_TAG);
    r.set_u32(36, data_sn);
    r.set_u32(40, offset as u32);
    r.data = data.to_vec();
    r
}

/// An R2T (StatSN and the window are the caller's to fill).
pub(super) fn r2t_pdu(itt: u32, lun_field: [u8; 8], r: &R2tState) -> Pdu {
    let mut p = Pdu::new(op::R2T);
    p.set_flags(0x80);
    p.set_lun(lun_field);
    p.set_itt(itt);
    p.set_u32(20, r.ttt);
    p.set_u32(36, r.r2t_sn);
    p.set_u32(40, r.offset);
    p.set_u32(44, r.length);
    p
}

fn inquiry(target_name: &str, max_burst: u32, lun: &Lun, cdb: &[u8; 16]) -> Result<Vec<u8>, Sense> {
    let alloc = u16::from_be_bytes([cdb[3], cdb[4]]) as usize;
    let evpd = cdb[1] & 0x01 != 0;
    let page = cdb[2];
    let mut d = if !evpd {
        if page != 0 {
            return Err(Sense::INVALID_FIELD_IN_CDB);
        }
        scsi::standard_inquiry(
            &lun.identity,
            false,
            0x06, // SPC-4
            true,
            &[
                scsi::VERSION_SAM5,
                scsi::VERSION_ISCSI,
                scsi::VERSION_SPC4,
                scsi::VERSION_SBC3,
            ],
        )
    } else {
        match page {
            0x00 => scsi::vpd_supported_pages(&[0x00, 0x80, 0x83, 0xB0, 0xB1]),
            0xB0 => {
                let max = (MAX_COMMAND_BYTES / lun.block_size as u64) as u32;
                let optimal = (max_burst / lun.block_size).max(1);
                scsi::vpd_block_limits(max, optimal)
            }
            0xB1 => scsi::vpd_block_device_characteristics(),
            0x80 => scsi::vpd_serial(&lun.serial),
            0x83 => scsi::vpd_device_identification(&[
                scsi::Designator::Naa6(scsi::naa6_from(&format!(
                    "{}/{}/{}",
                    target_name, lun.number, lun.serial
                ))),
                scsi::Designator::T10 {
                    vendor: lun.identity.vendor.clone(),
                    id: lun.serial.clone(),
                },
                scsi::Designator::IscsiTargetName(target_name.to_string()),
            ]),
            _ => return Err(Sense::INVALID_FIELD_IN_CDB),
        }
    };
    d.truncate(alloc);
    Ok(d)
}

/// MODE SENSE(6) or (10): a block descriptor unless DBD, and the caching (0x08) and control
/// (0x0A) pages. Write protection shows in the device-specific parameter.
fn mode_sense(lun: &Lun, cdb: &[u8; 16]) -> Result<Vec<u8>, Sense> {
    let ten = cdb[0] == opcode::MODE_SENSE_10;
    let dbd = cdb[1] & 0x08 != 0;
    let pc = cdb[2] >> 6;
    let page = cdb[2] & 0x3F;
    let subpage = cdb[3];
    if pc == 3 {
        return Err(Sense::SAVING_NOT_SUPPORTED);
    }
    if subpage != 0 && subpage != 0xFF {
        return Err(Sense::INVALID_FIELD_IN_CDB);
    }
    let changeable = pc == 1;
    let caching = {
        let mut p = vec![0u8; 20];
        p[0] = 0x08;
        p[1] = 0x12;
        p
    };
    let control = {
        let mut p = vec![0u8; 12];
        p[0] = 0x0A;
        p[1] = 0x0A;
        if !changeable {
            // D_SENSE 0 (fixed-format sense), QErr 0; busy timeout unlimited.
            p[8] = 0xFF;
            p[9] = 0xFF;
        }
        p
    };
    let mut pages = Vec::new();
    match page {
        0x08 => pages.extend(&caching),
        0x0A => pages.extend(&control),
        0x3F => {
            pages.extend(&caching);
            pages.extend(&control);
        }
        _ => return Err(Sense::INVALID_FIELD_IN_CDB),
    }
    let mut block = Vec::new();
    if !dbd {
        // A count past 24 bits reads as 0xFFFFFF, sending the host to READ CAPACITY.
        let blocks = lun.blocks.min(0x00FF_FFFF) as u32;
        block.push(0); // density
        block.extend(&blocks.to_be_bytes()[1..]);
        block.push(0);
        block.extend(&lun.block_size.to_be_bytes()[1..]);
    }
    // WP for a read-only LUN; DPOFUA, since DPO and FUA are honoured trivially (nothing is
    // cached, so every write is already where a later read finds it).
    let wp = if lun.writable { 0x10 } else { 0x90 };
    let mut d = Vec::new();
    if ten {
        let len = (6 + block.len() + pages.len()) as u16;
        d.extend(len.to_be_bytes());
        d.extend([0x00, wp, 0x00, 0x00]);
        d.extend((block.len() as u16).to_be_bytes());
        d.extend(&block);
        d.extend(&pages);
        let alloc = u16::from_be_bytes([cdb[7], cdb[8]]) as usize;
        d.truncate(alloc);
    } else {
        let len = (3 + block.len() + pages.len()).min(255) as u8;
        d.extend([len, 0x00, wp, block.len() as u8]);
        d.extend(&block);
        d.extend(&pages);
        d.truncate(cdb[4] as usize);
    }
    Ok(d)
}
