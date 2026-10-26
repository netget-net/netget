//! SNACK (RFC 7143 §11.16) at error recovery level 1 and above: Data-In and R2T sent again
//! by DataSN/R2TSN, status sent again by StatSN, DataACK freeing kept read data, and R-Data
//! SNACK resending a read's unacknowledged data followed by a SCSI Response carrying the SNACK
//! Tag. Every retransmission is an exact replica but for ExpCmdSN and MaxCmdSN (and an R2T's
//! StatSN), as §11.16 requires.
//!
//! Bounded: a task may be asked for retransmissions [`MAX_RETRANSMISSIONS`] times, and a
//! status PDU as often; past that the SNACK is rejected ("SNACK reject"), so 48 bytes from an
//! initiator cannot buy unbounded retransmission of a 32 MiB read.
use super::pdu::{self, reject, snack, Pdu, SnackRequest, RESERVED_TAG};
use super::scsi::{data_in_pdu, r2t_pdu, response_pdu, segments, Cmd};
use super::session::{lock, DataInPdu, Session, TaskState, MAX_RETRANSMISSIONS};
use super::{outcome, Conn};
use anyhow::Result;

impl Conn<'_> {
    pub(super) async fn snack(&mut self, req: Pdu) -> Result<bool> {
        let Some(cell) = self.session.clone().filter(|_| self.erl() >= 1) else {
            // Error recovery level 0 has no SNACK.
            outcome(
                self.ctx,
                self.id,
                "snack",
                "protocol_refusal",
                "SNACK at error recovery level 0",
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(true);
        };
        let sn = SnackRequest::decode(&req);
        let mut out = Vec::new();
        let refusal = {
            let mut s = lock(&cell);
            let r = match sn.kind {
                snack::DATA_R2T => self.data_snack(&mut s, &sn, &mut out),
                snack::STATUS => self.status_snack(&s, &sn, &mut out),
                snack::DATA_ACK => self.data_ack(&mut s, &sn),
                snack::R_DATA => self.r_data_snack(&mut s, &sn, &mut out),
                _ => Err((reject::PROTOCOL_ERROR, "an unassigned SNACK type")),
            };
            match r {
                Ok(()) => None,
                Err((reason, why)) => {
                    out.clear();
                    let p = self.reject_pdu(Some(&s), &req, reason);
                    out.push(p);
                    Some(why)
                }
            }
        };
        outcome(
            self.ctx,
            self.id,
            "snack",
            if refusal.is_some() {
                "protocol_refusal"
            } else {
                "answered"
            },
            &format!(
                "type {} ITT 0x{:08x} BegRun {} RunLength {}: {}",
                sn.kind,
                sn.itt,
                sn.beg_run,
                sn.run_length,
                refusal.unwrap_or(match out.len() {
                    0 => "acknowledged",
                    _ => "sent again",
                })
            ),
        );
        self.send_all(out).await?;
        Ok(true)
    }

    /// Data/R2T SNACK: a read's Data-In PDUs by DataSN, or a write's outstanding R2T.
    fn data_snack(
        &mut self,
        s: &mut Session,
        sn: &SnackRequest,
        out: &mut Vec<Pdu>,
    ) -> Result<(), (u8, &'static str)> {
        let me = self.id;
        let Some(task) = s.tasks.get_mut(&sn.itt).filter(|t| t.conn == me) else {
            return Err((
                reject::PROTOCOL_ERROR,
                "no task of this connection has that ITT",
            ));
        };
        if task.retransmissions >= MAX_RETRANSMISSIONS {
            return Err((
                reject::SNACK_REJECT,
                "the task's retransmission bound is spent",
            ));
        }
        let cmd = Cmd {
            itt: task.itt,
            lun_field: task.lun_field,
            lun: task.lun,
            cmd_sn: task.cmd_sn,
            edtl: 0,
        };
        match &mut task.state {
            TaskState::Write(w) => {
                let Some(r) = w.r2t.as_mut() else {
                    return Err((reject::PROTOCOL_ERROR, "no R2T is outstanding"));
                };
                // Only the outstanding R2T can be wanted: the data for earlier ones came.
                let wanted = sn.run(w.next_r2t_sn, r.r2t_sn).map_err(|_| {
                    (
                        reject::PROTOCOL_ERROR,
                        "an R2TSN that was not sent or was answered",
                    )
                })?;
                if wanted != (r.r2t_sn..r.r2t_sn + 1) {
                    return Err((
                        reject::PROTOCOL_ERROR,
                        "an R2TSN that was not sent or was answered",
                    ));
                }
                r.resent += 1;
                let copy = *r;
                task.retransmissions += 1;
                let mut p = r2t_pdu(cmd.itt, cmd.lun_field, &copy);
                p.set_u32(24, self.stat_sn);
                self.window_fields(&mut p, Some(s));
                out.push(p);
                Ok(())
            }
            TaskState::Completed(c) => {
                if c.data_dropped {
                    return Err((
                        reject::SNACK_REJECT,
                        "the read's data was let go under the retention bound",
                    ));
                }
                let Some(d) = c.data.as_ref() else {
                    return Err((reject::PROTOCOL_ERROR, "the task sent no Data-In"));
                };
                let wanted = sn.run(d.pdus.len() as u32, d.acked).map_err(|_| {
                    (
                        reject::PROTOCOL_ERROR,
                        "a DataSN that was not sent or was acknowledged",
                    )
                })?;
                let (status, stat_sn, ack_ttt) = (c.status.clone(), c.stat_sn, d.ack_ttt);
                let replicas: Vec<(u32, DataInPdu, Vec<u8>)> = wanted
                    .map(|i| {
                        let p = d.pdus[i as usize];
                        let at = p.offset as usize;
                        (i, p, d.bytes[at..at + p.length as usize].to_vec())
                    })
                    .collect();
                task.retransmissions += 1;
                for (data_sn, p, data) in replicas {
                    let mut r = data_in_pdu(&cmd, p.flags, data_sn, p.offset as usize, &data);
                    if p.flags & 0x40 != 0 {
                        r.set_u32(20, ack_ttt);
                    }
                    if p.flags & 0x01 != 0 {
                        // The status it carried, under the StatSN it first had.
                        r.bhs[3] = status.status;
                        r.set_u32(24, stat_sn);
                        r.set_u32(44, status.residual.1);
                    }
                    self.window_fields(&mut r, Some(s));
                    out.push(r);
                }
                Ok(())
            }
        }
    }

    /// Status SNACK: status PDUs again by StatSN, from those kept and not yet acknowledged.
    fn status_snack(
        &mut self,
        s: &Session,
        sn: &SnackRequest,
        out: &mut Vec<Pdu>,
    ) -> Result<(), (u8, &'static str)> {
        let (acked, sent) = (self.exp_stat_sn, self.stat_sn);
        let (begin, end) = if sn.beg_run == 0 && sn.run_length == 0 {
            (acked, sent)
        } else if sn.run_length == 0 {
            (sn.beg_run, sent)
        } else {
            (sn.beg_run, sn.beg_run.wrapping_add(sn.run_length))
        };
        let count = end.wrapping_sub(begin);
        if !pdu::sn_le(acked, begin)
            || !pdu::sn_le(end, sent)
            || count == 0
            || count as usize > super::MAX_STATUS_RING
        {
            return Err((
                reject::PROTOCOL_ERROR,
                "a StatSN that was not sent or was acknowledged",
            ));
        }
        let mut replicas = Vec::new();
        for i in 0..count {
            let want = begin.wrapping_add(i);
            let Some(kept) = self.ring.iter_mut().find(|k| k.stat_sn == want) else {
                return Err((reject::SNACK_REJECT, "a status no longer kept"));
            };
            if kept.resent >= MAX_RETRANSMISSIONS {
                return Err((
                    reject::SNACK_REJECT,
                    "the status's retransmission bound is spent",
                ));
            }
            kept.resent += 1;
            replicas.push(kept.pdu.clone());
        }
        for mut p in replicas {
            self.window_fields(&mut p, Some(s));
            out.push(p);
        }
        Ok(())
    }

    /// DataACK: the initiator has every Data-In of a read before BegRun; what it acknowledged
    /// need not be kept.
    fn data_ack(&mut self, s: &mut Session, sn: &SnackRequest) -> Result<(), (u8, &'static str)> {
        let me = self.id;
        let found = s.tasks.values_mut().find(|t| {
            t.conn == me
                && matches!(&t.state, TaskState::Completed(c)
                    if c.data.as_ref().is_some_and(|d| d.ack_ttt == sn.tag))
        });
        let Some(task) = found else {
            return Err((
                reject::INVALID_DATA_ACK,
                "no read of this connection has that tag",
            ));
        };
        let TaskState::Completed(c) = &mut task.state else {
            return Err((reject::INVALID_DATA_ACK, "not a read"));
        };
        let d = c.data.as_mut().expect("matched above");
        if sn.beg_run < d.acked || sn.beg_run as usize > d.pdus.len() {
            return Err((reject::INVALID_DATA_ACK, "a DataACK outside what was sent"));
        }
        d.acked = sn.beg_run;
        if d.acked as usize == d.pdus.len() {
            c.data = None;
        }
        Ok(())
    }

    /// R-Data SNACK: every unacknowledged Data-In again (segmented for this connection now),
    /// DataSN from the last DataACK, then a SCSI Response carrying the SNACK Tag under the
    /// status's original StatSN (§11.16.3).
    fn r_data_snack(
        &mut self,
        s: &mut Session,
        sn: &SnackRequest,
        out: &mut Vec<Pdu>,
    ) -> Result<(), (u8, &'static str)> {
        if sn.beg_run != 0 || sn.run_length != 0 {
            return Err((reject::PROTOCOL_ERROR, "an R-Data SNACK names no run"));
        }
        if sn.tag == 0 || sn.tag == RESERVED_TAG {
            return Err((reject::PROTOCOL_ERROR, "an R-Data SNACK needs a SNACK Tag"));
        }
        let me = self.id;
        let Some(task) = s.tasks.get_mut(&sn.itt).filter(|t| t.conn == me) else {
            return Err((
                reject::PROTOCOL_ERROR,
                "no task of this connection has that ITT",
            ));
        };
        if task.retransmissions >= MAX_RETRANSMISSIONS {
            return Err((
                reject::SNACK_REJECT,
                "the task's retransmission bound is spent",
            ));
        }
        let cmd = Cmd {
            itt: task.itt,
            lun_field: task.lun_field,
            lun: task.lun,
            cmd_sn: task.cmd_sn,
            edtl: 0,
        };
        let TaskState::Completed(c) = &mut task.state else {
            return Err((reject::PROTOCOL_ERROR, "the task has not completed"));
        };
        if c.data_dropped {
            return Err((
                reject::SNACK_REJECT,
                "the read's data was let go under the retention bound",
            ));
        }
        let Some(d) = c.data.as_mut() else {
            return Err((reject::PROTOCOL_ERROR, "the task sent no Data-In"));
        };
        task.retransmissions += 1;
        let start = d.acked;
        let from = d
            .pdus
            .get(start as usize)
            .map_or(d.bytes.len(), |p| p.offset as usize);
        let segs = segments(
            from,
            d.bytes.len(),
            self.params.peer_max_recv_data_segment as usize,
            self.params.max_burst as usize,
        );
        let mut built = Vec::with_capacity(segs.len());
        let mut layout = Vec::with_capacity(segs.len());
        for (i, (offset, len, burst_end)) in segs.into_iter().enumerate() {
            let flags = if burst_end { 0x80 } else { 0 };
            built.push(data_in_pdu(
                &cmd,
                flags,
                start + i as u32,
                offset,
                &d.bytes[offset..offset + len],
            ));
            layout.push(DataInPdu {
                offset: offset as u32,
                length: len as u32,
                flags,
            });
        }
        d.pdus.truncate(start as usize);
        d.pdus.extend(layout);
        c.status.exp_data_sn = d.pdus.len() as u32;
        c.snack_tag = sn.tag;
        c.collapsed = false;
        let mut r = response_pdu(cmd.itt, &c.status, sn.tag);
        r.set_u32(24, c.stat_sn);
        let stat_sn = c.stat_sn;
        for mut p in built {
            self.window_fields(&mut p, Some(s));
            out.push(p);
        }
        self.window_fields(&mut r, Some(s));
        // A later Status SNACK for that StatSN gets this, the latest content (§11.16.3).
        if let Some(kept) = self.ring.iter_mut().find(|k| k.stat_sn == stat_sn) {
            kept.pdu = r.clone();
        }
        out.push(r);
        Ok(())
    }
}
