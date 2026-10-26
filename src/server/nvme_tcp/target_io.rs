//! The target's Compare, Verify, Copy and reservation commands. Compare, Verify and Copy are
//! answered by Rust from the described namespace and the controller's write overlay;
//! a reservation command that would change the namespace's table is the model's decision
//! (`nvme_tcp_reservation`), taken after Rust has worked out that the change is valid and what
//! it does, and before it is applied. Every I/O command is checked against the table.
use super::ns::{self, Namespace};
use super::nvme::{self, io, Sqe, Status};
use super::resv::{self, rtype, Op};
use super::{
    actions, err, incoming, ok, outcome, outgoing, shown, Conn, Controller, Done, Incoming,
    PendingKind, MAX_RESERVATION_TABLES, MAX_TRANSFER,
};
use crate::protocol::Event;
use anyhow::Result;
use serde_json::json;

impl Conn<'_> {
    /// RESERVATION CONFLICT when the namespace's reservation keeps this host from a command of
    /// the read group (`write` false) or the write group.
    pub(super) fn reservation_denies(
        &self,
        ctrl: &Controller,
        nsid: u32,
        write: bool,
    ) -> Option<Status> {
        let denied = {
            let tables = self.target.reservations();
            let t = tables.get(&(ctrl.subnqn.clone(), nsid))?;
            (!t.allows(&ctrl.hostid, write)).then(|| t.holder.map_or(0, |(_, ty)| ty))
        }?;
        outcome(
            self.ctx,
            self.id,
            "io",
            "protocol_refusal",
            &format!(
                "a {} command on namespace {nsid} under another host's {} reservation",
                if write { "write" } else { "read" },
                rtype::name(denied)
            ),
        );
        Some(Status::RESERVATION_CONFLICT)
    }

    /// A Compare whose data is all here: the namespace's bytes (description and overlay) are
    /// compared with the host's; any difference is COMPARE FAILURE.
    pub(super) fn compare_now(&self, sqe: &Sqe, data: &[u8]) -> Done {
        let Some(q) = self.queue.as_ref() else {
            return err(Status::COMMAND_SEQUENCE_ERROR);
        };
        let Some(ns) = q.ctrl.desc.as_ref().and_then(|d| d.namespace(sqe.nsid())) else {
            return err(Status::INVALID_NAMESPACE);
        };
        let (slba, blocks) = sqe.lba_range();
        let on_disk = ns.read(slba, blocks, &q.ctrl.overlay());
        q.ctrl.state().stats.reads += 1;
        if on_disk.as_slice() == data {
            ok()
        } else {
            err(Status::COMPARE_FAILURE)
        }
    }

    /// Verify: the range must be readable, and that is all; no data moves.
    pub(super) fn verify(&self, ctrl: &Controller, sqe: &Sqe, data: &[u8], ns: &Namespace) -> Done {
        if !data.is_empty() {
            return err(Status::INVALID_FIELD);
        }
        let (slba, blocks) = sqe.lba_range();
        if !ns.in_range(slba, blocks) {
            return err(Status::LBA_OUT_OF_RANGE);
        }
        if (sqe.cdw(12) >> 26) & 0xF != 0 {
            return err(Status::INVALID_FIELD);
        }
        if let Some(s) = ns.failure(slba, blocks, false) {
            ctrl.state().stats.media_errors += 1;
            return err(s);
        }
        ok()
    }

    /// Copy (descriptor format 0): checked from its command, then its source ranges are asked
    /// for.
    pub(super) async fn copy(&mut self, sqe: &Sqe, data: Vec<u8>, ns: &Namespace) -> Result<Done> {
        let cdw12 = sqe.cdw(12);
        let ranges = (cdw12 & 0xFF) as usize + 1;
        let desfmt = (cdw12 >> 8) & 0xF;
        let prinfor = (cdw12 >> 12) & 0xF;
        let prinfow = (cdw12 >> 26) & 0xF;
        if desfmt != 0 || prinfor != 0 || prinfow != 0 {
            return Ok(err(Status::INVALID_FIELD));
        }
        if ranges > ns::MAX_COPY_RANGES {
            return Ok(err(Status::COMMAND_SIZE_LIMIT_EXCEEDED));
        }
        if !ns.writable {
            return Ok(err(Status::NAMESPACE_WRITE_PROTECTED));
        }
        let need = ranges * nvme::COPY_RANGE_LEN;
        Ok(match incoming(sqe, data, need) {
            Ok(Incoming::InCapsule(d)) => self.copy_now(sqe, &d),
            Ok(Incoming::Solicited) => self.solicit(sqe.clone(), PendingKind::Copy, need).await?,
            Err(s) => err(s),
        })
    }

    /// A Copy whose ranges are all here: every source is read (description and overlay)
    /// before anything is written, so overlapping ranges copy what was there.
    pub(super) fn copy_now(&self, sqe: &Sqe, data: &[u8]) -> Done {
        let Some(q) = self.queue.as_ref() else {
            return err(Status::COMMAND_SEQUENCE_ERROR);
        };
        let ctrl = &q.ctrl;
        let Some(ns) = ctrl.desc.as_ref().and_then(|d| d.namespace(sqe.nsid())) else {
            return err(Status::INVALID_NAMESPACE);
        };
        let ranges = nvme::copy_ranges(data);
        let destination = sqe.u64(40);
        let (mssrl, mcl) = ns.copy_limits();
        let total: u64 = ranges.iter().map(|r| r.1).sum();
        if ranges.iter().any(|r| r.1 > mssrl as u64) || total > mcl as u64 {
            return err(Status::COMMAND_SIZE_LIMIT_EXCEEDED);
        }
        for &(slba, blocks) in &ranges {
            if !ns.in_range(slba, blocks) {
                return err(Status::LBA_OUT_OF_RANGE);
            }
            if let Some(s) = ns.failure(slba, blocks, false) {
                ctrl.state().stats.media_errors += 1;
                return err(s);
            }
        }
        if !ns.in_range(destination, total) {
            return err(Status::LBA_OUT_OF_RANGE);
        }
        if let Some(s) = ns.failure(destination, total, true) {
            ctrl.state().stats.media_errors += 1;
            return err(s);
        }
        let mut bytes = Vec::with_capacity(total as usize * ns.block_size as usize);
        {
            let overlay = ctrl.overlay();
            for &(slba, blocks) in &ranges {
                bytes.extend(ns.read(slba, blocks, &overlay));
            }
        }
        if let Err(s) = ctrl.overlay().write(ns, destination, &bytes) {
            return err(s);
        }
        let mut s = ctrl.state();
        s.stats.writes += 1;
        s.stats.bytes_written += bytes.len() as u64;
        ok()
    }

    /// Reservation Register, Acquire, Release (their data in the capsule or asked for) and
    /// Report.
    pub(super) async fn reservation(&mut self, sqe: &Sqe, data: Vec<u8>) -> Result<Done> {
        let op = sqe.opcode();
        if op == io::RESV_REPORT {
            let Some(q) = self.queue.as_ref() else {
                return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
            };
            let len = (sqe.cdw(10) as u64 + 1) * 4;
            if sqe.cdw(11) & 1 == 0 {
                // Fabrics host identifiers are 128 bits: only the extended structure holds them.
                return Ok(err(Status::HOST_ID_INCONSISTENT));
            }
            if len < resv::REPORT_HEADER as u64 || len > MAX_TRANSFER as u64 {
                return Ok(err(Status::INVALID_FIELD));
            }
            let len = len as usize;
            if let Err(s) = outgoing(sqe, &data, len) {
                return Ok(err(s));
            }
            let table = self
                .target
                .reservations()
                .get(&(q.ctrl.subnqn.clone(), sqe.nsid()))
                .cloned()
                .unwrap_or_default();
            return Ok(Done::Data(table.report(len), 0));
        }
        let need = resv::data_len(op);
        Ok(match incoming(sqe, data, need) {
            Ok(Incoming::InCapsule(d)) => self.reservation_change(sqe, &d).await?,
            Ok(Incoming::Solicited) => {
                self.solicit(sqe.clone(), PendingKind::Reservation, need)
                    .await?
            }
            Err(s) => err(s),
        })
    }

    /// A Register, Acquire or Release whose data is all here. Rust decides whether it is valid
    /// and what it would do; a change is applied only when the model allows it.
    pub(super) async fn reservation_change(&mut self, sqe: &Sqe, data: &[u8]) -> Result<Done> {
        let Some(ctrl) = self.queue.as_ref().map(|q| q.ctrl.clone()) else {
            return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
        };
        let nsid = sqe.nsid();
        let cdw10 = sqe.cdw(10);
        let op = match sqe.opcode() {
            io::RESV_REGISTER => Op::register(cdw10, data),
            io::RESV_ACQUIRE => Op::acquire(cdw10, data),
            _ => Op::release(cdw10, data),
        };
        let op = match op {
            Ok(op) => op,
            Err(s) => return Ok(err(s)),
        };
        let key = (ctrl.subnqn.clone(), nsid);
        let (mut trial, exists) = match self.target.reservations().get(&key) {
            Some(t) => (t.clone(), true),
            None => (resv::Table::default(), false),
        };
        let before = trial.clone();
        let who = shown(&ctrl.hostnqn);
        let change = match trial.apply(ctrl.hostid, &op) {
            Ok(c) => c,
            Err(s) => {
                outcome(
                    self.ctx,
                    self.id,
                    "reservation",
                    "protocol_refusal",
                    &format!("{who} {} on namespace {nsid}: {}", op.name(), s.describe()),
                );
                return Ok(err(s));
            }
        };
        if !change.changes {
            return Ok(ok());
        }
        if !exists && self.target.reservations().len() >= MAX_RESERVATION_TABLES {
            outcome(
                self.ctx,
                self.id,
                "reservation",
                "protocol_refusal",
                &format!("the target holds {MAX_RESERVATION_TABLES} reservation tables"),
            );
            return Ok(err(Status::RESERVATION_CONFLICT));
        }
        let event = Event::new(
            &actions::RESERVATION_EVENT,
            json!({
                "operation": op.name(),
                "nsid": nsid,
                "type": op.rtype().map(rtype::name),
                "host_nqn": ctrl.hostnqn,
                "host_id": nvme::uuid_text(&ctrl.hostid),
                "subsystem_nqn": ctrl.subnqn,
                "effect": change.summary,
                "host_registered": before.registered(&ctrl.hostid),
                "registrants": before.registrants.len(),
                "holder": before.holder.map(|(h, t)| json!({
                    "host_id": nvme::uuid_text(&h),
                    "type": rtype::name(t),
                })),
            }),
        );
        let answer = match self.ask(&event).await {
            Ok(a) => a,
            Err((decision, status, detail)) => {
                let status = if status == Status::CONNECT_CONTROLLER_BUSY {
                    Status::INTERNAL_ERROR.retry()
                } else {
                    status
                };
                outcome(
                    self.ctx,
                    self.id,
                    "reservation",
                    decision,
                    &format!(
                        "{who} {} on namespace {nsid}: {detail}; nothing changed",
                        op.name()
                    ),
                );
                return Ok(err(status));
            }
        };
        match answer["type"].as_str() {
            Some(actions::ALLOW_RESERVATION) => {
                let mut tables = self.target.reservations();
                if !tables.contains_key(&key) && tables.len() >= MAX_RESERVATION_TABLES {
                    return Ok(err(Status::RESERVATION_CONFLICT));
                }
                // Applied to the table as it is now: another host may have changed it while
                // the model was answering, and the rules are applied again to that.
                let result = tables.entry(key).or_default().apply(ctrl.hostid, &op);
                drop(tables);
                match result {
                    Ok(c) => {
                        outcome(
                            self.ctx,
                            self.id,
                            "reservation",
                            "model_answer",
                            &format!("{who} {} on namespace {nsid}: {}", op.name(), c.summary),
                        );
                        Ok(ok())
                    }
                    Err(s) => {
                        outcome(
                            self.ctx,
                            self.id,
                            "reservation",
                            "protocol_refusal",
                            &format!(
                                "{who} {} on namespace {nsid}: {} once allowed (the table changed meanwhile)",
                                op.name(),
                                s.describe()
                            ),
                        );
                        Ok(err(s))
                    }
                }
            }
            Some(actions::REFUSE_RESERVATION) => {
                outcome(
                    self.ctx,
                    self.id,
                    "reservation",
                    "model_reject",
                    &format!(
                        "{who} {} on namespace {nsid} refused; nothing changed",
                        op.name()
                    ),
                );
                Ok(err(Status::RESERVATION_CONFLICT))
            }
            _ => {
                outcome(
                    self.ctx,
                    self.id,
                    "reservation",
                    "fail_closed_invalid_reply",
                    &format!(
                        "{who} {} on namespace {nsid}: an answer that is not a reservation \
                         decision; nothing changed",
                        op.name()
                    ),
                );
                Ok(err(Status::INTERNAL_ERROR))
            }
        }
    }
}
