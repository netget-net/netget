//! Task management (RFC 7143 §11.5, §4.2.3): what each function ends, the unit attentions the
//! resets leave on every I_T nexus (SAM-5 §6.3), the model's decision on each reset, and task
//! reassignment for connection recovery (§7.2.2).
//!
//! | Function | Scope | Decided by | Unit attention |
//! |---|---|---|---|
//! | ABORT TASK | one task of this session | Rust | — |
//! | ABORT TASK SET | this session's tasks for the LUN | Rust | — |
//! | CLEAR TASK SET | every session's tasks for the LUN (one task set per LU) | Rust | 2Fh/00h on the other nexuses that lost tasks |
//! | CLEAR ACA | — | Rust: not supported (no ACA) | — |
//! | LOGICAL UNIT RESET | every session's tasks for the LUN | the model | 29h/03h on every nexus |
//! | TARGET WARM RESET | every session's tasks on the target | the model | 29h/00h on every nexus and LUN |
//! | TARGET COLD RESET | every session on the target ends | the model | 29h/01h, owed to each nexus's next session |
//! | TASK REASSIGN | one task, to this connection | Rust (error recovery level 2) | — |
use super::pdu::{op, tmf, Pdu, TmfRequest};
use super::scsi::{data_in_pdu, response_pdu, segments, Cmd};
use super::session::{
    lock, lock_registry, DataInPdu, Fence, Life, Session, SessionCell, TaskState, FENCE_WAIT,
    MAX_RETRANSMISSIONS,
};
use super::{actions, outcome, Conn};
use crate::protocol::Event;
use crate::server::scsi_common::{self as scsi, Sense};
use crate::utils::clock::Instant;
use anyhow::Result;
use serde_json::json;
use std::sync::Arc;

/// What a reset's model decision came to.
enum Decision {
    Allow,
    Refuse(u8, &'static str),
}

impl Conn<'_> {
    pub(super) fn tmf_pdu(&mut self, s: Option<&Session>, itt: u32, response: u8) -> Pdu {
        let mut r = Pdu::new(op::TASK_MGMT_RESPONSE);
        r.set_flags(0x80);
        r.bhs[2] = response;
        r.set_itt(itt);
        self.stamp(&mut r, s);
        r
    }

    pub(super) async fn task_management(&mut self, req: Pdu) -> Result<bool> {
        let t = TmfRequest::decode(&req);
        let Some(cell) = self.session.clone() else {
            // A discovery session has no tasks and no logical units.
            let r = self.tmf_pdu(None, t.itt, tmf::REJECTED);
            self.send(&r).await?;
            return Ok(true);
        };
        let lun = scsi::lun_from_field(&t.lun);
        let mut out = Vec::new();
        let response = match t.function {
            tmf::ABORT_TASK => {
                let r = self.abort_task(&cell, &t);
                let p = self.tmf_pdu(Some(&lock(&cell)), t.itt, r);
                out.push(p);
                r
            }
            tmf::ABORT_TASK_SET | tmf::CLEAR_TASK_SET => self.task_set(&cell, &t, lun, &mut out),
            tmf::CLEAR_ACA => {
                // This target never establishes ACA (NormACA 0, NACA refused), so there is
                // none to clear.
                let r = if self.lun_exists(&cell, lun) {
                    tmf::NOT_SUPPORTED
                } else {
                    tmf::LUN_DOES_NOT_EXIST
                };
                let p = self.tmf_pdu(Some(&lock(&cell)), t.itt, r);
                out.push(p);
                r
            }
            tmf::LOGICAL_UNIT_RESET | tmf::TARGET_WARM_RESET | tmf::TARGET_COLD_RESET => {
                return self.reset(&cell, &t, lun).await;
            }
            tmf::TASK_REASSIGN => self.reassign(&cell, &t, &mut out),
            9..=12 => {
                // QUERY TASK, QUERY TASK SET, I_T NEXUS RESET, QUERY ASYNC EVENT (RFC 7144).
                let p = self.tmf_pdu(Some(&lock(&cell)), t.itt, tmf::NOT_SUPPORTED);
                out.push(p);
                tmf::NOT_SUPPORTED
            }
            _ => {
                let p = self.tmf_pdu(Some(&lock(&cell)), t.itt, tmf::REJECTED);
                out.push(p);
                tmf::REJECTED
            }
        };
        outcome(
            self.ctx,
            self.id,
            "task_management",
            "answered",
            &format!(
                "{} (function {}) -> {} ({response}){}",
                tmf::name(t.function),
                t.function,
                tmf::response_name(response),
                if out.is_empty() {
                    ", held until the transfers it ended finish"
                } else {
                    ""
                }
            ),
        );
        self.send_all(out).await?;
        Ok(true)
    }

    fn lun_exists(&self, cell: &SessionCell, lun: Option<u16>) -> bool {
        lun.is_some_and(|n| lock(cell).target.lun(n).is_some())
    }

    /// ABORT TASK (§11.6.1): a write still waiting for data, or a command delivered and not
    /// yet run, ends; a command named before it arrived is taken as received and aborted; one
    /// already answered does not exist.
    fn abort_task(&mut self, cell: &SessionCell, t: &TmfRequest) -> u8 {
        if t.referenced == t.itt {
            // ABORT TASK must not act on a task management request (§11.5.1).
            return tmf::REJECTED;
        }
        let mut s = lock(cell);
        match s.tasks.get(&t.referenced).map(|task| match &task.state {
            TaskState::Write(_) => true,
            TaskState::Completed(_) => false,
        }) {
            Some(true) => {
                s.tasks.remove(&t.referenced);
                s.sequence_ended(t.referenced);
                tmf::FUNCTION_COMPLETE
            }
            Some(false) => tmf::TASK_DOES_NOT_EXIST,
            None => {
                let before = s.ready.len();
                s.ready.retain(|r| {
                    !(r.pdu.opcode() == op::SCSI_COMMAND && r.pdu.itt() == t.referenced)
                });
                if s.ready.len() < before {
                    return tmf::FUNCTION_COMPLETE;
                }
                let open = s.open_slots();
                if s.window.abort_before_arrival(t.ref_cmd_sn, t.cmd_sn, open) {
                    tmf::FUNCTION_COMPLETE
                } else {
                    tmf::TASK_DOES_NOT_EXIST
                }
            }
        }
    }

    /// ABORT TASK SET (this session's tasks for the LUN) and CLEAR TASK SET (every session's:
    /// the control mode page's TST is 0, one task set per logical unit). Answered at once,
    /// or — when a write it ended still has data on the way — once that data has come (RFC
    /// 7143 §4.2.3.3 a).
    fn task_set(
        &mut self,
        cell: &SessionCell,
        t: &TmfRequest,
        lun: Option<u16>,
        out: &mut Vec<Pdu>,
    ) -> u8 {
        let Some(n) = lun.filter(|n| lock(cell).target.lun(*n).is_some()) else {
            let p = self.tmf_pdu(Some(&lock(cell)), t.itt, tmf::LUN_DOES_NOT_EXIST);
            out.push(p);
            return tmf::LUN_DOES_NOT_EXIST;
        };
        if t.function == tmf::CLEAR_TASK_SET {
            let others = lock_registry(&self.registry).on_target(&self.target_name);
            for other in others.iter().filter(|o| !Arc::ptr_eq(o, cell)) {
                let mut o = lock(other);
                if o.target.lun(n).is_none() {
                    continue;
                }
                let (ended, _) = o.abort_tasks(Some(n));
                if ended > 0 {
                    o.unit_attention(n, Sense::COMMANDS_CLEARED_BY_ANOTHER_INITIATOR);
                }
            }
        }
        let mut s = lock(cell);
        let target = s.target.clone();
        s.window
            .plug(Some(n), t.cmd_sn, |p| super::session::lun_of(&target, p));
        let (_, open) = s.abort_tasks(Some(n));
        self.fence_or_answer(&mut s, t, tmf::FUNCTION_COMPLETE, open, out);
        tmf::FUNCTION_COMPLETE
    }

    /// Answer now, or hold the answer until the writes `open` have no data on the way.
    fn fence_or_answer(
        &mut self,
        s: &mut Session,
        t: &TmfRequest,
        response: u8,
        open: Vec<u32>,
        out: &mut Vec<Pdu>,
    ) {
        if open.is_empty() {
            let p = self.tmf_pdu(Some(s), t.itt, response);
            out.push(p);
        } else {
            s.fences.push(Fence {
                conn: self.id,
                tmf_itt: t.itt,
                response,
                waiting: open,
                deadline: Instant::now() + FENCE_WAIT,
            });
        }
    }

    /// Send the task management responses whose fence has cleared or timed out.
    pub(super) async fn answer_fences(&mut self) -> Result<bool> {
        let Some(cell) = self.session.clone() else {
            return Ok(true);
        };
        let mut out = Vec::new();
        {
            let mut s = lock(&cell);
            for f in s.ripe_fences(self.id, Instant::now()) {
                if !f.waiting.is_empty() {
                    // Out of time: the transfers it waited for are dropped with their tasks.
                    for itt in &f.waiting {
                        s.tasks.remove(itt);
                    }
                }
                let p = self.tmf_pdu(Some(&s), f.tmf_itt, f.response);
                out.push(p);
            }
        }
        self.send_all(out).await?;
        Ok(true)
    }

    /// Ask the model whether a reset may go ahead. Fail closed: no answer, a failed call or
    /// an answer that is not a decision refuses it with "function rejected".
    async fn decide_reset(
        &mut self,
        t: &TmfRequest,
        lun: Option<u16>,
        tasks: usize,
        sessions: usize,
    ) -> Decision {
        let event = Event::new(
            &actions::TASK_MANAGEMENT_EVENT,
            json!({
                "function": tmf::name(t.function),
                "lun": if t.function == tmf::LOGICAL_UNIT_RESET { json!(lun) } else { json!(null) },
                "initiator_name": self.initiator_name,
                "target_name": self.target_name,
                "initiator_address": self.peer.to_string(),
                "authenticated_user": self.authenticated,
                "outstanding_tasks": tasks,
                "sessions_affected": sessions,
            }),
        );
        match self.ask(&event).await {
            Ok(a) => match a["type"].as_str() {
                Some(actions::ALLOW_TASK_MANAGEMENT) => Decision::Allow,
                Some(actions::REFUSE_TASK_MANAGEMENT) => Decision::Refuse(
                    actions::refusal_code(a["response"].as_str().unwrap_or_default()),
                    "model_reject",
                ),
                _ => Decision::Refuse(tmf::REJECTED, "fail_closed_invalid_reply"),
            },
            Err(f) => Decision::Refuse(tmf::REJECTED, f.decision),
        }
    }

    /// LOGICAL UNIT RESET, TARGET WARM RESET, TARGET COLD RESET: the model decides; allowed,
    /// each ends the tasks it covers in every session logged in to the target and leaves the
    /// unit attention SAM-5 names for it on every nexus. A cold reset is a power-on event
    /// (RFC 7143 §11.5.1): it answers, then ends every session of the target, and the power-on
    /// unit attention waits for each nexus's next login.
    async fn reset(
        &mut self,
        cell: &SessionCell,
        t: &TmfRequest,
        lun: Option<u16>,
    ) -> Result<bool> {
        let lu = t.function == tmf::LOGICAL_UNIT_RESET;
        if lu && !self.lun_exists(cell, lun) {
            let p = self.tmf_pdu(Some(&lock(cell)), t.itt, tmf::LUN_DOES_NOT_EXIST);
            self.send(&p).await?;
            return Ok(true);
        }
        let scope = if lu { lun } else { None };
        let sessions = lock_registry(&self.registry).on_target(&self.target_name);
        let tasks: usize = sessions
            .iter()
            .map(|s| {
                let s = lock(s);
                s.tasks
                    .values()
                    .filter(|t| t.is_write() && scope.is_none_or(|l| l == t.lun))
                    .count()
                    + s.ready.len()
            })
            .sum();
        let decision = self.decide_reset(t, lun, tasks, sessions.len()).await;
        if let Decision::Refuse(code, decision) = decision {
            outcome(
                self.ctx,
                self.id,
                "task_management",
                decision,
                &format!(
                    "{} refused -> {} ({code})",
                    tmf::name(t.function),
                    tmf::response_name(code)
                ),
            );
            let p = self.tmf_pdu(Some(&lock(cell)), t.itt, code);
            self.send(&p).await?;
            return Ok(true);
        }
        outcome(
            self.ctx,
            self.id,
            "task_management",
            "model_answer",
            &format!(
                "{} allowed: {tasks} outstanding task(s) in {} session(s)",
                tmf::name(t.function),
                sessions.len()
            ),
        );
        // The sessions as they are now (one may have logged in during the model's call).
        let sessions = lock_registry(&self.registry).on_target(&self.target_name);
        let mut out = Vec::new();
        if t.function == tmf::TARGET_COLD_RESET {
            let mut owed = Vec::new();
            for other in &sessions {
                let mut o = lock(other);
                o.abort_tasks(None);
                o.ended = true;
                for c in &o.conns {
                    if c.id != self.id {
                        c.close.cancel();
                    }
                }
                owed.push((o.tsih, o.nexus.clone()));
            }
            {
                let mut r = lock_registry(&self.registry);
                let now = Instant::now();
                for (tsih, nexus) in owed {
                    r.remove(tsih);
                    r.owe(nexus, Sense::POWER_ON_OCCURRED, now);
                }
            }
            // The response goes out on a session that no longer exists: numbers as they were.
            let p = self.tmf_pdu(Some(&lock(cell)), t.itt, tmf::FUNCTION_COMPLETE);
            self.send(&p).await?;
            outcome(
                self.ctx,
                self.id,
                "task_management",
                "answered",
                "target_cold_reset (function 7) -> function_complete (0); every session of the target ends",
            );
            return Ok(false);
        }
        let sense = if lu {
            Sense::BUS_DEVICE_RESET_OCCURRED
        } else {
            Sense::RESET_OCCURRED
        };
        for other in sessions.iter().filter(|o| !Arc::ptr_eq(o, cell)) {
            let mut o = lock(other);
            match scope {
                Some(n) if o.target.lun(n).is_some() => {
                    o.abort_tasks(Some(n));
                    o.unit_attention(n, sense);
                }
                Some(_) => {}
                None => {
                    o.abort_tasks(None);
                    o.unit_attention_all(sense);
                }
            }
        }
        {
            let mut s = lock(cell);
            let target = s.target.clone();
            match scope {
                Some(n) => {
                    s.window
                        .plug(Some(n), t.cmd_sn, |p| super::session::lun_of(&target, p));
                }
                // A target reset plugs the CmdSN space below it (§4.2.3.3 b).
                None => s.window.plug_all(t.cmd_sn),
            }
            let (_, open) = s.abort_tasks(scope);
            match scope {
                Some(n) => s.unit_attention(n, sense),
                None => s.unit_attention_all(sense),
            }
            self.fence_or_answer(&mut s, t, tmf::FUNCTION_COMPLETE, open, &mut out);
        }
        outcome(
            self.ctx,
            self.id,
            "task_management",
            "answered",
            &format!(
                "{} (function {}) -> function_complete (0); unit attention {}",
                tmf::name(t.function),
                t.function,
                sense.describe()
            ),
        );
        self.send_all(out).await?;
        Ok(true)
    }

    /// TASK REASSIGN (§7.2.2): at error recovery level 2, a task whose connection was logged
    /// out for recovery (or reinstated) continues on this one — the response first, then the
    /// read data from the initiator's ExpDataSN and the status again, or an R2T for whatever
    /// a write still lacks.
    fn reassign(&mut self, cell: &SessionCell, t: &TmfRequest, out: &mut Vec<Pdu>) -> u8 {
        let mut s = lock(cell);
        let respond = |me: &mut Self, s: &Session, out: &mut Vec<Pdu>, r: u8| {
            let p = me.tmf_pdu(Some(s), t.itt, r);
            out.push(p);
            r
        };
        if s.erl() < 2 {
            return respond(self, &s, out, tmf::REASSIGNMENT_NOT_SUPPORTED);
        }
        let Some(task) = s.tasks.get(&t.referenced) else {
            return respond(self, &s, out, tmf::TASK_DOES_NOT_EXIST);
        };
        let life = s.conn(task.conn).map(|c| c.life);
        let over_bound = task.retransmissions >= MAX_RETRANSMISSIONS;
        match life {
            None => return respond(self, &s, out, tmf::TASK_DOES_NOT_EXIST),
            // Still allegiant to a connection that is up, or one that failed without the
            // recovery logout §7.2.2 requires first.
            Some(Life::Live) | Some(Life::Failed(_)) => {
                return respond(self, &s, out, tmf::TASK_STILL_ALLEGIANT)
            }
            Some(Life::Recovering(_)) if over_bound => {
                return respond(self, &s, out, tmf::REJECTED)
            }
            Some(Life::Recovering(_)) => {}
        }
        // The response goes first; the reassignment takes effect after it (§11.5.1).
        respond(self, &s, out, tmf::FUNCTION_COMPLETE);
        let itt = t.referenced;
        let task = s.tasks.get_mut(&itt).expect("the task");
        task.conn = self.id;
        task.retransmissions += 1;
        match &mut task.state {
            TaskState::Write(w) => {
                // Whatever was in flight on the old connection is gone; ask again for what
                // has not arrived.
                w.r2t = None;
                w.unsolicited_open = false;
                self.advance_write(&mut s, itt, out);
            }
            TaskState::Completed(_) => self.resume_read(&mut s, itt, t.exp_data_sn, out),
        }
        outcome(
            self.ctx,
            self.id,
            "task_management",
            "reassigned",
            &format!("ITT 0x{itt:08x} continues on connection {}", self.cid),
        );
        tmf::FUNCTION_COMPLETE
    }

    /// A completed task continued on this connection: its unacknowledged read data from
    /// `exp_data_sn` (0 keeps the acknowledgement as it was), segmented for this connection,
    /// then its status again as a SCSI Response with a new StatSN.
    pub(super) fn resume_read(
        &mut self,
        s: &mut Session,
        itt: u32,
        exp_data_sn: u32,
        out: &mut Vec<Pdu>,
    ) {
        let Some(task) = s.tasks.get(&itt) else {
            return;
        };
        let TaskState::Completed(c) = &task.state else {
            return;
        };
        let cmd = Cmd {
            itt,
            lun_field: task.lun_field,
            lun: task.lun,
            cmd_sn: task.cmd_sn,
            edtl: 0,
        };
        let mut status = c.status.clone();
        let mut pdus = Vec::new();
        // The PDUs as now segmented, from the first one sent again.
        let mut layout: Option<(u32, Vec<DataInPdu>)> = None;
        if let Some(d) = &c.data {
            let start = if exp_data_sn != 0
                && exp_data_sn >= d.acked
                && (exp_data_sn as usize) <= d.pdus.len()
            {
                exp_data_sn
            } else {
                d.acked
            };
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
            let mut new = Vec::with_capacity(segs.len());
            for (i, (offset, len, burst_end)) in segs.into_iter().enumerate() {
                let flags = if burst_end { 0x80 } else { 0 };
                let mut p = data_in_pdu(
                    &cmd,
                    flags,
                    start + i as u32,
                    offset,
                    &d.bytes[offset..offset + len],
                );
                self.window_fields(&mut p, Some(s));
                pdus.push(p);
                new.push(DataInPdu {
                    offset: offset as u32,
                    length: len as u32,
                    flags,
                });
            }
            status.exp_data_sn = start + pdus.len() as u32;
            layout = Some((start, new));
        }
        out.extend(pdus);
        let mut r = response_pdu(itt, &status, 0);
        let stat_sn = self.stat_sn;
        self.stamp(&mut r, Some(s));
        out.push(r);
        if let Some(TaskState::Completed(c)) = s.tasks.get_mut(&itt).map(|t| &mut t.state) {
            c.stat_sn = stat_sn;
            c.collapsed = false;
            c.status = status;
            if let (Some(d), Some((start, new))) = (c.data.as_mut(), layout) {
                d.pdus.truncate(start as usize);
                d.pdus.extend(new);
                d.acked = start;
            }
        }
    }
}
