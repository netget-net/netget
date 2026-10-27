//! The full feature phase of one connection: reading PDUs (and waking for work another
//! connection of the session left it), CmdSN admission and in-order execution, NOP, Text,
//! Logout and Reject.
use super::pdu::{logout, op, reject, Pdu, ReadError, RESERVED_TAG};
use super::session::{self, lock, lock_registry, Admission, Gone, Life, Session};
use super::{actions, outcome, text, Conn, SessionType, TextContinuation, COMMAND_WINDOW};
use super::{LOGOUT_LINGER, PDU_DEADLINE, PORTAL_GROUP_TAG};
use crate::server::scsi_common::Sense;
use crate::utils::clock::Instant;
use anyhow::{bail, Result};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Wait until `at`, or forever.
async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

impl Conn<'_> {
    pub(super) async fn full_feature(&mut self) -> Result<()> {
        loop {
            // Work that is this connection's to do first: commands now in order, and task
            // management responses whose fence has cleared.
            if !self.run_ready().await? || !self.answer_fences().await? {
                return self.finish().await;
            }
            let deadline = self
                .session
                .as_ref()
                .and_then(|s| lock(s).fence_deadline(self.id));
            let max = self.params.our_max_recv_data_segment as usize;
            let digests = self.digests;
            let read = tokio::select! {
                biased;
                _ = self.close.cancelled() => {
                    outcome(self.ctx, self.id, "connection", "closed", "its session ended it (logout, reset or reinstatement)");
                    let _ = self.stream.shutdown().await;
                    return Ok(());
                }
                _ = self.wake.notified() => continue,
                _ = sleep_until(deadline) => continue,
                r = self.reader.next(&mut self.stream, digests, max, PDU_DEADLINE) => r,
            };
            let req = match read {
                Ok(p) => p,
                Err(ReadError::Closed) => return Ok(()),
                Err(ReadError::Oversize { declared, limit }) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        &format!("a data segment of {declared} bytes over MaxRecvDataSegmentLength {limit}"),
                    );
                    let _ = self.stream.shutdown().await;
                    return Ok(());
                }
                Err(ReadError::DataDigest(p)) => {
                    // The PDU was read whole, so the stream is in step: reject it alone (and
                    // recover a write's data, RFC 7143 §7.8). A command rejected this way is
                    // not taken as received: the initiator sends it again.
                    self.received(&p).await;
                    self.acknowledge(p.u32_at(28));
                    if p.opcode() == op::DATA_OUT {
                        self.data_out_lost(*p).await?;
                    } else {
                        outcome(
                            self.ctx,
                            self.id,
                            "pdu",
                            "protocol_refusal",
                            &format!("data digest mismatch on a {}", op::name(p.opcode())),
                        );
                        self.reject(&p, reject::DATA_DIGEST_ERROR).await?;
                    }
                    continue;
                }
                Err(ReadError::HeaderDigest) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        "header digest mismatch; the stream cannot be trusted",
                    );
                    let _ = self.stream.shutdown().await;
                    return Ok(());
                }
                Err(e) => bail!("{e}"),
            };
            self.received(&req).await;
            self.acknowledge(req.u32_at(28));
            if !self.dispatch(req).await? {
                return self.finish().await;
            }
        }
    }

    /// End the connection: after a Logout Response the initiator closes first (RFC 7143
    /// §11.15); closing first races it, and libiscsi reads the hang-up as a dropped connection
    /// and logs in again. Wait for its close, bounded.
    async fn finish(&mut self) -> Result<()> {
        if self.logged_out {
            let mut sink = [0u8; 512];
            let _ = tokio::time::timeout(LOGOUT_LINGER, async {
                while matches!(self.stream.read(&mut sink).await, Ok(n) if n > 0) {}
            })
            .await;
        }
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    /// Run the commands at the front of the session's in-order queue that are this
    /// connection's, one at a time, while no other connection is running one.
    async fn run_ready(&mut self) -> Result<bool> {
        let Some(cell) = self.session.clone() else {
            return Ok(true);
        };
        loop {
            let next = lock(&cell).next_ready(self.id);
            let Some(p) = next else {
                return Ok(true);
            };
            let r = self.execute(p).await;
            lock(&cell).done();
            if !r? {
                return Ok(false);
            }
        }
    }

    /// Returns false to end the connection.
    async fn dispatch(&mut self, req: Pdu) -> Result<bool> {
        match req.opcode() {
            op::NOP_OUT if req.itt() == RESERVED_TAG => {
                // A ping answer or a bare ExpStatSN update: nothing to say.
                Ok(true)
            }
            op::SCSI_COMMAND if self.session_type == SessionType::Discovery => {
                self.reject(&req, reject::COMMAND_NOT_SUPPORTED).await?;
                Ok(true)
            }
            op::NOP_OUT
            | op::SCSI_COMMAND
            | op::TASK_MGMT_REQUEST
            | op::TEXT_REQUEST
            | op::LOGOUT_REQUEST => self.command(req).await,
            op::DATA_OUT => self.data_out(req).await,
            op::SNACK_REQUEST => self.snack(req).await,
            other => {
                outcome(
                    self.ctx,
                    self.id,
                    "pdu",
                    "protocol_refusal",
                    &format!("opcode 0x{other:02x} ({})", op::name(other)),
                );
                self.reject(&req, reject::COMMAND_NOT_SUPPORTED).await?;
                Ok(true)
            }
        }
    }

    /// A command-bearing PDU: an immediate one runs now; a non-immediate one runs in CmdSN
    /// order across the session's connections (RFC 7143 §4.2.2.1) — at once when it is next,
    /// held when it is ahead of a gap, dropped when it is outside the window.
    async fn command(&mut self, req: Pdu) -> Result<bool> {
        let admission = match self.session.clone() {
            Some(cell) => {
                let a = {
                    let mut s = lock(&cell);
                    let open = s.open_slots();
                    let lun = session::lun_of(&s.target, &req);
                    let a = s.window.admit(self.id, &req, open, lun);
                    if a == Admission::Run && !req.immediate() {
                        // In order: it joins the session's queue, behind any command another
                        // connection has not run yet.
                        s.deliver(self.id, req);
                        return Ok(true);
                    }
                    a
                };
                if a == Admission::Run {
                    return self.execute(req).await;
                }
                a
            }
            None => {
                let a = self.window.admit(self.id, &req, COMMAND_WINDOW, None);
                if a == Admission::Run {
                    if !self.execute(req).await? {
                        return Ok(false);
                    }
                    for (_, p) in self.window.release(|_| None) {
                        if !self.execute(p).await? {
                            return Ok(false);
                        }
                    }
                    return Ok(true);
                }
                a
            }
        };
        let exp = match &self.session {
            Some(s) => lock(s).window.exp_cmd_sn,
            None => self.window.exp_cmd_sn,
        };
        match admission {
            Admission::Held => outcome(
                self.ctx,
                self.id,
                "sequence",
                "held",
                &format!(
                    "{} with CmdSN {} held until ExpCmdSN {exp} arrives",
                    op::name(req.opcode()),
                    req.u32_at(24)
                ),
            ),
            Admission::Dropped(why) => outcome(
                self.ctx,
                self.id,
                "sequence",
                "protocol_refusal",
                &format!(
                    "{} with CmdSN {} while ExpCmdSN is {exp}: dropped ({why})",
                    op::name(req.opcode()),
                    req.u32_at(24),
                ),
            ),
            Admission::Run => {}
        }
        Ok(true)
    }

    /// Run one admitted command. Returns false to end the connection.
    async fn execute(&mut self, req: Pdu) -> Result<bool> {
        match req.opcode() {
            op::NOP_OUT => {
                let mut r = Pdu::new(op::NOP_IN);
                r.set_flags(0x80);
                r.set_lun(req.lun());
                r.set_itt(req.itt());
                r.set_u32(20, RESERVED_TAG);
                r.data = req.data;
                self.stamp_now(&mut r);
                self.send(&r).await?;
                Ok(true)
            }
            op::SCSI_COMMAND => self.scsi_command(req).await,
            op::TASK_MGMT_REQUEST => self.task_management(req).await,
            op::TEXT_REQUEST => self.text_request(req).await,
            op::LOGOUT_REQUEST => self.logout(req).await,
            _ => Ok(true),
        }
    }

    /// Stamp a status PDU with the numbers as they stand now.
    pub(super) fn stamp_now(&mut self, p: &mut Pdu) {
        match self.session.clone() {
            Some(cell) => {
                let s = lock(&cell);
                self.stamp(p, Some(&s));
            }
            None => self.stamp(p, None),
        }
    }

    /// A Reject naming `req` (its header is the data).
    pub(super) fn reject_pdu(&mut self, s: Option<&Session>, req: &Pdu, reason: u8) -> Pdu {
        let mut r = Pdu::new(op::REJECT);
        r.set_flags(0x80);
        r.bhs[2] = reason;
        r.set_itt(RESERVED_TAG);
        r.data = req.bhs.to_vec();
        self.stamp(&mut r, s);
        r
    }

    pub(super) async fn reject(&mut self, req: &Pdu, reason: u8) -> Result<()> {
        let r = match self.session.clone() {
            Some(cell) => {
                let s = lock(&cell);
                self.reject_pdu(Some(&s), req, reason)
            }
            None => self.reject_pdu(None, req, reason),
        };
        self.send(&r).await
    }

    // ------------------------------------------------------------ logout

    /// Logout (RFC 7143 §11.14): close the session, close a connection (this one or another
    /// of the session, by CID), or — at error recovery level 2 — remove a connection for
    /// recovery, which leaves its tasks to be reassigned.
    async fn logout(&mut self, req: Pdu) -> Result<bool> {
        let reason = req.flags() & 0x7F;
        let cid = req.u16_at(20);
        let now = Instant::now();
        let mut response = logout::CLOSED;
        let mut close_me = reason != logout::REMOVE_FOR_RECOVERY;
        let mut times = (
            self.params.default_time2wait,
            self.params.default_time2retain,
        );
        let mut end_session = None;
        if let Some(cell) = self.session.clone() {
            let mut s = lock(&cell);
            let erl = s.erl();
            match reason {
                logout::CLOSE_SESSION => {
                    s.ended = true;
                    s.tasks.clear();
                    for c in &s.conns {
                        if c.id != self.id {
                            c.close.cancel();
                        }
                    }
                    end_session = Some(s.tsih);
                }
                logout::CLOSE_CONNECTION | logout::REMOVE_FOR_RECOVERY => {
                    let recovery = reason == logout::REMOVE_FOR_RECOVERY;
                    close_me = cid == self.cid;
                    // The live connection of that CID, or else one that failed or is being
                    // recovered (a reinstated CID can have both).
                    let slot = s
                        .conns
                        .iter()
                        .find(|c| c.cid == cid && c.life == Life::Live)
                        .or_else(|| s.conns.iter().find(|c| c.cid == cid))
                        .map(|c| (c.id, c.close.clone(), c.life));
                    if recovery && erl < 2 {
                        response = logout::RECOVERY_NOT_SUPPORTED;
                        close_me = false;
                    } else if let Some((id, close, life)) = slot {
                        if id != self.id && life == Life::Live {
                            close.cancel();
                        }
                        let how = if recovery {
                            Gone::Recovering(now)
                        } else {
                            Gone::Closed
                        };
                        let others = s.live_connections() > usize::from(life == Life::Live);
                        for l in s.connection_gone(id, how) {
                            if others {
                                s.unit_attention(l, Sense::COMMANDS_CLEARED_BY_ISCSI_EVENT);
                            }
                        }
                        if recovery {
                            // What the initiator has left: Time2Wait before reassigning, then
                            // at most the retention this target keeps.
                            let keep = session::MAX_TASK_RETENTION.as_secs() as u32;
                            let wait = s.params.default_time2wait.min(keep);
                            times = (wait, s.params.default_time2retain.min(keep - wait));
                        }
                        if s.idle() {
                            s.ended = true;
                            end_session = Some(s.tsih);
                        }
                    } else {
                        response = logout::CID_NOT_FOUND;
                        close_me = false;
                    }
                }
                _ => {
                    response = logout::CLEANUP_FAILED;
                    close_me = false;
                }
            }
        } else if reason == logout::REMOVE_FOR_RECOVERY {
            response = logout::RECOVERY_NOT_SUPPORTED;
            close_me = false;
        }
        if let (Some(tsih), Some(cell)) = (end_session, self.session.clone()) {
            let mut r = lock_registry(&self.registry);
            if r.get(tsih).is_some_and(|cur| Arc::ptr_eq(&cur, &cell)) {
                r.remove(tsih);
            }
        }
        let mut r = Pdu::new(op::LOGOUT_RESPONSE);
        r.set_flags(0x80);
        r.bhs[2] = response;
        r.set_itt(req.itt());
        r.set_u16(40, times.0.min(u16::MAX as u32) as u16);
        r.set_u16(42, times.1.min(u16::MAX as u32) as u16);
        self.stamp_now(&mut r);
        self.send(&r).await?;
        outcome(
            self.ctx,
            self.id,
            "logout",
            "logged_out",
            &format!("reason {reason} CID {cid} -> response {response}"),
        );
        self.logged_out = close_me;
        Ok(!close_me)
    }

    // ------------------------------------------------------------ text

    async fn text_request(&mut self, req: Pdu) -> Result<bool> {
        let itt = req.itt();
        let ttt = req.u32_at(20);
        let cont = req.flags() & 0x40 != 0;
        // The initiator asking for the rest of a long answer.
        if ttt != RESERVED_TAG {
            match self.text_out.take() {
                Some(c) if c.itt == itt && c.ttt == ttt => {
                    self.send_text(itt, c.rest).await?;
                }
                _ => self.reject(&req, reject::INVALID_PDU_FIELD).await?,
            }
            return Ok(true);
        }
        self.text_out = None;
        let mut acc = match self.text_in.take() {
            Some((i, buf)) if i == itt => buf,
            _ => Vec::new(),
        };
        if acc.len() + req.data.len() > text::MAX_TEXT {
            outcome(
                self.ctx,
                self.id,
                "text",
                "protocol_refusal",
                "more than 64 KiB of text",
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(true);
        }
        acc.extend(&req.data);
        if cont {
            self.text_in = Some((itt, acc));
            let mut r = Pdu::new(op::TEXT_RESPONSE);
            r.set_itt(itt);
            let t = self.issue_text_ttt();
            r.set_u32(20, t);
            self.stamp_now(&mut r);
            self.send(&r).await?;
            return Ok(true);
        }
        let pairs = match text::parse(&acc) {
            Ok(p) => p,
            Err(e) => {
                outcome(
                    self.ctx,
                    self.id,
                    "text",
                    "protocol_refusal",
                    &e.to_string(),
                );
                self.reject(&req, reject::PROTOCOL_ERROR).await?;
                return Ok(true);
            }
        };
        // Full feature phase text is SendTargets and nothing else here: its value is All, empty
        // (this session's target) or a target name. Anything else is refused with Reject, as
        // LIO does, rather than answered with an empty list the initiator would read as "no
        // targets" (keys are case-sensitive, so sENDtARGETS is not SendTargets either).
        let valid = !pairs.is_empty()
            && pairs.iter().all(|(k, v)| {
                k == "SendTargets" && (v == "All" || v.is_empty() || actions::valid_name(v))
            });
        if !valid {
            outcome(
                self.ctx,
                self.id,
                "text",
                "protocol_refusal",
                "a text request that is not SendTargets=All, a target name or empty",
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(true);
        }
        let mut answer: Vec<(String, String)> = Vec::new();
        for (_, v) in &pairs {
            answer.extend(self.send_targets(v).await);
        }
        self.send_text(itt, text::encode(&answer)).await?;
        Ok(true)
    }

    fn issue_text_ttt(&mut self) -> u32 {
        match self.session.clone() {
            Some(cell) => lock(&cell).issue_ttt(),
            None => {
                // A discovery session has no shared session to draw from: its own counter.
                let t = self.local_ttt;
                self.local_ttt = self.local_ttt.wrapping_add(1);
                if self.local_ttt == RESERVED_TAG || self.local_ttt == 0 {
                    self.local_ttt = 1;
                }
                t
            }
        }
    }

    /// Send a text answer, in as many PDUs as the initiator's MaxRecvDataSegmentLength needs:
    /// the first part now, the rest when it asks.
    async fn send_text(&mut self, itt: u32, mut body: Vec<u8>) -> Result<()> {
        let max = (self.params.peer_max_recv_data_segment as usize).max(512);
        let mut r = Pdu::new(op::TEXT_RESPONSE);
        r.set_itt(itt);
        if body.len() > max {
            // Split on a key boundary where one fits, so no key straddles two PDUs.
            let cut = body[..max]
                .iter()
                .rposition(|b| *b == 0)
                .map(|i| i + 1)
                .unwrap_or(max);
            let rest = body.split_off(cut);
            let ttt = self.issue_text_ttt();
            r.set_flags(0x40);
            r.set_u32(20, ttt);
            self.text_out = Some(TextContinuation { itt, ttt, rest });
        } else {
            r.set_flags(0x80);
            r.set_u32(20, RESERVED_TAG);
        }
        r.data = body;
        self.stamp_now(&mut r);
        self.send(&r).await
    }

    /// The answer to SendTargets: the model's list for All in a discovery session, this
    /// session's own target otherwise.
    async fn send_targets(&mut self, value: &str) -> Vec<(String, String)> {
        let portal = format!(
            "{}:{},{}",
            match self.local.ip() {
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                ip => ip.to_string(),
            },
            self.local.port(),
            PORTAL_GROUP_TAG
        );
        let targets: Vec<(String, Vec<String>)> = match (self.session_type, value) {
            (SessionType::Discovery, "All") => self.discover().await,
            // In a normal session the initiator already has its target: All and the empty
            // value both name it alone.
            (SessionType::Normal, "" | "All") => vec![(self.target_name.clone(), vec![])],
            (SessionType::Normal, name) if name == self.target_name => {
                vec![(self.target_name.clone(), vec![])]
            }
            (SessionType::Discovery, name) if !name.is_empty() => self
                .discover()
                .await
                .into_iter()
                .filter(|(n, _)| n == name)
                .collect(),
            _ => vec![],
        };
        let mut out = Vec::new();
        for (name, addresses) in targets {
            out.push(("TargetName".to_string(), name));
            if addresses.is_empty() {
                out.push(("TargetAddress".to_string(), portal.clone()));
            }
            for a in addresses {
                out.push((
                    "TargetAddress".to_string(),
                    format!("{a},{PORTAL_GROUP_TAG}"),
                ));
            }
        }
        out
    }

    /// The model's SendTargets list, asked once per connection. A failure lists nothing.
    async fn discover(&mut self) -> Vec<(String, Vec<String>)> {
        if let Some(d) = &self.discovered {
            return d.clone();
        }
        let event = crate::protocol::Event::new(
            &actions::DISCOVERY_EVENT,
            json!({
                "initiator_name": self.initiator_name,
                "initiator_address": self.peer.to_string(),
                "authenticated_user": self.authenticated,
            }),
        );
        let targets = match self.ask(&event).await {
            Ok(a) if a["type"] == actions::SEND_TARGETS => match actions::targets_of(&a) {
                Ok(t) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "model_answer",
                        &format!("{} target(s)", t.len()),
                    );
                    t
                }
                Err(e) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "fail_closed_invalid_reply",
                        &format!("{e:#}"),
                    );
                    vec![]
                }
            },
            Ok(_) => {
                outcome(
                    self.ctx,
                    self.id,
                    "discovery",
                    "fail_closed_invalid_reply",
                    "not a target list",
                );
                vec![]
            }
            Err(f) => {
                outcome(
                    self.ctx,
                    self.id,
                    "discovery",
                    f.decision,
                    "no targets listed",
                );
                vec![]
            }
        };
        self.discovered = Some(targets.clone());
        targets
    }
}
