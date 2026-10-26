//! Sessions as RFC 7143 has them: one or more connections (MaxConnections, §13.2) sharing the
//! command window, the task set, the write overlay and the unit attentions of one I_T nexus.
//!
//! Every connection runs in its own task. What they share lives here, behind a
//! `std::sync::Mutex` that is never held across an `.await`: a connection locks the session,
//! changes it, builds the PDUs it owes its own peer, unlocks, and only then writes. Another
//! connection that has work waiting (its command became the next in CmdSN order, or a task
//! management fence it holds cleared) is woken through its [`Notify`]; one that must stop (a
//! cold reset, a session logout, a reinstatement) through its [`CancellationToken`].
//!
//! **Command order across connections.** Commands are delivered to the SCSI layer in CmdSN
//! order session-wide (§4.2.2.1): a command ahead of ExpCmdSN is held (at most the window), and
//! once in order it joins [`Session::ready`], which only the connection the command arrived on
//! may execute, and only from the front. A connection whose command is at the front executes
//! it; one whose command is behind another connection's waits to be woken. That is what makes
//! "CmdSN N on connection B, then N+1 on connection A" execute in that order whichever arrived
//! first.
//!
//! Pure, bounded pieces — the command window ([`CommandWindow`]) and a write's received ranges
//! ([`Coverage`]) — are public for the fuzz target.
use super::lun::{Overlay, TargetDescription};
use super::pdu::{self, Pdu};
use super::text::Params;
use crate::server::connection::ConnectionId;
use crate::server::scsi_common::Sense;
use crate::utils::clock::Instant;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Normal sessions one target keeps at once (live, or retained for connection recovery).
pub const MAX_SESSIONS: usize = 256;
/// The most connections a session may ever negotiate (MaxConnections is clamped to this).
pub const MAX_CONNECTIONS_PER_SESSION: u32 = 8;
/// Unit attentions queued per logical unit of one I_T nexus.
pub const MAX_UNIT_ATTENTIONS: usize = 8;
/// I_T nexuses whose session ended with unit attentions still owed (a cold reset).
pub const MAX_PENDING_NEXUSES: usize = 1024;
/// How long unit attentions owed to an ended session's nexus are kept for its next login.
pub const PENDING_NEXUS_TTL: Duration = Duration::from_secs(600);
/// Completed tasks one session keeps for retransmission (ERL >= 1) until acknowledged.
pub const MAX_RETAINED_TASKS: usize = 256;
/// Read data one session keeps for Data SNACK and reassignment (ERL >= 1).
pub const MAX_RETAINED_READ_BYTES: usize = 64 * 1024 * 1024;
/// Retransmissions one task's data, R2Ts or status may be asked for (SNACK, reassignment).
pub const MAX_RETRANSMISSIONS: u32 = 8;
/// Received ranges a write may be split into while digest errors are being recovered.
pub const MAX_FRAGMENTS: usize = 64;
/// The longest a failed connection's tasks wait for reassignment, whatever Time2Wait and
/// Time2Retain were negotiated to (Time2Wait's result function is the maximum, so an
/// initiator can name an hour; this target keeps tasks for at most two minutes).
pub const MAX_TASK_RETENTION: Duration = Duration::from_secs(120);
/// How long a multi-task function waits for the data of outstanding transfers it ended
/// before answering anyway (RFC 7143 §4.2.3.3 step a).
pub const FENCE_WAIT: Duration = Duration::from_secs(30);

/// An I_T nexus: the initiator port (name and ISID) and the target (one portal group here).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nexus {
    pub initiator: String,
    pub isid: [u8; 6],
    pub target: String,
}

/// The CmdSN window: what is in order, what is held for a gap, what an ABORT TASK or a
/// multi-task function took out before it arrived.
#[derive(Debug, Default)]
pub struct CommandWindow {
    pub exp_cmd_sn: u32,
    /// Commands ahead of ExpCmdSN: (CmdSN, the connection, the PDU).
    held: Vec<(u32, ConnectionId, Pdu)>,
    /// CmdSNs an ABORT TASK named before the command arrived.
    aborted: Vec<u32>,
    /// Commands below a CmdSN for a LUN (or every LUN) that a multi-task function covered
    /// before they arrived: dropped when they do.
    plugged: Vec<(Option<u16>, u32)>,
}

/// What became of a command-bearing PDU.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// In order (or immediate): run it.
    Run,
    /// Ahead of a gap: kept until the gap fills.
    Held,
    /// Not run, and why.
    Dropped(&'static str),
}

impl CommandWindow {
    pub fn new(exp_cmd_sn: u32) -> Self {
        Self {
            exp_cmd_sn,
            ..Default::default()
        }
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Admit a command arriving on connection `conn`. A non-immediate command at ExpCmdSN
    /// runs; one ahead of it inside `open` slots is held; anything else is dropped (§4.2.2.1).
    pub fn admit(&mut self, conn: ConnectionId, p: &Pdu, open: u32, lun: Option<u16>) -> Admission {
        if p.immediate() {
            return Admission::Run;
        }
        let cmd_sn = p.u32_at(24);
        if cmd_sn == self.exp_cmd_sn {
            return self.take(cmd_sn, lun);
        }
        let ahead = cmd_sn.wrapping_sub(self.exp_cmd_sn);
        if pdu::sn_lt(self.exp_cmd_sn, cmd_sn) && ahead < open.max(1) {
            if self.held.iter().any(|(c, _, _)| *c == cmd_sn) {
                return Admission::Dropped("a CmdSN already held");
            }
            self.held.push((cmd_sn, conn, p.clone()));
            return Admission::Held;
        }
        Admission::Dropped("outside the command window")
    }

    /// Consume `cmd_sn` (which is ExpCmdSN): run it, unless something covered it already.
    fn take(&mut self, cmd_sn: u32, lun: Option<u16>) -> Admission {
        self.exp_cmd_sn = self.exp_cmd_sn.wrapping_add(1);
        if let Some(i) = self.aborted.iter().position(|c| *c == cmd_sn) {
            self.aborted.swap_remove(i);
            return Admission::Dropped("aborted before it arrived");
        }
        let covered = self
            .plugged
            .iter()
            .any(|(l, below)| pdu::sn_lt(cmd_sn, *below) && (l.is_none() || *l == lun));
        self.plugged.retain(|(_, below)| pdu::sn_lt(cmd_sn, *below));
        if covered {
            return Admission::Dropped("covered by a task management function");
        }
        Admission::Run
    }

    /// Held commands that are now in order, oldest first, with the connection each came on.
    /// `lun_of` names a command's LUN, for the plugs.
    pub fn release(&mut self, lun_of: impl Fn(&Pdu) -> Option<u16>) -> Vec<(ConnectionId, Pdu)> {
        let mut out = Vec::new();
        while let Some(i) = self.held.iter().position(|(c, _, _)| *c == self.exp_cmd_sn) {
            let (cmd_sn, conn, p) = self.held.swap_remove(i);
            if self.take(cmd_sn, lun_of(&p)) == Admission::Run {
                out.push((conn, p));
            }
        }
        out
    }

    /// An ABORT TASK named a CmdSN not received yet but inside the window (§11.6.1 b):
    /// consider it received and aborted. Returns whether it was within the window.
    pub fn abort_before_arrival(&mut self, ref_cmd_sn: u32, tmf_cmd_sn: u32, open: u32) -> bool {
        if let Some(i) = self.held.iter().position(|(c, _, _)| *c == ref_cmd_sn) {
            self.held.swap_remove(i);
            self.aborted.push(ref_cmd_sn);
            return true;
        }
        let within = pdu::sn_lt(ref_cmd_sn, tmf_cmd_sn)
            && pdu::sn_le(self.exp_cmd_sn, ref_cmd_sn)
            && ref_cmd_sn.wrapping_sub(self.exp_cmd_sn) < open.max(1);
        if within && self.aborted.len() < super::COMMAND_WINDOW as usize {
            self.aborted.push(ref_cmd_sn);
        }
        within
    }

    /// A multi-task function covering `lun` (or every LUN) issued at `tmf_cmd_sn`: commands
    /// held or still to arrive below that CmdSN for the LUN are not run. Returns the held
    /// commands it removed, (connection, ITT).
    pub fn plug(
        &mut self,
        lun: Option<u16>,
        tmf_cmd_sn: u32,
        lun_of: impl Fn(&Pdu) -> Option<u16>,
    ) -> Vec<(ConnectionId, u32)> {
        let mut removed = Vec::new();
        if !pdu::sn_le(self.exp_cmd_sn, tmf_cmd_sn)
            || tmf_cmd_sn.wrapping_sub(self.exp_cmd_sn) > super::COMMAND_WINDOW
        {
            // A CmdSN outside the window covers nothing.
            return removed;
        }
        self.held.retain(|(c, conn, p)| {
            let hit = pdu::sn_lt(*c, tmf_cmd_sn) && (lun.is_none() || lun_of(p) == lun);
            if hit {
                removed.push((*conn, p.itt()));
            }
            !hit
        });
        if pdu::sn_lt(self.exp_cmd_sn, tmf_cmd_sn)
            && tmf_cmd_sn.wrapping_sub(self.exp_cmd_sn) <= super::COMMAND_WINDOW
            && self.plugged.len() < super::COMMAND_WINDOW as usize
        {
            self.plugged.push((lun, tmf_cmd_sn));
        }
        removed
    }

    /// A target reset plugs the CmdSN space up to its own CmdSN (§4.2.3.3 b): everything
    /// below it counts as received, and nothing held below it runs.
    pub fn plug_all(&mut self, tmf_cmd_sn: u32) {
        // Only a CmdSN inside the window can be plugged up to: an initiator naming one past it
        // must not move ExpCmdSN wherever it likes.
        let ahead = tmf_cmd_sn.wrapping_sub(self.exp_cmd_sn);
        if !pdu::sn_lt(self.exp_cmd_sn, tmf_cmd_sn) || ahead > super::COMMAND_WINDOW {
            return;
        }
        self.held.retain(|(c, _, _)| !pdu::sn_lt(*c, tmf_cmd_sn));
        self.exp_cmd_sn = tmf_cmd_sn;
        self.aborted.clear();
        self.plugged.clear();
    }

    /// Drop the held commands of a connection that is gone (unacknowledged, §11.14).
    pub fn forget_connection(&mut self, conn: ConnectionId) {
        self.held.retain(|(_, c, _)| *c != conn);
    }
}

/// The byte ranges of a write that have arrived, merged and sorted, at most [`MAX_FRAGMENTS`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    ranges: Vec<(u32, u32)>,
}

impl Coverage {
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    /// Whether any of `[start, end)` has arrived already.
    pub fn overlaps(&self, start: u32, end: u32) -> bool {
        self.ranges.iter().any(|(s, e)| *s < end && start < *e)
    }

    /// Record `[start, end)`. `Err` when the write would be split into more than
    /// [`MAX_FRAGMENTS`] pieces.
    pub fn add(&mut self, start: u32, end: u32) -> Result<(), ()> {
        if start >= end {
            return Ok(());
        }
        let mut merged = (start, end);
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for &(s, e) in &self.ranges {
            if e < merged.0 || s > merged.1 {
                out.push((s, e));
            } else {
                merged = (merged.0.min(s), merged.1.max(e));
            }
        }
        out.push(merged);
        out.sort_unstable();
        if out.len() > MAX_FRAGMENTS {
            return Err(());
        }
        self.ranges = out;
        Ok(())
    }

    /// Bytes arrived, counting each once.
    pub fn received(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| (e - s) as u64).sum()
    }

    /// Whether `[0, total)` has all arrived.
    pub fn complete(&self, total: u32) -> bool {
        total == 0 || self.ranges.first() == Some(&(0, total))
    }

    /// The first range of `[0, total)` still missing.
    pub fn first_gap(&self, total: u32) -> Option<(u32, u32)> {
        let mut at = 0u32;
        for &(s, e) in &self.ranges {
            if s > at {
                return Some((at, s.min(total)));
            }
            at = at.max(e);
        }
        (at < total).then_some((at, total))
    }

    /// Where the contiguous prefix from offset 0 ends.
    pub fn prefix(&self) -> u32 {
        match self.ranges.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }
}

/// One outstanding R2T: its tag, the range it asked for, its R2TSN, and where its data stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R2tState {
    pub ttt: u32,
    pub offset: u32,
    pub length: u32,
    pub r2t_sn: u32,
    pub next_data_sn: u32,
    /// Times this R2T has been sent again (R2T SNACK).
    pub resent: u32,
}

/// A write waiting for its data.
#[derive(Debug)]
pub struct PendingWrite {
    pub lba: u64,
    pub expected: u32,
    /// The data so far, grown as it arrives (never allocated ahead of the data).
    pub buf: Vec<u8>,
    pub have: Coverage,
    pub unsolicited_open: bool,
    pub unsolicited_limit: u32,
    pub unsolicited_data_sn: u32,
    pub r2t: Option<R2tState>,
    pub next_r2t_sn: u32,
    /// A task management function ended the task: its outstanding data sequence is still
    /// taken (and discarded) until it ends, then the task goes (§4.2.3.3 a).
    pub aborted: bool,
    /// A data digest error at error recovery level 0: the task ends with CHECK CONDITION
    /// (PROTOCOL SERVICE CRC ERROR) once its outstanding sequence ends (§7.8 b).
    pub crc_failed: bool,
}

impl PendingWrite {
    /// Whether a data sequence is open: unsolicited data may still come, or an R2T awaits.
    pub fn sequence_open(&self) -> bool {
        self.unsolicited_open || self.r2t.is_some()
    }

    /// Copy `data` in at `offset`, growing the buffer to it.
    pub fn put(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
        let end = offset as usize + data.len();
        self.have.add(offset, end as u32)?;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[offset as usize..end].copy_from_slice(data);
        Ok(())
    }
}

/// How a SCSI command ended, kept so its status can be sent again.
#[derive(Clone, Debug)]
pub struct Status {
    pub status: u8,
    pub sense: Option<Sense>,
    /// (U/O flag bits, residual count).
    pub residual: (u8, u32),
    /// Data-In PDUs sent for the command (the SCSI Response's ExpDataSN).
    pub exp_data_sn: u32,
}

/// One Data-In PDU as first sent: where its data lies and its flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataInPdu {
    pub offset: u32,
    pub length: u32,
    pub flags: u8,
}

/// A read's data, kept (at error recovery level >= 1) until the initiator acknowledges it.
#[derive(Clone, Debug)]
pub struct ReadData {
    pub bytes: Vec<u8>,
    pub pdus: Vec<DataInPdu>,
    /// The first DataSN not yet acknowledged (DataACK, or a reassignment's ExpDataSN).
    pub acked: u32,
    /// The Target Transfer Tag carried by Data-In PDUs with the A bit.
    pub ack_ttt: u32,
}

/// A task whose status has been sent and not yet acknowledged (error recovery level >= 1).
#[derive(Clone, Debug)]
pub struct Completed {
    pub status: Status,
    /// The StatSN it went out with on its connection.
    pub stat_sn: u32,
    /// The status rode in the last Data-In PDU.
    pub collapsed: bool,
    /// None once acknowledged or let go under the retention bound.
    pub data: Option<ReadData>,
    /// The read's data was let go before it was acknowledged.
    pub data_dropped: bool,
    /// The SNACK Tag of the last R-Data SNACK, copied into the SCSI Response.
    pub snack_tag: u32,
    pub when: Instant,
}

#[derive(Debug)]
pub enum TaskState {
    Write(PendingWrite),
    Completed(Completed),
}

#[derive(Debug)]
pub struct Task {
    pub itt: u32,
    /// The connection it is allegiant to.
    pub conn: ConnectionId,
    pub lun: u16,
    pub lun_field: [u8; 8],
    pub cmd_sn: u32,
    pub state: TaskState,
    /// Retransmissions it has been asked for.
    pub retransmissions: u32,
}

impl Task {
    pub fn is_write(&self) -> bool {
        matches!(self.state, TaskState::Write(_))
    }
}

/// Where a connection of the session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    Live,
    /// The TCP connection ended without a logout (at error recovery level 2 its tasks wait
    /// for a recovery logout or a reinstatement).
    Failed(Instant),
    /// Logged out for recovery (reason 2), or replaced by a connection reinstatement: its
    /// tasks may be reassigned until the retention runs out.
    Recovering(Instant),
}

/// How a connection left its session; see [`Session::connection_gone`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gone {
    Closed,
    Failed(Instant),
    Recovering(Instant),
}

#[derive(Debug)]
pub struct ConnSlot {
    pub cid: u16,
    pub id: ConnectionId,
    pub wake: Arc<Notify>,
    pub close: CancellationToken,
    pub life: Life,
}

/// A multi-task function's response, held until the outstanding transfers of the tasks it
/// ended have run out (or [`FENCE_WAIT`]).
#[derive(Debug)]
pub struct Fence {
    pub conn: ConnectionId,
    pub tmf_itt: u32,
    pub response: u8,
    pub waiting: Vec<u32>,
    pub deadline: Instant,
}

/// A command delivered in order and waiting for the connection it came on to run it.
#[derive(Debug)]
pub struct Ready {
    pub conn: ConnectionId,
    pub pdu: Pdu,
}

#[derive(Debug)]
pub struct Session {
    pub tsih: u16,
    pub nexus: Nexus,
    pub authenticated: Option<String>,
    pub target: Arc<TargetDescription>,
    /// The leading login's operational parameters (the session-wide keys).
    pub params: Params,
    pub overlay: Overlay,
    pub window: CommandWindow,
    pub ready: VecDeque<Ready>,
    /// The connection running the command taken from the front of `ready`.
    pub busy: Option<ConnectionId>,
    pub tasks: HashMap<u32, Task>,
    pub conns: Vec<ConnSlot>,
    pub unit_attentions: HashMap<u16, VecDeque<Sense>>,
    pub fences: Vec<Fence>,
    pub ended: bool,
    next_ttt: u32,
}

impl Session {
    pub fn new(
        tsih: u16,
        nexus: Nexus,
        authenticated: Option<String>,
        target: Arc<TargetDescription>,
        params: Params,
        exp_cmd_sn: u32,
    ) -> Self {
        Self {
            tsih,
            nexus,
            authenticated,
            target,
            params,
            overlay: Overlay::default(),
            window: CommandWindow::new(exp_cmd_sn),
            ready: VecDeque::new(),
            busy: None,
            tasks: HashMap::new(),
            conns: Vec::new(),
            unit_attentions: HashMap::new(),
            fences: Vec::new(),
            ended: false,
            next_ttt: 0x0001_0000,
        }
    }

    pub fn erl(&self) -> u32 {
        self.params.error_recovery_level
    }

    /// A Target Transfer Tag unique in the session.
    pub fn issue_ttt(&mut self) -> u32 {
        let t = self.next_ttt;
        self.next_ttt = self.next_ttt.wrapping_add(1);
        if self.next_ttt == pdu::RESERVED_TAG || self.next_ttt == 0 {
            self.next_ttt = 1;
        }
        t
    }

    pub fn pending_writes(&self) -> usize {
        self.tasks.values().filter(|t| t.is_write()).count()
    }

    /// Command slots open: the window less the writes still waiting for data.
    pub fn open_slots(&self) -> u32 {
        super::COMMAND_WINDOW.saturating_sub(self.pending_writes() as u32)
    }

    pub fn max_cmd_sn(&self) -> u32 {
        self.window
            .exp_cmd_sn
            .wrapping_add(self.open_slots())
            .wrapping_sub(1)
    }

    pub fn live_connections(&self) -> usize {
        self.conns.iter().filter(|c| c.life == Life::Live).count()
    }

    pub fn conn(&self, conn: ConnectionId) -> Option<&ConnSlot> {
        self.conns.iter().find(|c| c.id == conn)
    }

    /// Wake connection `conn` (it has work: a command at the front, or a fence cleared).
    pub fn wake(&self, conn: ConnectionId) {
        if let Some(c) = self.conn(conn) {
            c.wake.notify_one();
        }
    }

    /// The next command connection `conn` may run, popped, marking the session busy until
    /// [`Session::done`]. Another connection's command at the front is woken instead.
    pub fn next_ready(&mut self, conn: ConnectionId) -> Option<Pdu> {
        if self.busy.is_some() {
            return None;
        }
        // Commands of connections that are gone are not run.
        while let Some(front) = self.ready.front() {
            if self.conn(front.conn).is_some_and(|c| c.life == Life::Live) {
                break;
            }
            self.ready.pop_front();
        }
        let front = self.ready.front()?;
        if front.conn != conn {
            self.wake(front.conn);
            return None;
        }
        self.busy = Some(conn);
        self.ready.pop_front().map(|r| r.pdu)
    }

    /// The command taken with [`Session::next_ready`] is done: wake whoever runs the next.
    pub fn done(&mut self) {
        self.busy = None;
        if let Some(front) = self.ready.front() {
            self.wake(front.conn);
        }
    }

    /// Queue a command for in-order execution, and any held commands it unblocks.
    pub fn deliver(&mut self, conn: ConnectionId, p: Pdu) {
        self.ready.push_back(Ready { conn, pdu: p });
        let target = self.target.clone();
        for (c, p) in self.window.release(|p| lun_of(&target, p)) {
            self.ready.push_back(Ready { conn: c, pdu: p });
        }
    }

    /// Establish a unit attention for one LUN (deduplicated, bounded: past the bound the
    /// oldest goes, as SPC lets a device server report only the most recent).
    pub fn unit_attention(&mut self, lun: u16, sense: Sense) {
        let q = self.unit_attentions.entry(lun).or_default();
        if q.iter().any(|s| *s == sense) {
            return;
        }
        if q.len() >= MAX_UNIT_ATTENTIONS {
            q.pop_front();
        }
        q.push_back(sense);
    }

    /// A unit attention for every LUN of the session.
    pub fn unit_attention_all(&mut self, sense: Sense) {
        let luns: Vec<u16> = self.target.luns.iter().map(|l| l.number).collect();
        for l in luns {
            self.unit_attention(l, sense);
        }
    }

    pub fn take_unit_attention(&mut self, lun: u16) -> Option<Sense> {
        let q = self.unit_attentions.get_mut(&lun)?;
        let s = q.pop_front();
        if q.is_empty() {
            self.unit_attentions.remove(&lun);
        }
        s
    }

    /// End tasks a task management function or a reset covers: those of `lun` (or all),
    /// optionally only those allegiant to `conn`. Writes with a data sequence still open are
    /// kept, marked aborted, so their data is taken until the sequence ends; their ITTs are
    /// returned for a fence. Returns (tasks ended, ITTs whose sequence is still open).
    pub fn abort_tasks(&mut self, lun: Option<u16>) -> (usize, Vec<u32>) {
        let mut ended = 0;
        let mut open = Vec::new();
        self.tasks.retain(|itt, t| {
            if lun.is_some_and(|l| l != t.lun) {
                return true;
            }
            match &mut t.state {
                TaskState::Write(w) if !w.aborted => {
                    ended += 1;
                    if w.sequence_open() {
                        w.aborted = true;
                        open.push(*itt);
                        true
                    } else {
                        false
                    }
                }
                TaskState::Write(_) => true,
                // Completed tasks were answered before the function: only their retained
                // state goes.
                TaskState::Completed(_) => false,
            }
        });
        // Commands delivered but not yet run are covered too.
        let target = self.target.clone();
        let before = self.ready.len();
        self.ready.retain(|r| {
            !(r.pdu.opcode() == pdu::op::SCSI_COMMAND
                && (lun.is_none() || lun_of(&target, &r.pdu) == lun))
        });
        ended += before - self.ready.len();
        (ended, open)
    }

    /// A write's open sequence ended: release any fence waiting on it.
    pub fn sequence_ended(&mut self, itt: u32) {
        let mut wake = Vec::new();
        for f in &mut self.fences {
            if let Some(i) = f.waiting.iter().position(|w| *w == itt) {
                f.waiting.swap_remove(i);
                if f.waiting.is_empty() {
                    wake.push(f.conn);
                }
            }
        }
        for c in wake {
            self.wake(c);
        }
    }

    /// Fences of connection `conn` that may now be answered (nothing to wait for, or out of
    /// time): removed and returned.
    pub fn ripe_fences(&mut self, conn: ConnectionId, now: Instant) -> Vec<Fence> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.fences.len() {
            let f = &self.fences[i];
            if f.conn == conn && (f.waiting.is_empty() || now >= f.deadline) {
                out.push(self.fences.swap_remove(i));
            } else {
                i += 1;
            }
        }
        out
    }

    /// The earliest deadline among connection `conn`'s fences.
    pub fn fence_deadline(&self, conn: ConnectionId) -> Option<Instant> {
        self.fences
            .iter()
            .filter(|f| f.conn == conn)
            .map(|f| f.deadline)
            .min()
    }

    /// The connection `conn` ended: `Closed` (a logout that closes it, or any end at error
    /// recovery level < 2: its tasks end now), `Failed` (the TCP connection dropped: at level 2
    /// its tasks wait for a recovery logout or a reinstatement) or `Recovering` (logged out for
    /// recovery or reinstated: its tasks may be reassigned). Returns the LUNs of writes that
    /// ended, for the unit attention RFC 7143 §11.14.5 asks for.
    pub fn connection_gone(&mut self, conn: ConnectionId, how: Gone) -> Vec<u16> {
        self.window.forget_connection(conn);
        self.fences.retain(|f| f.conn != conn);
        let life = match how {
            Gone::Failed(t) => Life::Failed(t),
            Gone::Recovering(t) => Life::Recovering(t),
            Gone::Closed => Life::Failed(Instant::now()),
        };
        if let Some(c) = self.conns.iter_mut().find(|c| c.id == conn) {
            c.life = life;
        }
        // Time2Retain 0 means the target keeps nothing for recovery (§11.15.4).
        let keep =
            self.erl() >= 2 && !matches!(how, Gone::Closed) && self.params.default_time2retain > 0;
        let mut luns = Vec::new();
        if !keep {
            self.tasks.retain(|_, t| {
                if t.conn != conn {
                    return true;
                }
                if !luns.contains(&t.lun) && t.is_write() {
                    luns.push(t.lun);
                }
                false
            });
            self.conns.retain(|c| c.id != conn || c.life == Life::Live);
        }
        if self.busy == Some(conn) {
            self.done();
        }
        luns
    }

    /// When a gone connection's retained tasks stop being reassignable.
    pub fn retention_ends(&self, since: Instant) -> Instant {
        let t = Duration::from_secs(
            self.params.default_time2wait as u64 + self.params.default_time2retain as u64,
        )
        .min(MAX_TASK_RETENTION);
        since + t
    }

    /// Drop retained tasks and connection slots whose retention ran out. Returns the LUNs of
    /// writes that ended this way (§11.14.5 c).
    pub fn expire(&mut self, now: Instant) -> Vec<u16> {
        let mut expired = Vec::new();
        for c in &self.conns {
            let since = match c.life {
                Life::Live => continue,
                Life::Failed(t) | Life::Recovering(t) => t,
            };
            if now >= self.retention_ends(since) {
                expired.push(c.id);
            }
        }
        let mut luns = Vec::new();
        for conn in &expired {
            self.tasks.retain(|_, t| {
                if t.conn != *conn {
                    return true;
                }
                if t.is_write() && !luns.contains(&t.lun) {
                    luns.push(t.lun);
                }
                false
            });
        }
        self.conns.retain(|c| !expired.contains(&c.id));
        luns
    }

    /// Whether nothing keeps the session: no live connection, and no failed one whose
    /// recovery it still waits for (§6.3.5: the session times out with the last connection's
    /// state).
    pub fn idle(&self) -> bool {
        self.conns.is_empty()
    }

    /// Keep the retained completed tasks and their read data within bounds, oldest first.
    pub fn bound_retention(&mut self) {
        let mut done: Vec<(Instant, u32, usize)> = self
            .tasks
            .iter()
            .filter_map(|(itt, t)| match &t.state {
                TaskState::Completed(c) => {
                    Some((c.when, *itt, c.data.as_ref().map_or(0, |d| d.bytes.len())))
                }
                _ => None,
            })
            .collect();
        done.sort_unstable_by_key(|(when, itt, _)| (*when, *itt));
        let mut count = done.len();
        let mut bytes: usize = done.iter().map(|(_, _, b)| *b).sum();
        for (_, itt, b) in done {
            if count > MAX_RETAINED_TASKS {
                self.tasks.remove(&itt);
                count -= 1;
                bytes -= b;
                continue;
            }
            if bytes > MAX_RETAINED_READ_BYTES && b > 0 {
                if let Some(Task {
                    state: TaskState::Completed(c),
                    ..
                }) = self.tasks.get_mut(&itt)
                {
                    c.data = None;
                    c.data_dropped = true;
                    bytes -= b;
                }
            }
        }
    }

    /// The initiator acknowledged every status before `exp_stat_sn` on connection `conn`:
    /// those tasks need nothing kept.
    pub fn acknowledge(&mut self, conn: ConnectionId, exp_stat_sn: u32) {
        self.tasks.retain(|_, t| match &t.state {
            TaskState::Completed(c) if t.conn == conn => !pdu::sn_lt(c.stat_sn, exp_stat_sn),
            _ => true,
        });
    }
}

/// The LUN a command PDU addresses, if it is one of the target's.
pub fn lun_of(target: &TargetDescription, p: &Pdu) -> Option<u16> {
    crate::server::scsi_common::lun_from_field(&p.lun()).filter(|n| target.lun(*n).is_some())
}

pub type SessionCell = Arc<Mutex<Session>>;

/// Lock a session; a poisoned lock (a panic in another connection) is taken over rather than
/// spread, since every change under it is a whole step.
pub fn lock(s: &SessionCell) -> std::sync::MutexGuard<'_, Session> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

/// Unit attentions owed to a nexus whose session has ended.
#[derive(Debug)]
struct Owed {
    since: Instant,
    senses: Vec<Sense>,
}

/// Every normal session of one target server, by TSIH.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: HashMap<u16, SessionCell>,
    next_tsih: u16,
    owed: HashMap<Nexus, Owed>,
}

pub type RegistryCell = Arc<Mutex<Registry>>;

pub fn lock_registry(r: &RegistryCell) -> std::sync::MutexGuard<'_, Registry> {
    r.lock().unwrap_or_else(|e| e.into_inner())
}

impl Registry {
    pub fn new() -> Self {
        Self {
            next_tsih: 1,
            ..Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn get(&self, tsih: u16) -> Option<SessionCell> {
        self.sessions.get(&tsih).cloned()
    }

    /// A TSIH no session holds (and not 0), or `None` when every one is taken.
    pub fn allocate_tsih(&mut self) -> Option<u16> {
        for _ in 0..=u16::MAX as u32 {
            let t = self.next_tsih;
            self.next_tsih = self.next_tsih.checked_add(1).unwrap_or(1);
            if t != 0 && !self.sessions.contains_key(&t) {
                return Some(t);
            }
        }
        None
    }

    pub fn insert(&mut self, tsih: u16, s: SessionCell) {
        self.sessions.insert(tsih, s);
    }

    pub fn remove(&mut self, tsih: u16) {
        self.sessions.remove(&tsih);
    }

    /// The session of a nexus, for reinstatement.
    pub fn by_nexus(&self, nexus: &Nexus) -> Option<SessionCell> {
        self.sessions
            .values()
            .find(|s| lock(s).nexus == *nexus)
            .cloned()
    }

    /// Every session logged in to `target`.
    pub fn on_target(&self, target: &str) -> Vec<SessionCell> {
        self.sessions
            .values()
            .filter(|s| lock(s).nexus.target == target)
            .cloned()
            .collect()
    }

    pub fn all(&self) -> Vec<SessionCell> {
        self.sessions.values().cloned().collect()
    }

    /// Remember unit attentions for a nexus whose session ended (bounded; oldest go first).
    pub fn owe(&mut self, nexus: Nexus, sense: Sense, now: Instant) {
        self.owed
            .retain(|_, o| now.duration_since(o.since) < PENDING_NEXUS_TTL);
        if !self.owed.contains_key(&nexus) && self.owed.len() >= MAX_PENDING_NEXUSES {
            if let Some(oldest) = self
                .owed
                .iter()
                .min_by_key(|(_, o)| o.since)
                .map(|(n, _)| n.clone())
            {
                self.owed.remove(&oldest);
            }
        }
        let o = self.owed.entry(nexus).or_insert(Owed {
            since: now,
            senses: Vec::new(),
        });
        if !o.senses.contains(&sense) && o.senses.len() < MAX_UNIT_ATTENTIONS {
            o.senses.push(sense);
        }
    }

    /// The unit attentions owed to a nexus logging in again.
    pub fn take_owed(&mut self, nexus: &Nexus) -> Vec<Sense> {
        self.owed
            .remove(nexus)
            .map(|o| o.senses)
            .unwrap_or_default()
    }

    /// Sessions that ended or that nothing keeps any more: removed. Returns their TSIHs.
    pub fn purge(&mut self, now: Instant) -> Vec<u16> {
        let mut gone = Vec::new();
        for (tsih, s) in &self.sessions {
            let mut s = lock(s);
            for lun in s.expire(now) {
                s.unit_attention(lun, Sense::COMMANDS_CLEARED_BY_ISCSI_EVENT);
            }
            if s.ended || s.idle() {
                s.ended = true;
                gone.push(*tsih);
            }
        }
        for t in &gone {
            self.sessions.remove(t);
        }
        gone
    }
}
