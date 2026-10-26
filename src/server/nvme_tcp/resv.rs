//! Persistent reservations (NVMe Base, "Reservations"): the registrant and holder table of one
//! namespace, the rules Reservation Register, Acquire and Release follow, which I/O a
//! reservation lets a host run, and the Reservation Report data structure. Pure: the target
//! (`super`) owns one table per subsystem namespace, asks the model before applying a change,
//! and checks every I/O command against it; the host decodes the report.
//!
//! The rules follow the specification as the Linux target (`drivers/nvme/target/pr.c`) applies
//! them, with two differences the specification states and nvmet does not: under an
//! all-registrants reservation every registrant holds it (so any of them may acquire the same
//! type again or release it), and releasing with the wrong type is INVALID FIELD rather than
//! RESERVATION CONFLICT.
use super::nvme::Status;

/// Reservation types.
pub mod rtype {
    pub const WRITE_EXCLUSIVE: u8 = 1;
    pub const EXCLUSIVE_ACCESS: u8 = 2;
    pub const WRITE_EXCLUSIVE_REGISTRANTS_ONLY: u8 = 3;
    pub const EXCLUSIVE_ACCESS_REGISTRANTS_ONLY: u8 = 4;
    pub const WRITE_EXCLUSIVE_ALL_REGISTRANTS: u8 = 5;
    pub const EXCLUSIVE_ACCESS_ALL_REGISTRANTS: u8 = 6;

    pub const NAMES: [&str; 6] = [
        "write_exclusive",
        "exclusive_access",
        "write_exclusive_registrants_only",
        "exclusive_access_registrants_only",
        "write_exclusive_all_registrants",
        "exclusive_access_all_registrants",
    ];

    pub fn name(t: u8) -> &'static str {
        match t {
            1..=6 => NAMES[t as usize - 1],
            0 => "none",
            _ => "unknown",
        }
    }
    pub fn parse(s: &str) -> Option<u8> {
        NAMES.iter().position(|n| *n == s).map(|i| i as u8 + 1)
    }
    pub fn all_registrants(t: u8) -> bool {
        matches!(
            t,
            WRITE_EXCLUSIVE_ALL_REGISTRANTS | EXCLUSIVE_ACCESS_ALL_REGISTRANTS
        )
    }
}

/// Identify Namespace RESCAP: types 1 to 6 and Ignore Existing Key as NVMe 1.3 defines it; no
/// persistence through power loss.
pub const RESCAP: u8 = 0xFE;
/// Hosts one namespace registers.
pub const MAX_REGISTRANTS: usize = 64;
/// The extended Reservation Report: a 64-byte header and 64 bytes per registrant.
pub const REPORT_HEADER: usize = 64;
pub const REPORT_ENTRY: usize = 64;

pub const CONFLICT: Status = Status::generic(0x83);
/// A report asked for with 64-bit host identifiers, which fabrics hosts do not have.
pub const HOST_ID_INCONSISTENT: Status = Status::generic(0x18);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registrant {
    pub hostid: [u8; 16],
    pub key: u64,
}

/// One namespace's reservation state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub generation: u32,
    pub registrants: Vec<Registrant>,
    /// The host holding the reservation and its type (an all-registrants reservation names
    /// the registrant that acquired it; every registrant holds it).
    pub holder: Option<([u8; 16], u8)>,
}

/// A reservation command, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Register {
        new_key: u64,
    },
    Unregister {
        key: u64,
        ignore_key: bool,
    },
    Replace {
        key: u64,
        new_key: u64,
        ignore_key: bool,
    },
    Acquire {
        key: u64,
        rtype: u8,
    },
    Preempt {
        key: u64,
        preempt_key: u64,
        rtype: u8,
        abort: bool,
    },
    Release {
        key: u64,
        rtype: u8,
    },
    Clear {
        key: u64,
    },
}

impl Op {
    pub fn name(&self) -> &'static str {
        match self {
            Op::Register { .. } => "register",
            Op::Unregister { .. } => "unregister",
            Op::Replace { .. } => "replace",
            Op::Acquire { .. } => "acquire",
            Op::Preempt { abort: false, .. } => "preempt",
            Op::Preempt { abort: true, .. } => "preempt_and_abort",
            Op::Release { .. } => "release",
            Op::Clear { .. } => "clear",
        }
    }
    pub fn rtype(&self) -> Option<u8> {
        match self {
            Op::Acquire { rtype, .. } | Op::Preempt { rtype, .. } | Op::Release { rtype, .. } => {
                Some(*rtype)
            }
            _ => None,
        }
    }

    /// Reservation Register (CDW10: RREGA, IEKEY, CPTPL; data: CRKEY, NRKEY).
    pub fn register(cdw10: u32, data: &[u8]) -> Result<Op, Status> {
        let (key, new_key) = keys(data, 16)?;
        let ignore_key = cdw10 & 0x08 != 0;
        // Change Persist Through Power Loss: no change and "clear" (it is never set) only.
        if !matches!(cdw10 >> 30, 0 | 2) {
            return Err(Status::INVALID_FIELD);
        }
        match cdw10 & 0x07 {
            0 => Ok(Op::Register { new_key }),
            1 => Ok(Op::Unregister { key, ignore_key }),
            2 => Ok(Op::Replace {
                key,
                new_key,
                ignore_key,
            }),
            _ => Err(Status::INVALID_FIELD),
        }
    }

    /// Reservation Acquire (CDW10: RACQA, IEKEY, RTYPE; data: CRKEY, PRKEY).
    pub fn acquire(cdw10: u32, data: &[u8]) -> Result<Op, Status> {
        let (key, preempt_key) = keys(data, 16)?;
        let rt = ((cdw10 >> 8) & 0xFF) as u8;
        if cdw10 & 0x08 != 0 || !(1..=6).contains(&rt) {
            return Err(Status::INVALID_FIELD);
        }
        match cdw10 & 0x07 {
            0 => Ok(Op::Acquire { key, rtype: rt }),
            a @ (1 | 2) => Ok(Op::Preempt {
                key,
                preempt_key,
                rtype: rt,
                abort: a == 2,
            }),
            _ => Err(Status::INVALID_FIELD),
        }
    }

    /// Reservation Release (CDW10: RRELA, IEKEY, RTYPE; data: CRKEY).
    pub fn release(cdw10: u32, data: &[u8]) -> Result<Op, Status> {
        let (key, _) = keys(data, 8)?;
        let rt = ((cdw10 >> 8) & 0xFF) as u8;
        if cdw10 & 0x08 != 0 {
            return Err(Status::INVALID_FIELD);
        }
        match cdw10 & 0x07 {
            0 => Ok(Op::Release { key, rtype: rt }),
            1 => Ok(Op::Clear { key }),
            _ => Err(Status::INVALID_FIELD),
        }
    }
}

fn keys(data: &[u8], need: usize) -> Result<(u64, u64), Status> {
    if data.len() < need {
        return Err(Status::SGL_LENGTH_INVALID);
    }
    let k = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"));
    Ok((k(0), if need >= 16 { k(8) } else { 0 }))
}

/// The data a reservation command carries: 16 bytes for Register and Acquire, 8 for Release.
pub fn data_len(opcode: u8) -> usize {
    if opcode == super::nvme::io::RESV_RELEASE {
        8
    } else {
        16
    }
}

/// What a change does, for the model and the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Whether the table changes at all (a no-op succeeds without asking anyone).
    pub changes: bool,
    pub summary: String,
}

impl Table {
    fn find(&self, host: &[u8; 16]) -> Option<usize> {
        self.registrants.iter().position(|r| r.hostid == *host)
    }

    pub fn registered(&self, host: &[u8; 16]) -> bool {
        self.find(host).is_some()
    }

    /// Whether `host` holds the reservation.
    pub fn holds(&self, host: &[u8; 16]) -> bool {
        match self.holder {
            None => false,
            Some((h, t)) => h == *host || (rtype::all_registrants(t) && self.registered(host)),
        }
    }

    fn remove(&mut self, i: usize) {
        let gone = self.registrants.remove(i);
        if let Some((h, t)) = self.holder {
            if h == gone.hostid {
                self.holder = if rtype::all_registrants(t) {
                    self.registrants.first().map(|r| (r.hostid, t))
                } else {
                    None
                };
            }
        }
    }

    /// Remove every registrant with `key` (but `keep`); how many went.
    fn remove_by_key(&mut self, key: u64, keep: Option<[u8; 16]>) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.registrants.len() {
            let r = self.registrants[i];
            if r.key == key && Some(r.hostid) != keep {
                self.remove(i);
                n += 1;
            } else {
                i += 1;
            }
        }
        n
    }

    fn add(&mut self, host: [u8; 16], key: u64) -> Result<(), Status> {
        if self.registrants.len() >= MAX_REGISTRANTS {
            return Err(CONFLICT);
        }
        self.registrants.push(Registrant { hostid: host, key });
        Ok(())
    }

    /// Apply a command for `host` to this table, as the specification orders it. `Err` is the
    /// status to complete the command with and leaves the table unchanged.
    pub fn apply(&mut self, host: [u8; 16], op: &Op) -> Result<Change, Status> {
        let before = self.clone();
        let r = self.apply_inner(host, op);
        match &r {
            Err(_) => *self = before,
            Ok(c) if c.changes && self.registrants != before.registrants => {
                self.generation = self.generation.wrapping_add(1);
            }
            Ok(_) => {}
        }
        r
    }

    fn apply_inner(&mut self, host: [u8; 16], op: &Op) -> Result<Change, Status> {
        let done = |changes: bool, summary: String| Ok(Change { changes, summary });
        let me = self.find(&host);
        match *op {
            Op::Register { new_key } => match me {
                Some(i) if self.registrants[i].key == new_key => {
                    done(false, "already registered with that key".into())
                }
                Some(_) => Err(CONFLICT),
                None => {
                    self.add(host, new_key)?;
                    done(true, "the host registers".into())
                }
            },
            Op::Unregister { key, ignore_key } => match me {
                Some(i) if ignore_key || self.registrants[i].key == key => {
                    let held = self.holds(&host);
                    self.remove(i);
                    done(
                        true,
                        if held && self.holder.is_none() {
                            "the host unregisters and its reservation is released".into()
                        } else {
                            "the host unregisters".into()
                        },
                    )
                }
                _ => Err(CONFLICT),
            },
            Op::Replace {
                key,
                new_key,
                ignore_key,
            } => match me {
                Some(i) if ignore_key || self.registrants[i].key == key => {
                    let changes = self.registrants[i].key != new_key;
                    self.registrants[i].key = new_key;
                    done(changes, "the host replaces its key".into())
                }
                Some(_) => Err(CONFLICT),
                None if ignore_key => {
                    if new_key == 0 {
                        return Err(Status::INVALID_FIELD);
                    }
                    self.add(host, new_key)?;
                    done(
                        true,
                        "the host registers (replace, ignoring its key)".into(),
                    )
                }
                None => Err(CONFLICT),
            },
            Op::Acquire { key, rtype: t } => {
                if !me.is_some_and(|i| self.registrants[i].key == key) {
                    return Err(CONFLICT);
                }
                match self.holder {
                    Some((_, held)) if self.holds(&host) && held == t => {
                        done(false, "the host already holds that reservation".into())
                    }
                    Some(_) => Err(CONFLICT),
                    None => {
                        self.holder = Some((host, t));
                        done(
                            true,
                            format!("the host acquires a {} reservation", rtype::name(t)),
                        )
                    }
                }
            }
            Op::Preempt {
                key,
                preempt_key,
                rtype: t,
                ..
            } => {
                if !me.is_some_and(|i| self.registrants[i].key == key) {
                    return Err(CONFLICT);
                }
                let Some((holder, held)) = self.holder else {
                    let n = self.remove_by_key(preempt_key, None);
                    if n == 0 {
                        return Err(CONFLICT);
                    }
                    return done(true, format!("{n} registration(s) preempted"));
                };
                if rtype::all_registrants(held) {
                    if preempt_key == 0 {
                        let others = self.registrants.len() - 1;
                        self.registrants.retain(|r| r.hostid == host);
                        self.holder = Some((host, t));
                        return done(
                            true,
                            format!(
                                "the host takes a {} reservation and {others} other registration(s) are removed",
                                rtype::name(t)
                            ),
                        );
                    }
                    let n = self.remove_by_key(preempt_key, None);
                    if n == 0 {
                        return Err(CONFLICT);
                    }
                    return done(true, format!("{n} registration(s) preempted"));
                }
                let holder_key = self
                    .find(&holder)
                    .map(|i| self.registrants[i].key)
                    .unwrap_or_default();
                if holder == host && preempt_key == holder_key {
                    self.holder = Some((host, t));
                    return done(
                        held != t,
                        format!("the host changes its reservation to {}", rtype::name(t)),
                    );
                }
                if preempt_key == holder_key {
                    self.holder = Some((host, t));
                    let n = self.remove_by_key(preempt_key, Some(host));
                    return done(
                        true,
                        format!(
                            "the host preempts the holder and takes a {} reservation; {n} registration(s) removed",
                            rtype::name(t)
                        ),
                    );
                }
                if preempt_key != 0 {
                    let n = self.remove_by_key(preempt_key, None);
                    if n == 0 {
                        return Err(CONFLICT);
                    }
                    return done(true, format!("{n} registration(s) preempted"));
                }
                Err(Status::INVALID_FIELD)
            }
            Op::Release { key, rtype: t } => {
                if !me.is_some_and(|i| self.registrants[i].key == key) {
                    return Err(CONFLICT);
                }
                match self.holder {
                    Some((_, held)) if self.holds(&host) => {
                        if held != t {
                            return Err(Status::INVALID_FIELD);
                        }
                        self.holder = None;
                        done(
                            true,
                            format!("the host releases the {} reservation", rtype::name(t)),
                        )
                    }
                    _ => done(false, "the host holds no reservation to release".into()),
                }
            }
            Op::Clear { key } => {
                if !me.is_some_and(|i| self.registrants[i].key == key) {
                    return Err(CONFLICT);
                }
                let n = self.registrants.len();
                self.registrants.clear();
                self.holder = None;
                done(
                    true,
                    format!("the reservation and all {n} registration(s) are cleared"),
                )
            }
        }
    }

    /// Whether `host` may run a command of the read group (`write` false: Read, Compare,
    /// Verify) or the write group (`write` true: Write, Write Zeroes, Dataset Management,
    /// Copy, Flush) under the current reservation.
    pub fn allows(&self, host: &[u8; 16], write: bool) -> bool {
        let Some((holder, t)) = self.holder else {
            return true;
        };
        if holder == *host {
            return true;
        }
        let registered = self.registered(host);
        match t {
            rtype::WRITE_EXCLUSIVE => !write,
            rtype::EXCLUSIVE_ACCESS => false,
            rtype::WRITE_EXCLUSIVE_REGISTRANTS_ONLY | rtype::WRITE_EXCLUSIVE_ALL_REGISTRANTS => {
                !write || registered
            }
            _ => registered,
        }
    }

    /// The extended Reservation Report (EDS 1), `len` bytes: the header, then as many
    /// registrants as fit; REGCTL counts them all.
    pub fn report(&self, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        let header = |b: &mut [u8], at: usize, v: &[u8]| {
            if at + v.len() <= b.len() {
                b[at..at + v.len()].copy_from_slice(v);
            }
        };
        header(&mut b, 0, &self.generation.to_le_bytes());
        header(&mut b, 4, &[self.holder.map_or(0, |(_, t)| t)]);
        header(&mut b, 5, &(self.registrants.len() as u16).to_le_bytes());
        for (i, r) in self.registrants.iter().enumerate() {
            let at = REPORT_HEADER + i * REPORT_ENTRY;
            if at + REPORT_ENTRY > len {
                break;
            }
            let e = &mut b[at..at + REPORT_ENTRY];
            // The dynamic controller model: no fixed CNTLID per host.
            e[0..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            e[2] = self.holds(&r.hostid) as u8;
            e[8..16].copy_from_slice(&r.key.to_le_bytes());
            e[16..32].copy_from_slice(&r.hostid);
        }
        b
    }
}

/// A Reservation Report as a host reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub generation: u32,
    pub rtype: u8,
    pub registered: u16,
    pub ptpls: bool,
    /// (CNTLID, holds the reservation, key, host identifier).
    pub entries: Vec<(u16, bool, u64, [u8; 16])>,
}

impl Report {
    /// Decode an extended report; entries past the buffer, or past REGCTL, are not read.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let h = b.get(..REPORT_HEADER)?;
        let registered = u16::from_le_bytes([h[5], h[6]]);
        let entries = b[REPORT_HEADER..]
            .chunks_exact(REPORT_ENTRY)
            .take(registered as usize)
            .map(|e| {
                (
                    u16::from_le_bytes([e[0], e[1]]),
                    e[2] & 1 != 0,
                    u64::from_le_bytes(e[8..16].try_into().expect("8 bytes")),
                    e[16..32].try_into().expect("16 bytes"),
                )
            })
            .collect();
        Some(Self {
            generation: u32::from_le_bytes(h[0..4].try_into().expect("4 bytes")),
            rtype: h[4],
            registered,
            ptpls: h[9] & 1 != 0,
            entries,
        })
    }
}
