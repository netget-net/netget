//! An emulated EtherCAT Slave Controller (ESC): the register space and process memory a master
//! reads and writes with datagrams, the SyncManagers and FMMUs that guard and map it, the AL
//! state machine registers, the SII (EEPROM) interface and the working counter.
//!
//! What a real ESC does in silicon and a slave's firmware does over the PDI are both here, so
//! the two halves are kept apart: datagram processing ([`Esc::process`]) is the silicon — it
//! never waits and never asks the model — and everything the firmware would decide is reported
//! as an [`EscEvent`] for the engine to settle, then applied with [`Esc::resolve_transition`],
//! [`Esc::post_mailbox`] and [`Esc::set_inputs`].
//!
//! Working counter rules (ETG.1000.4 §5.4): a read that succeeds adds 1, a write that succeeds
//! adds 1, a read-write adds 1 for the read and 2 for the write (so 3 when both succeed). A
//! datagram the slave is not addressed by, or whose access a SyncManager refuses, adds nothing
//! and leaves the data as it arrived.
use super::device::{get_bits, put_bits, DeviceSpec};
use super::frame::{self, cmd, DatagramAt};
use super::sii::{self, Layout};
use std::collections::VecDeque;

type Instant = crate::utils::clock::Instant;

pub const NUM_FMMU: usize = 8;
pub const NUM_SM: usize = 8;
/// Process memory (8 KiB, as an ET1100 has), after the 4 KiB register area.
pub const RAM_BYTES: usize = 8 * 1024;
pub const MEMORY: usize = 0x1000 + RAM_BYTES;
/// Mailbox replies waiting for the master to empty the send mailbox.
pub const MAILBOX_QUEUE: usize = 4;

/// Register addresses (ETG.1000.4 Table 31 onward).
pub mod reg {
    pub const TYPE: usize = 0x0000;
    pub const REVISION: usize = 0x0001;
    pub const BUILD: usize = 0x0002;
    pub const FMMUS: usize = 0x0004;
    pub const SYNC_MANAGERS: usize = 0x0005;
    pub const RAM_SIZE: usize = 0x0006;
    pub const PORT_DESCRIPTOR: usize = 0x0007;
    pub const FEATURES: usize = 0x0008;
    pub const STATION_ADDRESS: usize = 0x0010;
    pub const STATION_ALIAS: usize = 0x0012;
    pub const DL_CONTROL: usize = 0x0100;
    pub const DL_STATUS: usize = 0x0110;
    pub const AL_CONTROL: usize = 0x0120;
    pub const AL_STATUS: usize = 0x0130;
    pub const AL_STATUS_CODE: usize = 0x0134;
    pub const PDI_CONTROL: usize = 0x0140;
    pub const WATCHDOG_DIVIDER: usize = 0x0400;
    pub const WATCHDOG_PDI: usize = 0x0410;
    pub const WATCHDOG_SM: usize = 0x0420;
    pub const WATCHDOG_STATUS: usize = 0x0440;
    pub const SII_CONFIG: usize = 0x0500;
    pub const SII_PDI: usize = 0x0501;
    pub const SII_CONTROL: usize = 0x0502;
    pub const SII_ADDRESS: usize = 0x0504;
    pub const SII_DATA: usize = 0x0508;
    pub const FMMU0: usize = 0x0600;
    pub const SM0: usize = 0x0800;
    pub const DC_START: usize = 0x0900;
    pub const DC_END: usize = 0x09FF;
}

/// AL states (low nibble of AL control and AL status).
pub mod state {
    pub const INIT: u8 = 0x01;
    pub const PREOP: u8 = 0x02;
    pub const BOOT: u8 = 0x03;
    pub const SAFEOP: u8 = 0x04;
    pub const OP: u8 = 0x08;
    pub const ERROR: u8 = 0x10;

    pub fn name(s: u8) -> &'static str {
        match s & 0x0F {
            INIT => "init",
            PREOP => "preop",
            BOOT => "boot",
            SAFEOP => "safeop",
            OP => "op",
            _ => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<u8> {
        Some(
            match s
                .trim()
                .to_ascii_lowercase()
                .replace(['-', '_', ' '], "")
                .as_str()
            {
                "init" => INIT,
                "preop" | "preoperational" => PREOP,
                "safeop" | "safeoperational" => SAFEOP,
                "op" | "operational" => OP,
                "boot" | "bootstrap" => BOOT,
                _ => return None,
            },
        )
    }

    /// INIT < PREOP < SAFEOP < OP.
    pub fn rank(s: u8) -> Option<u8> {
        match s {
            INIT => Some(0),
            PREOP => Some(1),
            SAFEOP => Some(2),
            OP => Some(3),
            _ => None,
        }
    }
}

/// AL status codes (ETG.1000.6 Table 11) the slave and the model use.
pub mod al_code {
    pub const NONE: u16 = 0x0000;
    pub const UNSPECIFIED: u16 = 0x0001;
    pub const NO_MEMORY: u16 = 0x0002;
    pub const INVALID_STATE_CHANGE: u16 = 0x0011;
    pub const UNKNOWN_STATE: u16 = 0x0012;
    pub const BOOTSTRAP_NOT_SUPPORTED: u16 = 0x0013;
    pub const INVALID_MAILBOX_CONFIG: u16 = 0x0016;
    pub const INVALID_SM_CONFIG: u16 = 0x0017;
    pub const NO_VALID_INPUTS: u16 = 0x0018;
    pub const NO_VALID_OUTPUTS: u16 = 0x0019;
    pub const SYNCHRONIZATION: u16 = 0x001A;
    pub const SM_WATCHDOG: u16 = 0x001B;
    pub const INVALID_OUTPUT_CONFIG: u16 = 0x001D;
    pub const INVALID_INPUT_CONFIG: u16 = 0x001E;
    pub const INVALID_WATCHDOG_CONFIG: u16 = 0x001F;
    pub const NEEDS_COLD_START: u16 = 0x0020;
    pub const NEEDS_INIT: u16 = 0x0021;
    pub const NEEDS_PREOP: u16 = 0x0022;
    pub const NEEDS_SAFEOP: u16 = 0x0023;
    pub const INVALID_INPUT_MAPPING: u16 = 0x0024;
    pub const INVALID_OUTPUT_MAPPING: u16 = 0x0025;
    pub const INCONSISTENT_SETTINGS: u16 = 0x0026;
    pub const APPLICATION_CONTROLLER: u16 = 0x0050;

    /// The names the model may refuse a transition with.
    pub const NAMES: &[(&str, u16)] = &[
        ("unspecified_error", UNSPECIFIED),
        ("no_memory", NO_MEMORY),
        ("invalid_state_change", INVALID_STATE_CHANGE),
        ("invalid_sync_manager_configuration", INVALID_SM_CONFIG),
        ("no_valid_inputs", NO_VALID_INPUTS),
        ("no_valid_outputs", NO_VALID_OUTPUTS),
        ("synchronization_error", SYNCHRONIZATION),
        ("invalid_output_configuration", INVALID_OUTPUT_CONFIG),
        ("invalid_input_configuration", INVALID_INPUT_CONFIG),
        ("needs_cold_start", NEEDS_COLD_START),
        ("needs_init", NEEDS_INIT),
        ("needs_preop", NEEDS_PREOP),
        ("needs_safeop", NEEDS_SAFEOP),
        ("invalid_input_mapping", INVALID_INPUT_MAPPING),
        ("invalid_output_mapping", INVALID_OUTPUT_MAPPING),
        ("inconsistent_settings", INCONSISTENT_SETTINGS),
        ("application_controller_available", APPLICATION_CONTROLLER),
    ];

    pub fn text(code: u16) -> &'static str {
        match code {
            NONE => "no error",
            UNSPECIFIED => "unspecified error",
            NO_MEMORY => "no memory",
            INVALID_STATE_CHANGE => "invalid requested state change",
            UNKNOWN_STATE => "unknown requested state",
            BOOTSTRAP_NOT_SUPPORTED => "bootstrap not supported",
            INVALID_MAILBOX_CONFIG => "invalid mailbox configuration",
            INVALID_SM_CONFIG => "invalid sync manager configuration",
            NO_VALID_INPUTS => "no valid inputs available",
            NO_VALID_OUTPUTS => "no valid outputs",
            SYNCHRONIZATION => "synchronization error",
            SM_WATCHDOG => "sync manager watchdog",
            INVALID_OUTPUT_CONFIG => "invalid output configuration",
            INVALID_INPUT_CONFIG => "invalid input configuration",
            INVALID_WATCHDOG_CONFIG => "invalid watchdog configuration",
            NEEDS_COLD_START => "slave needs cold start",
            NEEDS_INIT => "slave needs INIT",
            NEEDS_PREOP => "slave needs PREOP",
            NEEDS_SAFEOP => "slave needs SAFEOP",
            INVALID_INPUT_MAPPING => "invalid input mapping",
            INVALID_OUTPUT_MAPPING => "invalid output mapping",
            INCONSISTENT_SETTINGS => "inconsistent settings",
            APPLICATION_CONTROLLER => "application controller available",
            _ => "vendor or reserved code",
        }
    }
}

/// What the slave's "firmware" has to settle after a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscEvent {
    /// The master asked for an upward transition that passed every structural check; the
    /// model decides. The AL status stays at `from` until then.
    StateRequest { from: u8, to: u8 },
    /// A transition that happened without the model: downward requests, which a slave must
    /// follow, and the SyncManager watchdog.
    StateChanged {
        from: u8,
        to: u8,
        code: u16,
        cause: String,
    },
    /// A transition refused by the slave itself (AL status error bit and code set).
    StateRefused {
        from: u8,
        to: u8,
        code: u16,
        why: String,
    },
    /// The master filled the receive mailbox: its whole SyncManager area.
    Mailbox(Vec<u8>),
    /// The master completed the output buffer.
    Outputs(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
struct Sm {
    start: usize,
    len: usize,
    control: u8,
    enabled: bool,
    repeat: bool,
}

impl Sm {
    fn mailbox(&self) -> bool {
        self.control & 0x03 == 0x02
    }
    fn ecat_writes(&self) -> bool {
        (self.control >> 2) & 0x03 == 0x01
    }
    fn covers(&self, addr: usize, len: usize) -> bool {
        self.enabled && self.len > 0 && addr < self.start + self.len && self.start < addr + len
    }
    fn last_covered(&self, addr: usize, len: usize) -> bool {
        addr <= self.start + self.len - 1 && self.start + self.len - 1 < addr + len
    }
}

#[derive(Debug, Clone, Copy)]
struct Fmmu {
    log_start_bit: u64,
    log_end_bit: u64,
    phys_start_bit: u64,
    read: bool,
    write: bool,
}

pub struct Esc {
    pub position: usize,
    pub chain_len: usize,
    pub device: DeviceSpec,
    pub layout: Layout,
    mem: Vec<u8>,
    sii: Vec<u8>,
    al_state: u8,
    al_error: bool,
    al_code: u16,
    /// An upward transition waiting for the model.
    pending: Option<u8>,
    pdi_deactivated: [bool; NUM_SM],
    repeat_ack: [bool; NUM_SM],
    full: [bool; NUM_SM],
    sii_errors: u16,
    queue: VecDeque<Vec<u8>>,
    last_reply: Option<Vec<u8>>,
    /// The model has set the inputs at least once.
    pub inputs_valid: bool,
    /// Outputs arrived since the slave entered SAFE-OP.
    outputs_seen: bool,
    last_output: Option<Instant>,
    events: Vec<EscEvent>,
    pub mailbox_dropped: u64,
}

fn u16_at(m: &[u8], a: usize) -> u16 {
    u16::from_le_bytes([m[a], m[a + 1]])
}

fn put16(m: &mut [u8], a: usize, v: u16) {
    m[a..a + 2].copy_from_slice(&v.to_le_bytes());
}

/// Bytes the master may not change.
fn ecat_writable(addr: usize) -> bool {
    match addr {
        0x0000..=0x000F | 0x0012..=0x0013 | 0x0110..=0x0111 | 0x0130..=0x0137 => false,
        0x0140..=0x01FF | 0x0204..=0x0213 | 0x0440..=0x0443 | 0x0501 => false,
        0x0E00..=0x0EFF => false,
        reg::DC_START..=reg::DC_END => false,
        a if (reg::SM0..reg::SM0 + 8 * NUM_SM).contains(&a) => !matches!((a - reg::SM0) % 8, 5 | 7),
        _ => true,
    }
}

impl Esc {
    pub fn new(position: usize, chain_len: usize, device: DeviceSpec, mailbox: usize) -> Self {
        let layout = Layout::for_device(&device, mailbox);
        let sii = sii::build(&device, &layout);
        let mut mem = vec![0u8; MEMORY];
        mem[reg::TYPE] = 0x04; // the code Beckhoff's ESC IP core reports; this is software
        mem[reg::REVISION] = 0x01;
        put16(&mut mem, reg::BUILD, 0x0001);
        mem[reg::FMMUS] = NUM_FMMU as u8;
        mem[reg::SYNC_MANAGERS] = NUM_SM as u8;
        mem[reg::RAM_SIZE] = (RAM_BYTES / 1024) as u8;
        mem[reg::PORT_DESCRIPTOR] = 0x0F; // ports 0 and 1: MII; 2 and 3 not implemented
        put16(&mut mem, reg::FEATURES, 0x0000); // no distributed clocks
        put16(&mut mem, reg::STATION_ALIAS, device.alias);
        put16(&mut mem, reg::PDI_CONTROL, 0x0005);
        put16(&mut mem, reg::WATCHDOG_DIVIDER, 2498); // 100 µs
        put16(&mut mem, reg::WATCHDOG_PDI, 1000);
        put16(&mut mem, reg::WATCHDOG_SM, 1000); // 100 ms
        put16(&mut mem, reg::AL_CONTROL, state::INIT as u16);
        let mut esc = Esc {
            position,
            chain_len,
            device,
            layout,
            mem,
            sii,
            al_state: state::INIT,
            al_error: false,
            al_code: 0,
            pending: None,
            pdi_deactivated: [true; NUM_SM],
            repeat_ack: [false; NUM_SM],
            full: [false; NUM_SM],
            sii_errors: 0,
            queue: VecDeque::new(),
            last_reply: None,
            inputs_valid: false,
            outputs_seen: false,
            last_output: None,
            events: Vec::new(),
            mailbox_dropped: 0,
        };
        // A slave with no inputs has nothing to fabricate, so it has nothing to wait for.
        esc.inputs_valid = esc.device.inputs.is_empty();
        esc.apply_pdi();
        esc
    }

    pub fn sii(&self) -> &[u8] {
        &self.sii
    }

    pub fn al_state(&self) -> u8 {
        self.al_state
    }

    pub fn al_error(&self) -> Option<u16> {
        self.al_error.then_some(self.al_code)
    }

    pub fn station_address(&self) -> u16 {
        u16_at(&self.mem, reg::STATION_ADDRESS)
    }

    pub fn pending_transition(&self) -> Option<u8> {
        self.pending
    }

    pub fn take_events(&mut self) -> Vec<EscEvent> {
        std::mem::take(&mut self.events)
    }

    fn sm(&self, i: usize) -> Sm {
        let b = reg::SM0 + 8 * i;
        Sm {
            start: u16_at(&self.mem, b) as usize,
            len: u16_at(&self.mem, b + 2) as usize,
            control: self.mem[b + 4],
            enabled: self.mem[b + 6] & 0x01 != 0,
            repeat: self.mem[b + 6] & 0x02 != 0,
        }
    }

    fn fmmus(&self) -> Vec<Fmmu> {
        (0..NUM_FMMU)
            .filter_map(|i| {
                let b = reg::FMMU0 + 16 * i;
                let m = &self.mem[b..b + 16];
                let active = m[12] & 0x01 != 0;
                let len = u16::from_le_bytes([m[4], m[5]]) as u64;
                if !active || len == 0 || m[11] & 0x03 == 0 {
                    return None;
                }
                let lstart = u32::from_le_bytes([m[0], m[1], m[2], m[3]]) as u64;
                Some(Fmmu {
                    log_start_bit: lstart * 8 + (m[6] & 7) as u64,
                    log_end_bit: (lstart + len - 1) * 8 + (m[7] & 7) as u64,
                    phys_start_bit: u16::from_le_bytes([m[8], m[9]]) as u64 * 8
                        + (m[10] & 7) as u64,
                    read: m[11] & 0x01 != 0,
                    write: m[11] & 0x02 != 0,
                })
            })
            .collect()
    }

    /// SyncManager rules for an access of `len` octets at `addr`.
    fn allowed(&self, addr: usize, len: usize, write: bool) -> bool {
        if len == 0 {
            return true;
        }
        if addr + len > self.mem.len() {
            return false;
        }
        for i in 0..NUM_SM {
            let s = self.sm(i);
            if !s.covers(addr, len) {
                continue;
            }
            if self.pdi_deactivated[i] || s.ecat_writes() != write {
                return false;
            }
            if s.mailbox() && (write == self.full[i]) {
                // A write to a full receive mailbox, or a read of an empty send mailbox.
                return false;
            }
        }
        true
    }

    fn after_access(&mut self, addr: usize, len: usize, write: bool) {
        for i in 0..NUM_SM {
            let s = self.sm(i);
            if !s.covers(addr, len) || !s.last_covered(addr, len) {
                continue;
            }
            let area = self.mem[s.start..s.start + s.len].to_vec();
            match (s.mailbox(), write) {
                (true, true) => {
                    self.full[i] = true;
                    self.events.push(EscEvent::Mailbox(area));
                }
                (true, false) => {
                    self.full[i] = false;
                    self.load_queued();
                }
                (false, true) => {
                    if self.al_state == state::SAFEOP || self.al_state == state::OP {
                        self.outputs_seen = true;
                        self.last_output = Some(Instant::now());
                        self.events.push(EscEvent::Outputs(area));
                    }
                }
                (false, false) => {}
            }
        }
    }

    /// The engine has read the receive mailbox (it does so after every frame).
    pub fn mailbox_consumed(&mut self) {
        for i in 0..NUM_SM {
            let s = self.sm(i);
            if s.mailbox() && s.ecat_writes() {
                self.full[i] = false;
            }
        }
    }

    fn send_mailbox_index(&self) -> Option<usize> {
        (0..NUM_SM).find(|&i| {
            let s = self.sm(i);
            s.enabled && s.len > 0 && s.mailbox() && !s.ecat_writes() && !self.pdi_deactivated[i]
        })
    }

    fn load_queued(&mut self) {
        let Some(i) = self.send_mailbox_index() else {
            return;
        };
        if self.full[i] {
            return;
        }
        if let Some(m) = self.queue.pop_front() {
            self.load_into(i, m);
        }
    }

    fn load_into(&mut self, i: usize, mut m: Vec<u8>) {
        let s = self.sm(i);
        if s.start + s.len > self.mem.len() {
            // The master put the send mailbox outside the memory; there is nowhere to put it.
            self.mailbox_dropped += 1;
            return;
        }
        m.resize(s.len, 0);
        self.mem[s.start..s.start + s.len].copy_from_slice(&m);
        self.full[i] = true;
        self.last_reply = Some(m);
    }

    /// Put a reply (a whole encoded mailbox) where the master reads it: in the send mailbox if it
    /// is empty, otherwise queued behind what is there.
    pub fn post_mailbox(&mut self, m: Vec<u8>) {
        if self.queue.len() >= MAILBOX_QUEUE {
            self.queue.pop_front();
            self.mailbox_dropped += 1;
        }
        self.queue.push_back(m);
        self.load_queued();
    }

    /// The size of the send mailbox the master configured (the reply must fit it).
    pub fn send_mailbox_len(&self) -> usize {
        self.send_mailbox_index()
            .map(|i| self.sm(i).len)
            .unwrap_or(self.layout.mailbox)
    }

    /// Write the input image (the model's values, encoded by the caller).
    pub fn set_inputs(&mut self, image: &[u8]) {
        let s = self.layout.sm[3];
        let n = image.len().min(s.length as usize);
        let at = s.start as usize;
        self.mem[at..at + n].copy_from_slice(&image[..n]);
        self.inputs_valid = true;
    }

    pub fn input_image(&self) -> Vec<u8> {
        let s = self.layout.sm[3];
        self.mem[s.start as usize..s.start as usize + s.length as usize].to_vec()
    }

    fn apply_pdi(&mut self) {
        let st = self.al_state;
        for (i, c) in self.layout.sm.iter().enumerate() {
            let on = match c.sm_type {
                sii::sm_type::MAILBOX_OUT | sii::sm_type::MAILBOX_IN => st != state::INIT,
                _ => st == state::SAFEOP || st == state::OP,
            };
            self.pdi_deactivated[i] = !on;
        }
        if st == state::INIT {
            self.full = [false; NUM_SM];
            self.queue.clear();
            self.last_reply = None;
        }
    }

    fn set_state(&mut self, to: u8) {
        let from = self.al_state;
        self.al_state = to;
        if to == state::SAFEOP && from != state::OP {
            self.outputs_seen = false;
        }
        if to != state::OP {
            self.last_output = None;
        }
        self.apply_pdi();
    }

    fn refuse(&mut self, to: u8, code: u16, why: String) {
        self.pending = None;
        self.al_error = true;
        self.al_code = code;
        self.events.push(EscEvent::StateRefused {
            from: self.al_state,
            to,
            code,
            why,
        });
    }

    fn check_sm(&self, i: usize, want_control: u8) -> Result<(), String> {
        let c = self.layout.sm[i];
        let s = self.sm(i);
        if s.start != c.start as usize || s.len != c.length as usize {
            return Err(format!(
                "SM{i} is {:#06x}+{} where the SII says {:#06x}+{}",
                s.start, s.len, c.start, c.length
            ));
        }
        if s.control & 0x0F != want_control {
            return Err(format!(
                "SM{i} control {:#04x} is not the {} the SII says",
                s.control,
                match want_control {
                    0x06 => "mailbox, master writes",
                    0x02 => "mailbox, master reads",
                    0x04 => "buffered, master writes",
                    _ => "buffered, master reads",
                }
            ));
        }
        if !s.enabled {
            return Err(format!("SM{i} is not enabled"));
        }
        Ok(())
    }

    fn on_al_control(&mut self) {
        let v = u16_at(&self.mem, reg::AL_CONTROL);
        let to = (v & 0x0F) as u8;
        let ack = v & 0x10 != 0;
        if self.al_error && !ack {
            // An error indication must be acknowledged before any request is followed.
            return;
        }
        if ack {
            self.al_error = false;
            self.al_code = 0;
        }
        let from = self.al_state;
        if to == from {
            self.pending = None;
            return;
        }
        if to == state::BOOT {
            self.refuse(
                to,
                al_code::BOOTSTRAP_NOT_SUPPORTED,
                "this slave has no bootstrap mode".into(),
            );
            return;
        }
        let (Some(rf), Some(rt)) = (state::rank(from), state::rank(to)) else {
            self.refuse(to, al_code::UNKNOWN_STATE, format!("state {to:#x}"));
            return;
        };
        if rt < rf {
            // Downward requests are always followed, at once.
            self.pending = None;
            self.set_state(to);
            self.events.push(EscEvent::StateChanged {
                from,
                to,
                code: 0,
                cause: "requested by the master".into(),
            });
            return;
        }
        if rt != rf + 1 {
            self.refuse(
                to,
                al_code::INVALID_STATE_CHANGE,
                format!("{} to {} skips a state", state::name(from), state::name(to)),
            );
            return;
        }
        if self.pending == Some(to) {
            return;
        }
        let check = match to {
            state::PREOP => self
                .check_sm(0, 0x06)
                .and_then(|_| self.check_sm(1, 0x02))
                .map_err(|e| (al_code::INVALID_MAILBOX_CONFIG, e)),
            state::SAFEOP => {
                let mut r = Ok(());
                if !self.device.outputs.is_empty() {
                    r = self
                        .check_sm(2, 0x04)
                        .map_err(|e| (al_code::INVALID_OUTPUT_CONFIG, e));
                }
                if r.is_ok() && !self.device.inputs.is_empty() {
                    r = self
                        .check_sm(3, 0x00)
                        .map_err(|e| (al_code::INVALID_INPUT_CONFIG, e));
                }
                r
            }
            state::OP => {
                if !self.device.outputs.is_empty() && !self.outputs_seen {
                    Err((
                        al_code::NO_VALID_OUTPUTS,
                        "no output frame arrived in SAFE-OP".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        };
        if let Err((code, why)) = check {
            self.refuse(to, code, why);
            return;
        }
        self.pending = Some(to);
        self.events.push(EscEvent::StateRequest { from, to });
    }

    /// Settle a pending upward transition: `Ok` to take it, `Err(code)` to refuse it. A decision
    /// for a request the master has since replaced is ignored (returns false).
    pub fn resolve_transition(&mut self, to: u8, decision: Result<(), u16>) -> bool {
        if self.pending != Some(to) {
            return false;
        }
        match decision {
            Ok(()) => {
                if to == state::SAFEOP && !self.inputs_valid {
                    self.refuse(
                        to,
                        al_code::NO_VALID_INPUTS,
                        "the inputs were never set, and a slave does not invent them".into(),
                    );
                    return true;
                }
                self.pending = None;
                self.set_state(to);
            }
            Err(code) => {
                let why = al_code::text(code).to_string();
                self.refuse(to, code, why);
            }
        }
        true
    }

    /// The SyncManager watchdog: in OP, outputs must keep coming.
    pub fn check_watchdog(&mut self, now: Instant) {
        if self.al_state != state::OP || self.device.outputs.is_empty() {
            return;
        }
        let s = self.sm(2);
        if s.control & 0x40 == 0 {
            return;
        }
        let div = u16_at(&self.mem, reg::WATCHDOG_DIVIDER) as u64;
        let ticks = u16_at(&self.mem, reg::WATCHDOG_SM) as u64;
        if ticks == 0 {
            return;
        }
        let limit = std::time::Duration::from_nanos((div + 2) * 40 * ticks);
        let Some(last) = self.last_output else {
            self.last_output = Some(now);
            return;
        };
        if now.duration_since(last) > limit {
            self.set_state(state::SAFEOP);
            self.al_error = true;
            self.al_code = al_code::SM_WATCHDOG;
            self.events.push(EscEvent::StateChanged {
                from: state::OP,
                to: state::SAFEOP,
                code: al_code::SM_WATCHDOG,
                cause: format!("no outputs for {} ms", limit.as_millis()),
            });
        }
    }

    fn on_sii_command(&mut self) {
        let w = u16_at(&self.mem, reg::SII_CONTROL);
        let command = (w >> 8) & 0x07;
        self.sii_errors = 0;
        match command {
            0 => {}
            1 => {
                let word = u32::from_le_bytes([
                    self.mem[reg::SII_ADDRESS],
                    self.mem[reg::SII_ADDRESS + 1],
                    self.mem[reg::SII_ADDRESS + 2],
                    self.mem[reg::SII_ADDRESS + 3],
                ]) as usize;
                for k in 0..8 {
                    self.mem[reg::SII_DATA + k] = word
                        .checked_mul(2)
                        .and_then(|b| self.sii.get(b + k))
                        .copied()
                        .unwrap_or(0xFF);
                }
            }
            4 => {
                let alias = u16::from_le_bytes([self.sii[8], self.sii[9]]);
                put16(&mut self.mem, reg::STATION_ALIAS, alias);
            }
            // The SII is read-only: a write is refused as a command error.
            _ => self.sii_errors = 1 << 13,
        }
    }

    fn on_sm_activate(&mut self, i: usize, old: u8) {
        let new = self.mem[reg::SM0 + 8 * i + 6];
        let s = self.sm(i);
        if old & 0x01 == 0 && new & 0x01 != 0 {
            self.full[i] = false;
            if s.mailbox() && !s.ecat_writes() {
                self.load_queued();
            }
        }
        if s.mailbox() && !s.ecat_writes() && (old ^ new) & 0x02 != 0 {
            // Repeat request: hand the last reply back and acknowledge.
            if let Some(m) = self.last_reply.clone() {
                self.load_into(i, m);
            }
            self.repeat_ack[i] = s.repeat;
        }
    }

    fn refresh(&mut self) {
        let mut dl: u16 = 0x0001 | 0x0010 | 0x0200; // PDI operational, port 0 link + communication
        if self.position + 1 < self.chain_len {
            dl |= 0x0020 | 0x0800; // port 1 link + communication
        } else {
            dl |= 0x0400; // port 1 loop closed
        }
        dl |= 0x1000 | 0x4000; // ports 2 and 3 closed
        put16(&mut self.mem, reg::DL_STATUS, dl);
        let st = self.al_state as u16 | if self.al_error { 0x10 } else { 0 };
        put16(&mut self.mem, reg::AL_STATUS, st);
        put16(&mut self.mem, reg::AL_STATUS_CODE, self.al_code);
        let ctl: u16 = 0x0040 | self.sii_errors; // 8-octet reads, never busy
        let keep = u16_at(&self.mem, reg::SII_CONTROL) & 0x0001;
        put16(&mut self.mem, reg::SII_CONTROL, ctl | keep);
        self.mem[reg::SII_PDI] = 0;
        for i in 0..NUM_SM {
            let s = self.sm(i);
            let b = reg::SM0 + 8 * i;
            self.mem[b + 5] = if s.mailbox() && self.full[i] {
                0x08 | if s.ecat_writes() { 0x01 } else { 0x02 }
            } else {
                0
            };
            self.mem[b + 7] = self.pdi_deactivated[i] as u8 | (self.repeat_ack[i] as u8) << 1;
        }
        let mut wd = 0u16;
        if self.al_state == state::OP && self.last_output.is_some() {
            wd = 1;
        }
        put16(&mut self.mem, reg::WATCHDOG_STATUS, wd);
    }

    /// Read `len` octets at `addr` for the master, if the SyncManagers allow it.
    fn read(&mut self, addr: usize, len: usize) -> Option<Vec<u8>> {
        if !self.allowed(addr, len, false) {
            return None;
        }
        if addr < 0x1000 {
            self.refresh();
        }
        let out = self.mem[addr..addr + len].to_vec();
        self.after_access(addr, len, false);
        Some(out)
    }

    /// Write for the master, if the SyncManagers allow it.
    fn write(&mut self, addr: usize, data: &[u8]) -> bool {
        let len = data.len();
        if !self.allowed(addr, len, true) {
            return false;
        }
        let activates: Vec<(usize, u8)> = (0..NUM_SM)
            .map(|i| (i, self.mem[reg::SM0 + 8 * i + 6]))
            .collect();
        for (k, b) in data.iter().enumerate() {
            let a = addr + k;
            if a >= 0x1000 || ecat_writable(a) {
                self.mem[a] = *b;
            }
        }
        let touched = |a: usize| addr <= a && a < addr + len;
        if touched(reg::AL_CONTROL) {
            self.on_al_control();
        }
        if touched(reg::SII_CONTROL) || touched(reg::SII_CONTROL + 1) {
            self.on_sii_command();
        }
        for (i, old) in activates {
            if touched(reg::SM0 + 8 * i + 6) {
                self.on_sm_activate(i, old);
            }
        }
        self.after_access(addr, len, true);
        true
    }

    fn addressed_fixed(&self, adp: u16) -> bool {
        if adp == self.station_address() {
            return true;
        }
        let alias_on = self.mem[reg::DL_CONTROL + 3] & 0x01 != 0;
        alias_on && adp == u16_at(&self.mem, reg::STATION_ALIAS) && adp != 0
    }

    /// Process one datagram of a frame passing this slave: change its data and working counter
    /// in `buf`, and its position address where the command says each slave increments it.
    pub fn process(&mut self, buf: &mut [u8], d: &DatagramAt) {
        let c = d.cmd;
        let adp = d.adp(buf);
        let ado = d.ado(buf) as usize;
        let (data_at, len) = (d.data, d.len);
        let incoming = buf[data_at..data_at + len].to_vec();
        let mut inc: u16 = 0;
        match c {
            cmd::APRD | cmd::APWR | cmd::APRW | cmd::ARMW | cmd::BRD | cmd::BWR | cmd::BRW => {
                d.set_adp(buf, adp.wrapping_add(1));
            }
            _ => {}
        }
        match c {
            cmd::APRD | cmd::FPRD | cmd::BRD => {
                let me = match c {
                    cmd::APRD => adp == 0,
                    cmd::FPRD => self.addressed_fixed(adp),
                    _ => true,
                };
                if me {
                    if let Some(v) = self.read(ado, len) {
                        let out = &mut buf[data_at..data_at + len];
                        if c == cmd::BRD {
                            out.iter_mut().zip(&v).for_each(|(o, b)| *o |= b);
                        } else {
                            out.copy_from_slice(&v);
                        }
                        inc = 1;
                    }
                }
            }
            cmd::APWR | cmd::FPWR | cmd::BWR => {
                let me = match c {
                    cmd::APWR => adp == 0,
                    cmd::FPWR => self.addressed_fixed(adp),
                    _ => true,
                };
                if me && self.write(ado, &incoming) {
                    inc = 1;
                }
            }
            cmd::APRW | cmd::FPRW | cmd::BRW => {
                let me = match c {
                    cmd::APRW => adp == 0,
                    cmd::FPRW => self.addressed_fixed(adp),
                    _ => true,
                };
                if me {
                    if let Some(v) = self.read(ado, len) {
                        let out = &mut buf[data_at..data_at + len];
                        if c == cmd::BRW {
                            out.iter_mut().zip(&v).for_each(|(o, b)| *o |= b);
                        } else {
                            out.copy_from_slice(&v);
                        }
                        inc += 1;
                    }
                    if self.write(ado, &incoming) {
                        inc += 2;
                    }
                }
            }
            cmd::ARMW | cmd::FRMW => {
                let me = if c == cmd::ARMW {
                    adp == 0
                } else {
                    self.addressed_fixed(adp)
                };
                if me {
                    if let Some(v) = self.read(ado, len) {
                        buf[data_at..data_at + len].copy_from_slice(&v);
                        inc = 1;
                    }
                } else if self.write(ado, &incoming) {
                    inc = 1;
                }
            }
            cmd::LRD | cmd::LWR | cmd::LRW => {
                inc = self.logical(c, d.logical(buf), buf, data_at, len, &incoming);
            }
            _ => {}
        }
        if inc > 0 {
            d.set_wkc(buf, d.wkc(buf).wrapping_add(inc));
        }
    }

    fn logical(
        &mut self,
        c: u8,
        lad: u32,
        buf: &mut [u8],
        data_at: usize,
        len: usize,
        incoming: &[u8],
    ) -> u16 {
        if len == 0 {
            return 0;
        }
        let dg_lo = lad as u64 * 8;
        let dg_hi = dg_lo + len as u64 * 8 - 1;
        let mut read_ok = false;
        let mut write_ok = false;
        for f in self.fmmus() {
            let lo = f.log_start_bit.max(dg_lo);
            let hi = f.log_end_bit.min(dg_hi);
            if lo > hi {
                continue;
            }
            let bits = (hi - lo + 1) as usize;
            let phys_lo = f.phys_start_bit + (lo - f.log_start_bit);
            let phys_hi = phys_lo + bits as u64 - 1;
            let (pa, pb) = ((phys_lo / 8) as usize, (phys_hi / 8) as usize);
            let plen = pb - pa + 1;
            let dg_bit = (lo - dg_lo) as usize;
            let phys_bit_in = (phys_lo % 8) as usize;
            if f.read && (c == cmd::LRD || c == cmd::LRW) {
                if let Some(v) = self.read(pa, plen) {
                    let bits_v = get_bits(&v, phys_bit_in, bits);
                    put_bits(&mut buf[data_at..data_at + len], dg_bit, bits, &bits_v);
                    read_ok = true;
                }
            }
            if f.write && (c == cmd::LWR || c == cmd::LRW) {
                if self.allowed(pa, plen, true) {
                    let mut cur = self.mem[pa..pa + plen].to_vec();
                    let src = get_bits(incoming, dg_bit, bits);
                    put_bits(&mut cur, phys_bit_in, bits, &src);
                    if self.write(pa, &cur) {
                        write_ok = true;
                    }
                }
            }
        }
        let mut inc = 0;
        if read_ok {
            inc += 1;
        }
        if write_ok {
            inc += if c == cmd::LRW { 2 } else { 1 };
        }
        inc
    }
}

/// Run a frame (an EtherCAT payload, header first) through a chain of slaves in order, in
/// place. Returns the number of datagrams processed.
pub fn process_frame(chain: &mut [Esc], buf: &mut [u8]) -> Result<usize, frame::FrameError> {
    let ds = frame::parse(buf)?;
    for esc in chain.iter_mut() {
        for d in &ds {
            esc.process(buf, d);
        }
    }
    Ok(ds.len())
}
