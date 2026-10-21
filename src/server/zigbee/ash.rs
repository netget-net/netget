//! ASH, the Asynchronous Serial Host protocol (Silicon Labs UG101) that carries EZSP between a
//! Zigbee host and its network co-processor: byte stuffing around the flag, CANCEL and
//! SUBSTITUTE handling, data-field randomisation, CRC-CCITT, the control byte of each frame
//! type, and the NCP's side of the link (frame and acknowledgement numbers, the retransmit
//! window and its adaptive timer, NAKs, RST/RSTACK and the ERROR frame of the failed state).
//!
//! Everything here is pure and synchronous; `mod.rs` drives the timers.
use std::collections::VecDeque;
use std::time::Duration;

pub const FLAG: u8 = 0x7E;
pub const ESCAPE: u8 = 0x7D;
pub const XON: u8 = 0x11;
pub const XOFF: u8 = 0x13;
pub const SUBSTITUTE: u8 = 0x18;
pub const CANCEL: u8 = 0x1A;
/// Sent by a host to wake a sleeping NCP; ignored between frames.
pub const WAKE: u8 = 0xFF;
const FLIP: u8 = 0x20;
const RESERVED: [u8; 6] = [FLAG, ESCAPE, XON, XOFF, SUBSTITUTE, CANCEL];

/// ASH version carried in RSTACK and ERROR.
pub const VERSION: u8 = 0x02;
/// The largest EZSP frame a DATA frame carries (EZSP's 218-byte maximum plus the two bytes
/// the extended frame format adds), which is also what both open hosts allocate for one.
pub const MAX_DATA: usize = 220;
/// The smallest EZSP frame: sequence, frame control and a legacy frame id.
pub const MIN_DATA: usize = 3;
/// Control byte, data field and CRC: the longest frame there is, after unstuffing.
pub const MAX_FRAME: usize = 1 + MAX_DATA + 2;

/// Reset and failure reasons an RSTACK or ERROR frame reports (`NcpResetCode`).
pub mod reset {
    pub const SOFTWARE: u8 = 0x0B;
    pub const EXCEEDED_MAXIMUM_ACK_TIMEOUT_COUNT: u8 = 0x51;
}

/// How long the NCP waits for its DATA frame to be acknowledged before retransmitting, and the
/// bounds the adaptive timer stays within (UG101 §3.6: 1.6 s initially, 0.4 to 3.2 s).
pub const T_RX_ACK_INIT: Duration = Duration::from_millis(1600);
pub const T_RX_ACK_MIN: Duration = Duration::from_millis(400);
pub const T_RX_ACK_MAX: Duration = Duration::from_millis(3200);
/// Consecutive acknowledgement timeouts after which the NCP enters the failed state.
pub const ACK_TIMEOUTS: u32 = 4;
/// DATA frames the NCP sends before waiting for an acknowledgement.
pub const TX_WINDOW: usize = 3;
/// A host's nRdy holds callbacks back for this long at most (UG101's T_REMOTE_NOTRDY).
pub const T_REMOTE_NOTRDY: Duration = Duration::from_millis(1000);
/// How long a reset takes: an RST arriving while the NCP is still rebooting from the last one
/// is lost with the rest of the UART's input, as on a real chip. bellows sends three RSTs back
/// to back and expects one RSTACK.
pub const T_REBOOT: Duration = Duration::from_millis(250);

/// CRC-CCITT as ASH computes it: polynomial 0x1021, initial value 0xFFFF, no reflection,
/// transmitted high byte first.
pub fn crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// XOR a DATA frame's data field with ASH's pseudo-random sequence (an LFSR seeded 0x42 with
/// feedback 0xB8). Its own inverse.
pub fn randomize(data: &mut [u8]) {
    let mut rand: u8 = 0x42;
    for b in data.iter_mut() {
        *b ^= rand;
        rand = if rand & 1 == 0 {
            rand >> 1
        } else {
            (rand >> 1) ^ 0xB8
        };
    }
}

/// Escape the reserved bytes of a frame and close it with the flag.
pub fn stuff(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() * 2 + 1);
    for &b in frame {
        if RESERVED.contains(&b) {
            out.push(ESCAPE);
            out.push(b ^ FLIP);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

fn with_crc(mut body: Vec<u8>) -> Vec<u8> {
    let c = crc(&body);
    body.extend_from_slice(&c.to_be_bytes());
    body
}

/// A DATA frame on the wire: randomised data, CRC, stuffing and the flag.
pub fn data_frame(frm_num: u8, re_tx: bool, ack_num: u8, ezsp: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(ezsp.len() + 3);
    body.push(((frm_num & 7) << 4) | ((re_tx as u8) << 3) | (ack_num & 7));
    let mut data = ezsp.to_vec();
    randomize(&mut data);
    body.extend_from_slice(&data);
    stuff(&with_crc(body))
}

pub fn ack_frame(ack_num: u8, not_ready: bool) -> Vec<u8> {
    stuff(&with_crc(vec![
        0x80 | ((not_ready as u8) << 3) | (ack_num & 7),
    ]))
}

pub fn nak_frame(ack_num: u8, not_ready: bool) -> Vec<u8> {
    stuff(&with_crc(vec![
        0xA0 | ((not_ready as u8) << 3) | (ack_num & 7),
    ]))
}

/// RST, as a host sends it (after a CANCEL that discards anything half-sent).
pub fn rst_frame() -> Vec<u8> {
    let mut v = vec![CANCEL];
    v.extend(stuff(&with_crc(vec![0xC0])));
    v
}

pub fn rstack_frame(code: u8) -> Vec<u8> {
    stuff(&with_crc(vec![0xC1, VERSION, code]))
}

pub fn error_frame(code: u8) -> Vec<u8> {
    stuff(&with_crc(vec![0xC2, VERSION, code]))
}

/// One frame received from the host, its CRC checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        frm_num: u8,
        re_tx: bool,
        ack_num: u8,
        ezsp: Vec<u8>,
    },
    Ack {
        not_ready: bool,
        ack_num: u8,
    },
    Nak {
        not_ready: bool,
        ack_num: u8,
    },
    Rst,
    /// RSTACK and ERROR are NCP-to-host frames; a host sending one is a protocol error.
    Unexpected(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadCrc,
    BadControl,
    BadLength,
}

impl Frame {
    /// Decode an unstuffed frame (control byte, data, CRC).
    pub fn parse(raw: &[u8]) -> Result<Frame, FrameError> {
        if raw.len() < 3 {
            return Err(FrameError::TooShort);
        }
        let (body, tail) = raw.split_at(raw.len() - 2);
        if crc(body) != u16::from_be_bytes([tail[0], tail[1]]) {
            return Err(FrameError::BadCrc);
        }
        let control = body[0];
        let data = &body[1..];
        if control & 0x80 == 0 {
            if data.len() < MIN_DATA || data.len() > MAX_DATA {
                return Err(FrameError::BadLength);
            }
            let mut ezsp = data.to_vec();
            randomize(&mut ezsp);
            return Ok(Frame::Data {
                frm_num: (control >> 4) & 7,
                re_tx: control & 0x08 != 0,
                ack_num: control & 7,
                ezsp,
            });
        }
        let short = |f: Frame| {
            if data.is_empty() {
                Ok(f)
            } else {
                Err(FrameError::BadLength)
            }
        };
        match control & 0xE0 {
            0x80 => short(Frame::Ack {
                not_ready: control & 0x08 != 0,
                ack_num: control & 7,
            }),
            0xA0 => short(Frame::Nak {
                not_ready: control & 0x08 != 0,
                ack_num: control & 7,
            }),
            _ => match control {
                0xC0 => short(Frame::Rst),
                0xC1 | 0xC2 => Ok(Frame::Unexpected(control)),
                _ => Err(FrameError::BadControl),
            },
        }
    }
}

/// What the deframer produced from the bytes it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deframed {
    /// A complete unstuffed frame, not yet checked.
    Frame(Vec<u8>),
    /// A frame that grew past [`MAX_FRAME`]; its bytes up to the next flag are discarded.
    TooLong,
    /// An escape followed by a byte that is not a reserved byte flipped, or a SUBSTITUTE
    /// (a byte the UART could not receive): the frame was discarded.
    Corrupt,
    /// A CANCEL: the frame in progress was discarded.
    Cancelled,
}

/// Splits the byte stream at flags, undoing the stuffing as it goes. Holds at most
/// [`MAX_FRAME`] bytes whatever the peer sends.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    escaped: bool,
    /// Discarding until the next flag (overlong, corrupt or substituted frame).
    discarding: bool,
}

impl Deframer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Deframed>) {
        for &b in bytes {
            match b {
                FLAG => {
                    if self.discarding {
                        // Already reported when the frame was cut off.
                    } else if self.escaped {
                        out.push(Deframed::Corrupt);
                    } else if !self.buf.is_empty() {
                        out.push(Deframed::Frame(std::mem::take(&mut self.buf)));
                    }
                    self.reset();
                }
                CANCEL => {
                    if !self.buf.is_empty() || self.escaped || self.discarding {
                        out.push(Deframed::Cancelled);
                    }
                    self.reset();
                }
                SUBSTITUTE => {
                    if !self.discarding {
                        out.push(Deframed::Corrupt);
                    }
                    self.buf.clear();
                    self.escaped = false;
                    self.discarding = true;
                }
                XON | XOFF => {}
                WAKE if self.buf.is_empty() && !self.escaped && !self.discarding => {}
                ESCAPE if !self.discarding => {
                    if self.escaped {
                        // Two escapes in a row: the second is not a reserved byte flipped.
                        self.corrupt(out);
                    } else {
                        self.escaped = true;
                    }
                }
                _ if self.discarding => {}
                _ => {
                    let byte = if self.escaped {
                        self.escaped = false;
                        let v = b ^ FLIP;
                        if !RESERVED.contains(&v) {
                            self.corrupt(out);
                            continue;
                        }
                        v
                    } else {
                        b
                    };
                    if self.buf.len() >= MAX_FRAME {
                        // Reported at once, not at the next flag: a peer that never sends one
                        // must not be able to keep the deframer silently discarding.
                        out.push(Deframed::TooLong);
                        self.buf.clear();
                        self.discarding = true;
                        continue;
                    }
                    self.buf.push(byte);
                }
            }
        }
    }

    fn corrupt(&mut self, out: &mut Vec<Deframed>) {
        out.push(Deframed::Corrupt);
        self.buf.clear();
        self.escaped = false;
        self.discarding = true;
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.escaped = false;
        self.discarding = false;
    }

    /// Bytes held for the frame in progress.
    pub fn held(&self) -> usize {
        self.buf.len()
    }
}

/// One DATA frame the NCP sent and the host has not acknowledged.
#[derive(Debug, Clone)]
struct Outstanding {
    frm_num: u8,
    ezsp: Vec<u8>,
    sent: Option<std::time::Instant>,
    retransmitted: bool,
}

/// What the link wants written or done after an input.
#[derive(Debug, Default)]
pub struct Output {
    /// Wire bytes to write, in order.
    pub wire: Vec<u8>,
    /// EZSP frames the host delivered, in order.
    pub delivered: Vec<Vec<u8>>,
    /// The host reset the link (RST): the NCP has rebooted.
    pub reset: bool,
    /// The link entered the failed state on this input.
    pub failed: bool,
    /// The peer sent a frame longer than any ASH frame before ever resetting the link: it is
    /// not a host, and the connection is closed.
    pub close: bool,
}

/// Counters an operator or a test reads.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub rx_data: u64,
    pub rx_bad_crc: u64,
    pub rx_too_long: u64,
    pub rx_corrupt: u64,
    pub rx_out_of_sequence: u64,
    pub rx_duplicates: u64,
    pub tx_data: u64,
    pub tx_retransmits: u64,
    pub tx_naks: u64,
}

/// The NCP's side of one ASH link.
pub struct Link {
    connected: bool,
    failed: bool,
    /// The frame number the next DATA frame from the host must carry (our ackNum).
    rx_expected: u8,
    /// A NAK was sent and no good frame has arrived since (UG101's reject condition).
    rejecting: bool,
    /// Frame number of our next new DATA frame.
    tx_next: u8,
    outstanding: VecDeque<Outstanding>,
    /// EZSP frames waiting for room in the window.
    queued: VecDeque<Vec<u8>>,
    t_rx_ack: Duration,
    timeouts: u32,
    /// The host said it is not ready, until this instant.
    not_ready_until: Option<std::time::Instant>,
    /// When the last reset began.
    rebooted_at: Option<std::time::Instant>,
    pub counters: Counters,
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

impl Link {
    pub fn new() -> Self {
        Self {
            connected: false,
            failed: false,
            rx_expected: 0,
            rejecting: false,
            tx_next: 0,
            outstanding: VecDeque::new(),
            queued: VecDeque::new(),
            t_rx_ack: T_RX_ACK_INIT,
            timeouts: 0,
            not_ready_until: None,
            rebooted_at: None,
            counters: Counters::default(),
        }
    }

    pub fn connected(&self) -> bool {
        self.connected && !self.failed
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    /// The current acknowledgement timer.
    pub fn t_rx_ack(&self) -> Duration {
        self.t_rx_ack
    }

    /// Frames sent and not yet acknowledged, and frames waiting for the window.
    pub fn backlog(&self) -> (usize, usize) {
        (self.outstanding.len(), self.queued.len())
    }

    /// When the oldest unacknowledged frame times out.
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.outstanding
            .front()
            .and_then(|o| o.sent)
            .map(|s| s + self.t_rx_ack)
    }

    fn rebooted(&mut self) {
        let counters = self.counters;
        *self = Self::new();
        self.counters = counters;
        self.connected = true;
    }

    /// Handle one deframer result.
    pub fn receive(&mut self, d: Deframed, now: std::time::Instant, out: &mut Output) {
        let raw = match d {
            Deframed::Frame(raw) => raw,
            Deframed::TooLong => {
                self.counters.rx_too_long += 1;
                if !self.connected {
                    out.close = true;
                }
                self.reject(out);
                return;
            }
            Deframed::Corrupt => {
                self.counters.rx_corrupt += 1;
                self.reject(out);
                return;
            }
            Deframed::Cancelled => return,
        };
        let frame = match Frame::parse(&raw) {
            Ok(f) => f,
            Err(FrameError::BadCrc) => {
                self.counters.rx_bad_crc += 1;
                self.reject(out);
                return;
            }
            Err(_) => {
                self.counters.rx_corrupt += 1;
                self.reject(out);
                return;
            }
        };
        if let Frame::Rst = frame {
            if self
                .rebooted_at
                .is_some_and(|t| now.saturating_duration_since(t) < T_REBOOT)
            {
                return;
            }
            self.rebooted();
            self.rebooted_at = Some(now);
            out.wire.extend(rstack_frame(reset::SOFTWARE));
            out.reset = true;
            return;
        }
        // Before the first RST, and in the failed state, everything but RST is ignored.
        if !self.connected || self.failed {
            return;
        }
        match frame {
            Frame::Data {
                frm_num,
                re_tx,
                ack_num,
                ezsp,
            } => {
                self.acknowledge(ack_num, now, out);
                if frm_num == self.rx_expected {
                    self.rx_expected = (self.rx_expected + 1) & 7;
                    self.rejecting = false;
                    self.counters.rx_data += 1;
                    out.wire.extend(ack_frame(self.rx_expected, false));
                    out.delivered.push(ezsp);
                } else if re_tx {
                    // A retransmission of a frame already accepted: acknowledge it again.
                    self.counters.rx_duplicates += 1;
                    out.wire.extend(ack_frame(self.rx_expected, false));
                } else {
                    self.counters.rx_out_of_sequence += 1;
                    self.reject(out);
                }
            }
            Frame::Ack { not_ready, ack_num } => {
                self.note_ready(not_ready, now);
                self.acknowledge(ack_num, now, out);
            }
            Frame::Nak { not_ready, ack_num } => {
                self.note_ready(not_ready, now);
                self.acknowledge(ack_num, now, out);
                self.retransmit_all(now, out);
            }
            Frame::Rst => unreachable!("handled above"),
            Frame::Unexpected(_) => {
                self.counters.rx_corrupt += 1;
            }
        }
        self.pump(now, out);
    }

    fn reject(&mut self, out: &mut Output) {
        if self.connected && !self.failed && !self.rejecting {
            self.rejecting = true;
            self.counters.tx_naks += 1;
            out.wire.extend(nak_frame(self.rx_expected, false));
        }
    }

    fn note_ready(&mut self, not_ready: bool, now: std::time::Instant) {
        self.not_ready_until = not_ready.then(|| now + T_REMOTE_NOTRDY);
    }

    /// Whether the host asked the NCP to hold its callbacks.
    pub fn host_not_ready(&self, now: std::time::Instant) -> bool {
        self.not_ready_until.is_some_and(|t| now < t)
    }

    /// Drop every outstanding frame the host's ackNum covers: those numbered from the oldest
    /// outstanding up to, not including, ackNum. An ackNum outside the window acknowledges
    /// nothing.
    fn acknowledge(&mut self, ack_num: u8, now: std::time::Instant, _out: &mut Output) {
        let Some(oldest) = self.outstanding.front().map(|o| o.frm_num) else {
            return;
        };
        let covered = (ack_num.wrapping_sub(oldest) & 7) as usize;
        if covered == 0 || covered > self.outstanding.len() {
            return;
        }
        for _ in 0..covered {
            if let Some(o) = self.outstanding.pop_front() {
                if let (Some(sent), false) = (o.sent, o.retransmitted) {
                    // UG101: t_rx_ack = 7/8 t_rx_ack + 1/2 the measured time.
                    let measured = now.saturating_duration_since(sent);
                    let next = self.t_rx_ack.mul_f64(7.0 / 8.0) + measured / 2;
                    self.t_rx_ack = next.clamp(T_RX_ACK_MIN, T_RX_ACK_MAX);
                }
            }
        }
        self.timeouts = 0;
    }

    fn retransmit_all(&mut self, now: std::time::Instant, out: &mut Output) {
        let ack = self.rx_expected;
        for o in self.outstanding.iter_mut() {
            o.sent = Some(now);
            o.retransmitted = true;
            self.counters.tx_retransmits += 1;
            out.wire.extend(data_frame(o.frm_num, true, ack, &o.ezsp));
        }
    }

    /// Queue an EZSP frame for the host.
    pub fn send(&mut self, ezsp: Vec<u8>, now: std::time::Instant, out: &mut Output) {
        if !self.connected || self.failed {
            return;
        }
        self.queued.push_back(ezsp);
        self.pump(now, out);
    }

    /// Move queued frames into the window.
    fn pump(&mut self, now: std::time::Instant, out: &mut Output) {
        while self.outstanding.len() < TX_WINDOW {
            let Some(ezsp) = self.queued.pop_front() else {
                break;
            };
            let frm_num = self.tx_next;
            self.tx_next = (self.tx_next + 1) & 7;
            self.counters.tx_data += 1;
            out.wire
                .extend(data_frame(frm_num, false, self.rx_expected, &ezsp));
            self.outstanding.push_back(Outstanding {
                frm_num,
                ezsp,
                sent: Some(now),
                retransmitted: false,
            });
        }
    }

    /// The acknowledgement timer fired: retransmit the window, or fail after
    /// [`ACK_TIMEOUTS`] in a row.
    pub fn timeout(&mut self, now: std::time::Instant, out: &mut Output) {
        if self.failed || self.outstanding.is_empty() {
            return;
        }
        if self.deadline().is_some_and(|d| now < d) {
            return;
        }
        self.timeouts += 1;
        if self.timeouts >= ACK_TIMEOUTS {
            self.failed = true;
            self.outstanding.clear();
            self.queued.clear();
            out.wire
                .extend(error_frame(reset::EXCEEDED_MAXIMUM_ACK_TIMEOUT_COUNT));
            out.failed = true;
            return;
        }
        self.t_rx_ack = (self.t_rx_ack * 2).clamp(T_RX_ACK_MIN, T_RX_ACK_MAX);
        self.retransmit_all(now, out);
    }
}
