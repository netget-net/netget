//! CTAPHID (Client-to-Authenticator Protocol HID) transport layer
//!
//! This module implements the CTAPHID protocol for FIDO2/U2F over HID.
//! CTAPHID uses 64-byte HID packets with channel multiplexing and message fragmentation.
//!
//! ## Packet Format
//!
//! **Initialization Packet** (first packet of a message):
//! ```text
//! | CID (4) | CMD (1) | BCNT_H (1) | BCNT_L (1) | DATA (57) |
//! ```
//!
//! **Continuation Packet** (subsequent packets):
//! ```text
//! | CID (4) | SEQ (1) | DATA (59) |
//! ```
//!
//! ## Commands
//!
//! - PING (0x01): Echo data back
//! - MSG (0x03): Send CTAP1/U2F message
//! - LOCK (0x04): Lock channel for exclusive use
//! - INIT (0x06): Initialize channel
//! - WINK (0x08): User presence test
//! - CBOR (0x10): Send CTAP2 CBOR message
//! - CANCEL (0x11): Cancel pending request
//! - ERROR (0x3f): Error response
//! - KEEPALIVE (0x3b): Processing status

#[cfg(all(unix, feature = "libusb"))]
use anyhow::{bail, Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, trace, warn};

/// HID packet size (64 bytes as per CTAPHID spec)
#[cfg(all(unix, feature = "libusb"))]
pub const HID_PACKET_SIZE: usize = 64;

/// Broadcast channel ID (used for INIT command)
#[cfg(all(unix, feature = "libusb"))]
pub const BROADCAST_CHANNEL: u32 = 0xffffffff;

/// Payload bytes an initialization packet carries: 64 minus the 7-byte header.
#[cfg(all(unix, feature = "libusb"))]
pub const INIT_PAYLOAD: usize = HID_PACKET_SIZE - 7;

/// Payload bytes a continuation packet carries: 64 minus the 5-byte header.
#[cfg(all(unix, feature = "libusb"))]
pub const CONT_PAYLOAD: usize = HID_PACKET_SIZE - 5;

/// Largest CTAPHID message, in bytes.
///
/// Not an arbitrary cap: the sequence number is 7 bits, so a message is one initialization
/// packet plus **at most 128** continuation packets. 57 + 128 * 59 = 7609, which is the
/// `MAX_MSG_SIZE` the CTAPHID specification states. Anything longer cannot be framed —
/// `fragment_response` would wrap the sequence number back to 0 and a host would reject the
/// reply as out of order.
#[cfg(all(unix, feature = "libusb"))]
pub const MAX_MESSAGE_SIZE: usize = INIT_PAYLOAD + 128 * CONT_PAYLOAD;

/// How many channels may be part-way through a message at once.
///
/// `BCNT` is 16 bits, so a *single* 64-byte packet on the wire can declare a 65535-byte
/// message and deliver 57 of its bytes; the rest of the buffer is reserved and held until
/// the message completes. With no cap on either number, an attached host reserves memory at
/// roughly a thousand times the rate it spends bandwidth, on as many channel ids as it cares
/// to invent, and none of it is freed — a pre-authentication memory exhaustion of the same
/// shape as the AMQP field-table and bencode cases in the root CLAUDE.md.
///
/// `MAX_MESSAGE_SIZE` bounds the per-channel cost and this bounds how many can be paid for at
/// once. A real host uses one channel per application and completes each message before
/// starting the next, so four in flight is already generous.
#[cfg(all(unix, feature = "libusb"))]
pub const MAX_ASSEMBLING_CHANNELS: usize = 4;

/// CTAPHID command codes
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Msg = 0x03, // U2F/CTAP1 message
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10, // CTAP2 CBOR message
    Cancel = 0x11,
    Error = 0x3f,
    Keepalive = 0x3b,
}

#[cfg(all(unix, feature = "libusb"))]
impl CtapHidCommand {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & !0x80 {
            // Strip the initialization bit
            0x01 => Some(Self::Ping),
            0x03 => Some(Self::Msg),
            0x04 => Some(Self::Lock),
            0x06 => Some(Self::Init),
            0x08 => Some(Self::Wink),
            0x10 => Some(Self::Cbor),
            0x11 => Some(Self::Cancel),
            0x3f => Some(Self::Error),
            0x3b => Some(Self::Keepalive),
            _ => None,
        }
    }
}

/// CTAPHID error codes
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidError {
    InvalidCmd = 0x01,
    InvalidPar = 0x02,
    InvalidLen = 0x03,
    InvalidSeq = 0x04,
    MsgTimeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0a,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

/// A refusal that has a CTAPHID answer, carried so the caller can send the right one.
///
/// `process_packet` returns `anyhow::Error`, and the connection handler used to answer every
/// one of them with `INVALID_SEQ` on the broadcast channel — the wrong code, on a channel the
/// host is not listening to. Attaching the intended code and the offending channel to the
/// error lets the handler reply in CTAPHID's own vocabulary without a second parse.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy)]
pub struct CtapHidRejection {
    pub cid: u32,
    pub error: CtapHidError,
}

#[cfg(all(unix, feature = "libusb"))]
impl std::fmt::Display for CtapHidRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CTAPHID refusal on cid {:#010x}: {:?}",
            self.cid, self.error
        )
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl std::error::Error for CtapHidRejection {}

#[cfg(all(unix, feature = "libusb"))]
impl CtapHidRejection {
    fn err(cid: u32, error: CtapHidError, context: String) -> anyhow::Error {
        anyhow::Error::new(CtapHidRejection { cid, error }).context(context)
    }
}

/// The CTAPHID answer an error from [`CtapHidHandler::process_packet`] deserves.
///
/// Falls back to `INVALID_SEQ` on the broadcast channel for an error that carries no
/// rejection of its own, which is what every error used to get.
#[cfg(all(unix, feature = "libusb"))]
pub fn rejection_of(error: &anyhow::Error) -> CtapHidRejection {
    error
        .downcast_ref::<CtapHidRejection>()
        .copied()
        .unwrap_or(CtapHidRejection {
            cid: BROADCAST_CHANNEL,
            error: CtapHidError::InvalidSeq,
        })
}

/// CTAPHID packet (64 bytes)
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone)]
pub struct CtapHidPacket {
    /// Channel ID (4 bytes)
    pub cid: u32,
    /// Command byte (only for init packet) or sequence number (for continuation)
    pub cmd_or_seq: u8,
    /// Payload data (57 bytes for init, 59 for continuation)
    pub data: Vec<u8>,
}

#[cfg(all(unix, feature = "libusb"))]
impl CtapHidPacket {
    /// Parse a CTAPHID packet from 64-byte HID report
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != HID_PACKET_SIZE {
            bail!(
                "Invalid packet size: {} (expected {})",
                data.len(),
                HID_PACKET_SIZE
            );
        }

        let cid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let cmd_or_seq = data[4];

        // Check if this is an initialization packet (bit 7 set)
        let is_init = (cmd_or_seq & 0x80) != 0;

        let payload = if is_init {
            // Initialization packet: 7-byte header + 57-byte data
            // Skip CID (4) + CMD (1) + BCNT (2) = 7 bytes
            data[7..].to_vec()
        } else {
            // Continuation packet: 5-byte header + 59-byte data
            // Skip CID (4) + SEQ (1) = 5 bytes
            data[5..].to_vec()
        };

        Ok(Self {
            cid,
            cmd_or_seq,
            data: payload,
        })
    }

    /// Get byte count from initialization packet
    pub fn get_byte_count(&self, data: &[u8]) -> Option<usize> {
        if (self.cmd_or_seq & 0x80) != 0 && data.len() >= 7 {
            let bcnt = u16::from_be_bytes([data[5], data[6]]) as usize;
            Some(bcnt)
        } else {
            None
        }
    }

    /// Check if this is an initialization packet
    pub fn is_init(&self) -> bool {
        (self.cmd_or_seq & 0x80) != 0
    }

    /// Get command (only valid for init packets)
    pub fn command(&self) -> Option<CtapHidCommand> {
        if self.is_init() {
            CtapHidCommand::from_u8(self.cmd_or_seq)
        } else {
            None
        }
    }

    /// Get sequence number (only valid for continuation packets)
    pub fn sequence(&self) -> Option<u8> {
        if !self.is_init() {
            Some(self.cmd_or_seq)
        } else {
            None
        }
    }

    /// Build an initialization packet
    pub fn build_init(cid: u32, cmd: CtapHidCommand, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; HID_PACKET_SIZE];

        // CID (4 bytes)
        packet[0..4].copy_from_slice(&cid.to_be_bytes());

        // CMD (1 byte, with init bit set)
        packet[4] = (cmd as u8) | 0x80;

        // BCNT (2 bytes) - total message length.
        //
        // `data.len() as u16` truncated silently: a 65536-byte message announced itself as 0
        // bytes and a host read the reply as empty. Nothing here can produce a message that
        // long any more -- `fragment_response` refuses past `MAX_MESSAGE_SIZE`, which is well
        // inside 16 bits -- so a value that does not fit is a bug rather than input. Clamp to
        // the largest this transport can frame instead of wrapping to a small one.
        let bcnt = u16::try_from(data.len()).unwrap_or(MAX_MESSAGE_SIZE as u16);
        packet[5..7].copy_from_slice(&bcnt.to_be_bytes());

        // DATA (up to 57 bytes)
        let copy_len = data.len().min(INIT_PAYLOAD);
        packet[7..7 + copy_len].copy_from_slice(&data[..copy_len]);

        packet
    }

    /// Build a continuation packet
    pub fn build_cont(cid: u32, seq: u8, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; HID_PACKET_SIZE];

        // CID (4 bytes)
        packet[0..4].copy_from_slice(&cid.to_be_bytes());

        // SEQ (1 byte)
        packet[4] = seq & 0x7f; // Ensure init bit is not set

        // DATA (up to 59 bytes)
        let copy_len = data.len().min(CONT_PAYLOAD);
        packet[5..5 + copy_len].copy_from_slice(&data[..copy_len]);

        packet
    }

    /// Build an error response packet
    pub fn build_error(cid: u32, error: CtapHidError) -> Vec<u8> {
        Self::build_init(cid, CtapHidCommand::Error, &[error as u8])
    }

    /// Build a KEEPALIVE packet.
    ///
    /// This is how a real authenticator says "still here, waiting for the button" rather than
    /// going silent while the user decides. netget's button is the model, and an approval round
    /// trip takes as long as an LLM call, so without this the host sees an unresponsive device
    /// for seconds at a time and gives up.
    pub fn build_keepalive(cid: u32, status: KeepaliveStatus) -> Vec<u8> {
        Self::build_init(cid, CtapHidCommand::Keepalive, &[status as u8])
    }
}

/// CTAPHID KEEPALIVE status byte.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    /// The authenticator is busy processing.
    Processing = 0x01,
    /// The authenticator is waiting for user presence.
    UpNeeded = 0x02,
}

/// CTAPHID message assembler (handles fragmentation)
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct CtapHidMessage {
    /// Channel ID
    pub cid: u32,
    /// Command
    pub cmd: CtapHidCommand,
    /// Complete message data
    pub data: Vec<u8>,
    /// Expected total length
    expected_len: usize,
    /// Current sequence number
    next_seq: u8,
}

#[cfg(all(unix, feature = "libusb"))]
impl CtapHidMessage {
    /// Start a new message from an initialization packet.
    ///
    /// Refuses a `BCNT` this transport could not frame a reply to. `BCNT` is 16 bits, so a
    /// host can declare 65535 bytes, but the 7-bit sequence number caps a CTAPHID message at
    /// [`MAX_MESSAGE_SIZE`]; a longer one is malformed by the specification's own arithmetic
    /// and answering `INVALID_LEN` is what a real authenticator does.
    ///
    /// Nothing is pre-allocated from `bcnt` either. `Vec::with_capacity(bcnt)` reserved the
    /// host's declared size up front, so 64 bytes on the wire bought up to 64 KiB of resident
    /// memory that was released only when the message completed -- which a host that simply
    /// never sends the continuation packets never does. The buffer now grows with the bytes
    /// that actually arrive.
    pub fn new(
        cid: u32,
        cmd: CtapHidCommand,
        bcnt: usize,
        init_data: &[u8],
    ) -> std::result::Result<Self, anyhow::Error> {
        if bcnt > MAX_MESSAGE_SIZE {
            return Err(CtapHidRejection::err(
                cid,
                CtapHidError::InvalidLen,
                format!(
                    "CTAPHID BCNT={bcnt} exceeds the {MAX_MESSAGE_SIZE}-byte maximum a 7-bit \
                     sequence number can frame"
                ),
            ));
        }

        let mut data = Vec::new();
        let copy_len = init_data.len().min(bcnt);
        data.extend_from_slice(&init_data[..copy_len]);

        Ok(Self {
            cid,
            cmd,
            data,
            expected_len: bcnt,
            next_seq: 0,
        })
    }

    /// Add a continuation packet
    pub fn add_continuation(&mut self, seq: u8, cont_data: &[u8]) -> Result<()> {
        if seq != self.next_seq {
            return Err(CtapHidRejection::err(
                self.cid,
                CtapHidError::InvalidSeq,
                format!(
                    "CTAPHID sequence mismatch on cid {:#010x}: expected {}, got {}",
                    self.cid, self.next_seq, seq
                ),
            ));
        }

        let remaining = self.expected_len.saturating_sub(self.data.len());
        let copy_len = cont_data.len().min(remaining);
        self.data.extend_from_slice(&cont_data[..copy_len]);

        self.next_seq = (self.next_seq + 1) & 0x7f;
        Ok(())
    }

    /// Check if message is complete
    pub fn is_complete(&self) -> bool {
        self.data.len() >= self.expected_len
    }

    /// Get the complete message data
    pub fn into_data(mut self) -> Vec<u8> {
        self.data.truncate(self.expected_len);
        self.data
    }
}

/// CTAPHID protocol handler (manages channels and message assembly)
#[cfg(all(unix, feature = "libusb"))]
pub struct CtapHidHandler {
    /// Next available channel ID
    next_cid: u32,
    /// Active messages being assembled (keyed by channel ID)
    active_messages: HashMap<u32, CtapHidMessage>,
}

#[cfg(all(unix, feature = "libusb"))]
impl CtapHidHandler {
    pub fn new() -> Self {
        Self {
            next_cid: 1, // Start at 1 (0xffffffff is broadcast)
            active_messages: HashMap::new(),
        }
    }

    /// Allocate a new channel ID
    pub fn allocate_channel(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == BROADCAST_CHANNEL {
            self.next_cid = 1;
        }
        cid
    }

    /// Process incoming HID packet
    pub fn process_packet(&mut self, raw_data: &[u8]) -> Result<Option<CtapHidMessage>> {
        let packet = CtapHidPacket::parse(raw_data)?;

        trace!(
            "CTAPHID packet: cid={:#010x}, cmd_or_seq={:#04x}",
            packet.cid,
            packet.cmd_or_seq
        );

        if packet.is_init() {
            // Initialization packet - start new message
            let cmd = packet.command().context("Invalid command")?;
            let bcnt = packet
                .get_byte_count(raw_data)
                .context("Missing byte count")?;

            debug!(
                "CTAPHID init: cid={:#010x}, cmd={:?}, bcnt={}",
                packet.cid, cmd, bcnt
            );

            let message = CtapHidMessage::new(packet.cid, cmd, bcnt, &packet.data)?;

            if message.is_complete() {
                // Single-packet message. Nothing is retained, so no channel is consumed.
                Ok(Some(message))
            } else {
                // Multi-packet message: this is the only path that retains memory for a host
                // that may never come back, so it is the one that needs a cap. Re-initializing
                // a channel already assembling replaces its buffer rather than adding one, so
                // it is free and must not be refused.
                if !self.active_messages.contains_key(&packet.cid)
                    && self.active_messages.len() >= MAX_ASSEMBLING_CHANNELS
                {
                    warn!(
                        "CTAPHID: {} channels are already mid-message; refusing cid {:#010x}",
                        self.active_messages.len(),
                        packet.cid
                    );
                    return Err(CtapHidRejection::err(
                        packet.cid,
                        CtapHidError::ChannelBusy,
                        format!(
                            "CTAPHID refuses a {}th partially-assembled message; finish one \
                             before starting another",
                            MAX_ASSEMBLING_CHANNELS + 1
                        ),
                    ));
                }
                self.active_messages.insert(packet.cid, message);
                Ok(None)
            }
        } else {
            // Continuation packet - add to existing message
            let seq = packet.sequence().context("Invalid sequence")?;

            if let Some(message) = self.active_messages.get_mut(&packet.cid) {
                message.add_continuation(seq, &packet.data)?;

                if message.is_complete() {
                    // Message complete - remove and return
                    Ok(self.active_messages.remove(&packet.cid))
                } else {
                    // Still waiting for more packets
                    Ok(None)
                }
            } else {
                warn!(
                    "Continuation packet for unknown channel: {:#010x}",
                    packet.cid
                );
                Err(CtapHidRejection::err(
                    packet.cid,
                    CtapHidError::InvalidChannel,
                    format!(
                        "CTAPHID continuation for unopened channel {:#010x}",
                        packet.cid
                    ),
                ))
            }
        }
    }

    /// Fragment a response into HID packets.
    ///
    /// A response longer than [`MAX_MESSAGE_SIZE`] cannot be framed: `seq` is 7 bits, so the
    /// 129th continuation packet reuses sequence 0 and a host rejects the reply as out of
    /// order -- while `BCNT` would separately have wrapped. That produced a garbled answer
    /// rather than an error, so it is refused here with the one packet that says so.
    pub fn fragment_response(&self, cid: u32, cmd: CtapHidCommand, data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() > MAX_MESSAGE_SIZE {
            warn!(
                "CTAPHID response of {} bytes on cid {:#010x} exceeds the {}-byte maximum; \
                 answering INVALID_LEN",
                data.len(),
                cid,
                MAX_MESSAGE_SIZE
            );
            return vec![CtapHidPacket::build_error(cid, CtapHidError::InvalidLen)];
        }

        let mut packets = Vec::new();

        // First packet (initialization)
        packets.push(CtapHidPacket::build_init(cid, cmd, data));

        // Continuation packets if needed
        if data.len() > INIT_PAYLOAD {
            let mut offset = INIT_PAYLOAD;
            let mut seq = 0u8;

            while offset < data.len() {
                let chunk = &data[offset..];
                packets.push(CtapHidPacket::build_cont(cid, seq, chunk));
                offset += CONT_PAYLOAD;
                seq = (seq + 1) & 0x7f;
            }
        }

        packets
    }

    /// Channels currently part-way through a message. Diagnostics and tests.
    pub fn assembling_channels(&self) -> usize {
        self.active_messages.len()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for CtapHidHandler {
    fn default() -> Self {
        Self::new()
    }
}
