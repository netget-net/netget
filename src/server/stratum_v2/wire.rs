//! Stratum V2 on the wire, for both roles: the binary data types (sv2-spec §3.1), the frame
//! header (§3.2), the Common and Mining Protocol messages this server and client exchange, the
//! encrypted transport framing (§4.6), and the arithmetic a pool and a miner must agree on byte
//! for byte — the coinbase a job describes, its merkle root, the 80-byte header a share commits
//! to, its double SHA-256 and where that falls against a target.
use super::noise::{CipherState, Session, MAC_LEN, MAX_CIPHERTEXT_CHUNK, MAX_PLAINTEXT_CHUNK};
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// extension_type (U16), msg_type (U8), msg_length (U24).
pub const HEADER_LEN: usize = 6;
/// The header as one transport message: six bytes and a MAC.
pub const ENCRYPTED_HEADER_LEN: usize = HEADER_LEN + MAC_LEN;
/// Bit 15 of extension_type: the payload starts with the channel it is for.
pub const CHANNEL_MSG_BIT: u16 = 0x8000;
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The only protocol version there is.
pub const PROTOCOL_VERSION: u16 = 2;
/// `SetupConnection.protocol` for the Mining Protocol.
pub const MINING_PROTOCOL: u8 = 0;
/// `SetupConnection.protocol` for the Job Declaration Protocol (sv2-spec §6).
pub const JOB_DECLARATION_PROTOCOL: u8 = 1;
/// `SetupConnection.protocol` for the Template Distribution Protocol (sv2-spec §7).
pub const TEMPLATE_DISTRIBUTION_PROTOCOL: u8 = 2;
/// The one SetupConnection flag the Job Declaration Protocol defines: the client may declare
/// full templates (DECLARE_TX_DATA). SRI's jd_client v0.8.0 sets it in FULLTEMPLATE mode, and SRI's
/// JDS refuses a client without it (`missing-declare-tx-data-flag`).
pub const DECLARE_TX_DATA: u32 = 1 << 0;

/// SetupConnection flags a mining client may send (sv2-spec §5.3.1).
pub const REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
pub const REQUIRES_WORK_SELECTION: u32 = 1 << 1;
pub const REQUIRES_VERSION_ROLLING: u32 = 1 << 2;
/// The general-purpose version bits (BIP 320) a miner may roll.
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;
/// How far past now a share's nTime may be: Bitcoin's MAX_FUTURE_BLOCK_TIME.
pub const MAX_FUTURE_NTIME: u32 = 7200;
/// Bytes of extranonce prefix this pool assigns each channel.
pub const EXTRANONCE_PREFIX_LEN: usize = 4;
/// An extended channel's extranonce is at most this long (B0_32, sv2-spec §5.3.4).
pub const MAX_EXTRANONCE: usize = 32;
/// The coinbase message a pool job carries, in bytes; the scriptSig must stay under 100.
pub const MAX_COINBASE_MESSAGE: usize = 32;
/// Difficulty 1: the target 0x00000000FFFF0000…, as a number.
pub const DIFF1: f64 = 26959535291011309493156476344723991336010898738574164086137773096960.0;

pub mod msg {
    pub const SETUP_CONNECTION: u8 = 0x00;
    pub const SETUP_CONNECTION_SUCCESS: u8 = 0x01;
    pub const SETUP_CONNECTION_ERROR: u8 = 0x02;
    pub const CHANNEL_ENDPOINT_CHANGED: u8 = 0x03;
    pub const RECONNECT: u8 = 0x04;
    pub const OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
    pub const OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
    pub const OPEN_MINING_CHANNEL_ERROR: u8 = 0x12;
    pub const OPEN_EXTENDED_MINING_CHANNEL: u8 = 0x13;
    pub const OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: u8 = 0x14;
    pub const NEW_MINING_JOB: u8 = 0x15;
    pub const UPDATE_CHANNEL: u8 = 0x16;
    pub const UPDATE_CHANNEL_ERROR: u8 = 0x17;
    pub const CLOSE_CHANNEL: u8 = 0x18;
    pub const SET_EXTRANONCE_PREFIX: u8 = 0x19;
    pub const SUBMIT_SHARES_STANDARD: u8 = 0x1a;
    pub const SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
    pub const SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
    pub const SUBMIT_SHARES_ERROR: u8 = 0x1d;
    pub const NEW_EXTENDED_MINING_JOB: u8 = 0x1f;
    pub const SET_NEW_PREV_HASH: u8 = 0x20;
    pub const SET_TARGET: u8 = 0x21;
    pub const SET_CUSTOM_MINING_JOB: u8 = 0x22;
    pub const SET_CUSTOM_MINING_JOB_SUCCESS: u8 = 0x23;
    pub const SET_CUSTOM_MINING_JOB_ERROR: u8 = 0x24;
    pub const SET_GROUP_CHANNEL: u8 = 0x25;
    // Job Declaration Protocol (sv2-spec §6; job_declaration_sv2 10.0, sv2-apps v0.8.0).
    pub const ALLOCATE_MINING_JOB_TOKEN: u8 = 0x50;
    pub const ALLOCATE_MINING_JOB_TOKEN_SUCCESS: u8 = 0x51;
    pub const PROVIDE_MISSING_TRANSACTIONS: u8 = 0x55;
    pub const PROVIDE_MISSING_TRANSACTIONS_SUCCESS: u8 = 0x56;
    pub const DECLARE_MINING_JOB: u8 = 0x57;
    pub const DECLARE_MINING_JOB_SUCCESS: u8 = 0x58;
    pub const DECLARE_MINING_JOB_ERROR: u8 = 0x59;
    pub const PUSH_SOLUTION: u8 = 0x60;
    // Template Distribution Protocol (sv2-spec §7; template_distribution_sv2 7.0).
    pub const COINBASE_OUTPUT_CONSTRAINTS: u8 = 0x70;
    pub const NEW_TEMPLATE: u8 = 0x71;
    pub const TEMPLATE_SET_NEW_PREV_HASH: u8 = 0x72;
    pub const REQUEST_TRANSACTION_DATA: u8 = 0x73;
    pub const REQUEST_TRANSACTION_DATA_SUCCESS: u8 = 0x74;
    pub const REQUEST_TRANSACTION_DATA_ERROR: u8 = 0x75;
    pub const SUBMIT_SOLUTION: u8 = 0x76;
}

/// Whether a core message carries the channel_msg bit (sv2-spec §8).
pub fn channel_bit(msg_type: u8) -> bool {
    matches!(msg_type, 0x03 | 0x15..=0x24)
}

/// One frame: who defined the message, which it is, and its plaintext payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub extension_type: u16,
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// The extension the message belongs to, without the channel_msg bit.
    pub fn extension(&self) -> u16 {
        self.extension_type & !CHANNEL_MSG_BIT
    }

    pub fn header(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..2].copy_from_slice(&self.extension_type.to_le_bytes());
        h[2] = self.msg_type;
        h[3..6].copy_from_slice(&(self.payload.len() as u32).to_le_bytes()[..3]);
        h
    }
}

/// Bytes on the wire for a payload of `plaintext` bytes: 65519-byte chunks, each with a MAC.
pub fn ciphertext_len(plaintext: usize) -> usize {
    let rest = plaintext % MAX_PLAINTEXT_CHUNK;
    plaintext / MAX_PLAINTEXT_CHUNK * MAX_CIPHERTEXT_CHUNK
        + if rest > 0 { rest + MAC_LEN } else { 0 }
}

/// Encrypt one frame: the header as one transport message, then the payload in chunks.
pub fn seal(cipher: &mut CipherState, frame: &Frame) -> Result<Vec<u8>> {
    ensure!(
        frame.payload.len() < 1 << 24,
        "a payload is at most 2^24-1 bytes"
    );
    let mut out = cipher.encrypt(&[], &frame.header())?;
    for chunk in frame.payload.chunks(MAX_PLAINTEXT_CHUNK) {
        out.extend_from_slice(&cipher.encrypt(&[], chunk)?);
    }
    Ok(out)
}

/// The receiving half of an established session.
pub struct FrameReader<R> {
    reader: R,
    cipher: CipherState,
    max_payload: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R, cipher: CipherState, max_payload: usize) -> Self {
        Self {
            reader,
            cipher,
            max_payload,
        }
    }

    /// Change the largest payload this side accepts, once the session has said which protocol
    /// it speaks (one listener can serve more than one).
    pub fn set_max_payload(&mut self, max_payload: usize) {
        self.max_payload = max_payload;
    }

    /// The next frame; None at a clean end of stream between frames. A header that does not
    /// authenticate, a declared length over the bound, or a payload chunk that does not
    /// authenticate is an error, and the session cannot continue after one.
    pub async fn next(&mut self, idle: Duration) -> Result<Option<Frame>> {
        let mut header_ct = [0u8; ENCRYPTED_HEADER_LEN];
        let first = tokio::time::timeout(idle, self.reader.read(&mut header_ct[..1]))
            .await
            .context("Stratum V2 peer idle")??;
        if first == 0 {
            return Ok(None);
        }
        tokio::time::timeout(IO_TIMEOUT, self.reader.read_exact(&mut header_ct[1..]))
            .await
            .context("Stratum V2 frame header deadline")??;
        let header = self
            .cipher
            .decrypt(&[], &header_ct)
            .context("frame header did not authenticate")?;
        let extension_type = u16::from_le_bytes([header[0], header[1]]);
        let msg_type = header[2];
        let length = u32::from_le_bytes([header[3], header[4], header[5], 0]) as usize;
        ensure!(
            length <= self.max_payload,
            "frame declares a {length}-byte payload, more than the {} this side accepts",
            self.max_payload
        );
        let mut ct = vec![0u8; ciphertext_len(length)];
        tokio::time::timeout(IO_TIMEOUT, self.reader.read_exact(&mut ct))
            .await
            .context("Stratum V2 frame payload deadline")??;
        let mut payload = Vec::with_capacity(length);
        for chunk in ct.chunks(MAX_CIPHERTEXT_CHUNK) {
            payload.extend_from_slice(
                &self
                    .cipher
                    .decrypt(&[], chunk)
                    .context("frame payload did not authenticate")?,
            );
        }
        ensure!(payload.len() == length, "payload length mismatch");
        Ok(Some(Frame {
            extension_type,
            msg_type,
            payload,
        }))
    }
}

/// The sending half of an established session.
pub struct FrameWriter<W> {
    writer: W,
    cipher: CipherState,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(writer: W, cipher: CipherState) -> Self {
        Self { writer, cipher }
    }

    pub async fn send(&mut self, message: &Message) -> Result<usize> {
        let bytes = seal(&mut self.cipher, &message.encode())?;
        tokio::time::timeout(IO_TIMEOUT, self.writer.write_all(&bytes))
            .await
            .context("Stratum V2 write deadline")??;
        Ok(bytes.len())
    }

    pub async fn shutdown(&mut self) {
        let _ = self.writer.shutdown().await;
    }
}

/// Split a session over a stream's two halves.
pub fn transport<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    writer: W,
    session: Session,
    max_payload: usize,
) -> (FrameReader<R>, FrameWriter<W>) {
    (
        FrameReader::new(reader, session.recv, max_payload),
        FrameWriter::new(writer, session.send),
    )
}

/// Reads the binary data types, refusing anything that runs past the payload.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(
            self.buf.len() - self.pos >= n,
            "message ends {} bytes into a {n}-byte field",
            self.buf.len() - self.pos
        );
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    pub fn u24(&mut self) -> Result<u32> {
        let b = self.take(3)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], 0]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    /// F32: NaN, ±infinity and negative values (including -0.0) are protocol errors.
    pub fn f32(&mut self) -> Result<f32> {
        let v = f32::from_le_bytes(self.take(4)?.try_into()?);
        ensure!(
            v.is_finite() && v.is_sign_positive(),
            "F32 field is {v}, which the protocol forbids"
        );
        Ok(v)
    }
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? & 1 == 1)
    }
    pub fn u256(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into()?)
    }
    fn bytes_u8_prefix(&mut self, max: usize, what: &str) -> Result<Vec<u8>> {
        let n = self.u8()? as usize;
        ensure!(n <= max, "{what} declares {n} bytes, at most {max} allowed");
        Ok(self.take(n)?.to_vec())
    }
    pub fn str0_255(&mut self) -> Result<Vec<u8>> {
        self.bytes_u8_prefix(255, "STR0_255")
    }
    pub fn b0_32(&mut self) -> Result<Vec<u8>> {
        self.bytes_u8_prefix(32, "B0_32")
    }
    pub fn b0_255(&mut self) -> Result<Vec<u8>> {
        self.bytes_u8_prefix(255, "B0_255")
    }
    pub fn b0_64k(&mut self) -> Result<Vec<u8>> {
        let n = self.u16()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn b0_16m(&mut self) -> Result<Vec<u8>> {
        let n = self.u24()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    /// SEQ0_64K: the declared count is checked against what the payload can still hold before
    /// anything is allocated for it, so a count of 65535 in a short frame costs nothing.
    fn seq0_64k<T>(
        &mut self,
        min_element: usize,
        mut item: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let n = self.u16()? as usize;
        ensure!(
            n.saturating_mul(min_element) <= self.buf.len() - self.pos,
            "SEQ0_64K declares {n} elements, more than the {} bytes left can hold",
            self.buf.len() - self.pos
        );
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(item(self)?);
        }
        Ok(out)
    }
    pub fn seq0_64k_u256(&mut self) -> Result<Vec<[u8; 32]>> {
        self.seq0_64k(32, |r| r.u256())
    }
    pub fn seq0_64k_u16(&mut self) -> Result<Vec<u16>> {
        self.seq0_64k(2, |r| r.u16())
    }
    pub fn seq0_64k_b0_16m(&mut self) -> Result<Vec<Vec<u8>>> {
        self.seq0_64k(3, |r| r.b0_16m())
    }
    pub fn option_u32(&mut self) -> Result<Option<u32>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u32()?)),
            n => bail!("OPTION declares {n} elements, at most 1 allowed"),
        }
    }
    pub fn seq0_255_u256(&mut self) -> Result<Vec<[u8; 32]>> {
        let n = self.u8()? as usize;
        (0..n).map(|_| self.u256()).collect()
    }
    pub fn seq0_64k_u32(&mut self) -> Result<Vec<u32>> {
        self.seq0_64k(4, |r| r.u32())
    }
    /// The whole payload must have been read: trailing bytes are a malformed message.
    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.pos == self.buf.len(),
            "{} unexpected bytes after the message",
            self.buf.len() - self.pos
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn f32(&mut self, v: f32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }
    pub fn u256(&mut self, v: &[u8; 32]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    /// STR0_255, B0_32 and B0_255; callers keep the length within the type's bound.
    pub fn short_bytes(&mut self, v: &[u8]) -> &mut Self {
        let v = &v[..v.len().min(255)];
        self.u8(v.len() as u8);
        self.0.extend_from_slice(v);
        self
    }
    pub fn b0_64k(&mut self, v: &[u8]) -> &mut Self {
        let v = &v[..v.len().min(65535)];
        self.u16(v.len() as u16);
        self.0.extend_from_slice(v);
        self
    }
    /// B0_16M; callers keep the length under 2^24.
    pub fn b0_16m(&mut self, v: &[u8]) -> &mut Self {
        let v = &v[..v.len().min((1 << 24) - 1)];
        self.0
            .extend_from_slice(&(v.len() as u32).to_le_bytes()[..3]);
        self.0.extend_from_slice(v);
        self
    }
    pub fn seq0_64k_u256(&mut self, v: &[[u8; 32]]) -> &mut Self {
        let v = &v[..v.len().min(65535)];
        self.u16(v.len() as u16);
        for h in v {
            self.u256(h);
        }
        self
    }
    pub fn seq0_64k_u16(&mut self, v: &[u16]) -> &mut Self {
        let v = &v[..v.len().min(65535)];
        self.u16(v.len() as u16);
        for n in v {
            self.u16(*n);
        }
        self
    }
    pub fn seq0_64k_b0_16m(&mut self, v: &[Vec<u8>]) -> &mut Self {
        let v = &v[..v.len().min(65535)];
        self.u16(v.len() as u16);
        for b in v {
            self.b0_16m(b);
        }
        self
    }
    pub fn option_u32(&mut self, v: Option<u32>) -> &mut Self {
        match v {
            Some(v) => self.u8(1).u32(v),
            None => self.u8(0),
        }
    }
    pub fn seq0_255_u256(&mut self, v: &[[u8; 32]]) -> &mut Self {
        let v = &v[..v.len().min(255)];
        self.u8(v.len() as u8);
        for h in v {
            self.u256(h);
        }
        self
    }
    pub fn seq0_64k_u32(&mut self, v: &[u32]) -> &mut Self {
        let v = &v[..v.len().min(65535)];
        self.u16(v.len() as u16);
        for n in v {
            self.u32(*n);
        }
        self
    }
}

/// The Common and Mining Protocol messages both roles speak. Strings are kept as the bytes
/// the peer sent; `text` renders them for events and logs.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    SetupConnection {
        protocol: u8,
        min_version: u16,
        max_version: u16,
        flags: u32,
        endpoint_host: Vec<u8>,
        endpoint_port: u16,
        vendor: Vec<u8>,
        hardware_version: Vec<u8>,
        firmware: Vec<u8>,
        device_id: Vec<u8>,
    },
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    SetupConnectionError {
        flags: u32,
        error_code: Vec<u8>,
    },
    ChannelEndpointChanged {
        channel_id: u32,
    },
    Reconnect {
        new_host: Vec<u8>,
        new_port: u16,
    },
    OpenStandardMiningChannel {
        request_id: u32,
        user_identity: Vec<u8>,
        nominal_hash_rate: f32,
        max_target: [u8; 32],
    },
    OpenStandardMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target: [u8; 32],
        extranonce_prefix: Vec<u8>,
        group_channel_id: u32,
    },
    OpenExtendedMiningChannel {
        request_id: u32,
        user_identity: Vec<u8>,
        nominal_hash_rate: f32,
        max_target: [u8; 32],
        min_extranonce_size: u16,
    },
    OpenExtendedMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target: [u8; 32],
        extranonce_size: u16,
        extranonce_prefix: Vec<u8>,
        group_channel_id: u32,
    },
    OpenMiningChannelError {
        request_id: u32,
        error_code: Vec<u8>,
    },
    UpdateChannel {
        channel_id: u32,
        nominal_hash_rate: f32,
        max_target: [u8; 32],
    },
    UpdateChannelError {
        channel_id: u32,
        error_code: Vec<u8>,
    },
    CloseChannel {
        channel_id: u32,
        reason_code: Vec<u8>,
    },
    SetExtranoncePrefix {
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    },
    SubmitSharesStandard {
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
    },
    SubmitSharesExtended {
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
        extranonce: Vec<u8>,
    },
    SubmitSharesSuccess {
        channel_id: u32,
        last_sequence_number: u32,
        new_submits_accepted_count: u32,
        new_shares_sum: u64,
    },
    SubmitSharesError {
        channel_id: u32,
        sequence_number: u32,
        error_code: Vec<u8>,
    },
    NewMiningJob {
        channel_id: u32,
        job_id: u32,
        min_ntime: Option<u32>,
        version: u32,
        merkle_root: [u8; 32],
    },
    NewExtendedMiningJob {
        channel_id: u32,
        job_id: u32,
        min_ntime: Option<u32>,
        version: u32,
        version_rolling_allowed: bool,
        merkle_path: Vec<[u8; 32]>,
        coinbase_tx_prefix: Vec<u8>,
        coinbase_tx_suffix: Vec<u8>,
    },
    SetNewPrevHash {
        channel_id: u32,
        job_id: u32,
        prev_hash: [u8; 32],
        min_ntime: u32,
        nbits: u32,
    },
    SetTarget {
        channel_id: u32,
        maximum_target: [u8; 32],
    },
    /// Work selection (sv2-spec §5.3.18, mining_sv2 12.0): a job the downstream chose and
    /// declared to a Job Declarator Server, redeemed on an extended channel with the token that
    /// server issued.
    SetCustomMiningJob {
        channel_id: u32,
        request_id: u32,
        token: Vec<u8>,
        version: u32,
        prev_hash: [u8; 32],
        min_ntime: u32,
        nbits: u32,
        coinbase_tx_version: u32,
        /// The scriptSig up to the extranonce, including the push opcode that precedes it.
        coinbase_prefix: Vec<u8>,
        coinbase_tx_input_n_sequence: u32,
        /// The output vector, serialised with its count.
        coinbase_tx_outputs: Vec<u8>,
        coinbase_tx_locktime: u32,
        merkle_path: Vec<[u8; 32]>,
    },
    SetCustomMiningJobSuccess {
        channel_id: u32,
        request_id: u32,
        job_id: u32,
    },
    SetCustomMiningJobError {
        channel_id: u32,
        request_id: u32,
        error_code: Vec<u8>,
    },
    SetGroupChannel {
        group_channel_id: u32,
        channel_ids: Vec<u32>,
    },
    // Job Declaration Protocol.
    AllocateMiningJobToken {
        user_identifier: Vec<u8>,
        request_id: u32,
    },
    AllocateMiningJobTokenSuccess {
        request_id: u32,
        mining_job_token: Vec<u8>,
        /// A consensus-serialised output vector (CompactSize count, then the outputs).
        coinbase_outputs: Vec<u8>,
    },
    ProvideMissingTransactions {
        request_id: u32,
        unknown_tx_position_list: Vec<u16>,
    },
    ProvideMissingTransactionsSuccess {
        request_id: u32,
        transaction_list: Vec<Vec<u8>>,
    },
    DeclareMiningJob {
        request_id: u32,
        mining_job_token: Vec<u8>,
        version: u32,
        coinbase_tx_prefix: Vec<u8>,
        coinbase_tx_suffix: Vec<u8>,
        wtxid_list: Vec<[u8; 32]>,
        excess_data: Vec<u8>,
    },
    DeclareMiningJobSuccess {
        request_id: u32,
        new_mining_job_token: Vec<u8>,
    },
    DeclareMiningJobError {
        request_id: u32,
        error_code: Vec<u8>,
        error_details: Vec<u8>,
    },
    PushSolution {
        extranonce: Vec<u8>,
        prev_hash: [u8; 32],
        nonce: u32,
        ntime: u32,
        nbits: u32,
        version: u32,
    },
    // Template Distribution Protocol.
    CoinbaseOutputConstraints {
        max_additional_size: u32,
        max_additional_sigops: u16,
    },
    NewTemplate {
        template_id: u64,
        future_template: bool,
        version: u32,
        coinbase_tx_version: u32,
        coinbase_prefix: Vec<u8>,
        coinbase_tx_input_sequence: u32,
        coinbase_tx_value_remaining: u64,
        coinbase_tx_outputs_count: u32,
        /// The outputs concatenated, without a count (the count is the field above).
        coinbase_tx_outputs: Vec<u8>,
        coinbase_tx_locktime: u32,
        merkle_path: Vec<[u8; 32]>,
    },
    /// The Template Distribution Protocol's SetNewPrevHash (0x72), which unlike the Mining
    /// Protocol's names a template and carries the target.
    TemplateSetNewPrevHash {
        template_id: u64,
        prev_hash: [u8; 32],
        header_timestamp: u32,
        nbits: u32,
        target: [u8; 32],
    },
    RequestTransactionData {
        template_id: u64,
    },
    RequestTransactionDataSuccess {
        template_id: u64,
        excess_data: Vec<u8>,
        transaction_list: Vec<Vec<u8>>,
    },
    RequestTransactionDataError {
        template_id: u64,
        error_code: Vec<u8>,
    },
    SubmitSolution {
        template_id: u64,
        version: u32,
        header_timestamp: u32,
        header_nonce: u32,
        coinbase_tx: Vec<u8>,
    },
}

impl Message {
    pub fn msg_type(&self) -> u8 {
        use Message::*;
        match self {
            SetupConnection { .. } => msg::SETUP_CONNECTION,
            SetupConnectionSuccess { .. } => msg::SETUP_CONNECTION_SUCCESS,
            SetupConnectionError { .. } => msg::SETUP_CONNECTION_ERROR,
            ChannelEndpointChanged { .. } => msg::CHANNEL_ENDPOINT_CHANGED,
            Reconnect { .. } => msg::RECONNECT,
            OpenStandardMiningChannel { .. } => msg::OPEN_STANDARD_MINING_CHANNEL,
            OpenStandardMiningChannelSuccess { .. } => msg::OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            OpenExtendedMiningChannel { .. } => msg::OPEN_EXTENDED_MINING_CHANNEL,
            OpenExtendedMiningChannelSuccess { .. } => msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            OpenMiningChannelError { .. } => msg::OPEN_MINING_CHANNEL_ERROR,
            UpdateChannel { .. } => msg::UPDATE_CHANNEL,
            UpdateChannelError { .. } => msg::UPDATE_CHANNEL_ERROR,
            CloseChannel { .. } => msg::CLOSE_CHANNEL,
            SetExtranoncePrefix { .. } => msg::SET_EXTRANONCE_PREFIX,
            SubmitSharesStandard { .. } => msg::SUBMIT_SHARES_STANDARD,
            SubmitSharesExtended { .. } => msg::SUBMIT_SHARES_EXTENDED,
            SubmitSharesSuccess { .. } => msg::SUBMIT_SHARES_SUCCESS,
            SubmitSharesError { .. } => msg::SUBMIT_SHARES_ERROR,
            NewMiningJob { .. } => msg::NEW_MINING_JOB,
            NewExtendedMiningJob { .. } => msg::NEW_EXTENDED_MINING_JOB,
            SetNewPrevHash { .. } => msg::SET_NEW_PREV_HASH,
            SetTarget { .. } => msg::SET_TARGET,
            SetCustomMiningJob { .. } => msg::SET_CUSTOM_MINING_JOB,
            SetCustomMiningJobSuccess { .. } => msg::SET_CUSTOM_MINING_JOB_SUCCESS,
            SetCustomMiningJobError { .. } => msg::SET_CUSTOM_MINING_JOB_ERROR,
            SetGroupChannel { .. } => msg::SET_GROUP_CHANNEL,
            AllocateMiningJobToken { .. } => msg::ALLOCATE_MINING_JOB_TOKEN,
            AllocateMiningJobTokenSuccess { .. } => msg::ALLOCATE_MINING_JOB_TOKEN_SUCCESS,
            ProvideMissingTransactions { .. } => msg::PROVIDE_MISSING_TRANSACTIONS,
            ProvideMissingTransactionsSuccess { .. } => msg::PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
            DeclareMiningJob { .. } => msg::DECLARE_MINING_JOB,
            DeclareMiningJobSuccess { .. } => msg::DECLARE_MINING_JOB_SUCCESS,
            DeclareMiningJobError { .. } => msg::DECLARE_MINING_JOB_ERROR,
            PushSolution { .. } => msg::PUSH_SOLUTION,
            CoinbaseOutputConstraints { .. } => msg::COINBASE_OUTPUT_CONSTRAINTS,
            NewTemplate { .. } => msg::NEW_TEMPLATE,
            TemplateSetNewPrevHash { .. } => msg::TEMPLATE_SET_NEW_PREV_HASH,
            RequestTransactionData { .. } => msg::REQUEST_TRANSACTION_DATA,
            RequestTransactionDataSuccess { .. } => msg::REQUEST_TRANSACTION_DATA_SUCCESS,
            RequestTransactionDataError { .. } => msg::REQUEST_TRANSACTION_DATA_ERROR,
            SubmitSolution { .. } => msg::SUBMIT_SOLUTION,
        }
    }

    /// The message's name as the specification writes it.
    pub fn name(&self) -> &'static str {
        name_of(self.msg_type())
    }

    pub fn encode(&self) -> Frame {
        use Message::*;
        let mut w = Writer::default();
        match self {
            SetupConnection {
                protocol,
                min_version,
                max_version,
                flags,
                endpoint_host,
                endpoint_port,
                vendor,
                hardware_version,
                firmware,
                device_id,
            } => {
                w.u8(*protocol)
                    .u16(*min_version)
                    .u16(*max_version)
                    .u32(*flags)
                    .short_bytes(endpoint_host)
                    .u16(*endpoint_port)
                    .short_bytes(vendor)
                    .short_bytes(hardware_version)
                    .short_bytes(firmware)
                    .short_bytes(device_id);
            }
            SetupConnectionSuccess {
                used_version,
                flags,
            } => {
                w.u16(*used_version).u32(*flags);
            }
            SetupConnectionError { flags, error_code } => {
                w.u32(*flags).short_bytes(error_code);
            }
            ChannelEndpointChanged { channel_id } => {
                w.u32(*channel_id);
            }
            Reconnect { new_host, new_port } => {
                w.short_bytes(new_host).u16(*new_port);
            }
            OpenStandardMiningChannel {
                request_id,
                user_identity,
                nominal_hash_rate,
                max_target,
            } => {
                w.u32(*request_id)
                    .short_bytes(user_identity)
                    .f32(*nominal_hash_rate)
                    .u256(max_target);
            }
            OpenStandardMiningChannelSuccess {
                request_id,
                channel_id,
                target,
                extranonce_prefix,
                group_channel_id,
            } => {
                w.u32(*request_id)
                    .u32(*channel_id)
                    .u256(target)
                    .short_bytes(extranonce_prefix)
                    .u32(*group_channel_id);
            }
            OpenExtendedMiningChannel {
                request_id,
                user_identity,
                nominal_hash_rate,
                max_target,
                min_extranonce_size,
            } => {
                w.u32(*request_id)
                    .short_bytes(user_identity)
                    .f32(*nominal_hash_rate)
                    .u256(max_target)
                    .u16(*min_extranonce_size);
            }
            OpenExtendedMiningChannelSuccess {
                request_id,
                channel_id,
                target,
                extranonce_size,
                extranonce_prefix,
                group_channel_id,
            } => {
                w.u32(*request_id)
                    .u32(*channel_id)
                    .u256(target)
                    .u16(*extranonce_size)
                    .short_bytes(extranonce_prefix)
                    .u32(*group_channel_id);
            }
            OpenMiningChannelError {
                request_id,
                error_code,
            } => {
                w.u32(*request_id).short_bytes(error_code);
            }
            UpdateChannel {
                channel_id,
                nominal_hash_rate,
                max_target,
            } => {
                w.u32(*channel_id).f32(*nominal_hash_rate).u256(max_target);
            }
            UpdateChannelError {
                channel_id,
                error_code,
            } => {
                w.u32(*channel_id).short_bytes(error_code);
            }
            CloseChannel {
                channel_id,
                reason_code,
            } => {
                w.u32(*channel_id).short_bytes(reason_code);
            }
            SetExtranoncePrefix {
                channel_id,
                extranonce_prefix,
            } => {
                w.u32(*channel_id).short_bytes(extranonce_prefix);
            }
            SubmitSharesStandard {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                ntime,
                version,
            } => {
                w.u32(*channel_id)
                    .u32(*sequence_number)
                    .u32(*job_id)
                    .u32(*nonce)
                    .u32(*ntime)
                    .u32(*version);
            }
            SubmitSharesExtended {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                ntime,
                version,
                extranonce,
            } => {
                w.u32(*channel_id)
                    .u32(*sequence_number)
                    .u32(*job_id)
                    .u32(*nonce)
                    .u32(*ntime)
                    .u32(*version)
                    .short_bytes(extranonce);
            }
            SubmitSharesSuccess {
                channel_id,
                last_sequence_number,
                new_submits_accepted_count,
                new_shares_sum,
            } => {
                w.u32(*channel_id)
                    .u32(*last_sequence_number)
                    .u32(*new_submits_accepted_count)
                    .u64(*new_shares_sum);
            }
            SubmitSharesError {
                channel_id,
                sequence_number,
                error_code,
            } => {
                w.u32(*channel_id)
                    .u32(*sequence_number)
                    .short_bytes(error_code);
            }
            NewMiningJob {
                channel_id,
                job_id,
                min_ntime,
                version,
                merkle_root,
            } => {
                w.u32(*channel_id)
                    .u32(*job_id)
                    .option_u32(*min_ntime)
                    .u32(*version)
                    .u256(merkle_root);
            }
            NewExtendedMiningJob {
                channel_id,
                job_id,
                min_ntime,
                version,
                version_rolling_allowed,
                merkle_path,
                coinbase_tx_prefix,
                coinbase_tx_suffix,
            } => {
                w.u32(*channel_id)
                    .u32(*job_id)
                    .option_u32(*min_ntime)
                    .u32(*version)
                    .bool(*version_rolling_allowed)
                    .seq0_255_u256(merkle_path)
                    .b0_64k(coinbase_tx_prefix)
                    .b0_64k(coinbase_tx_suffix);
            }
            SetNewPrevHash {
                channel_id,
                job_id,
                prev_hash,
                min_ntime,
                nbits,
            } => {
                w.u32(*channel_id)
                    .u32(*job_id)
                    .u256(prev_hash)
                    .u32(*min_ntime)
                    .u32(*nbits);
            }
            SetTarget {
                channel_id,
                maximum_target,
            } => {
                w.u32(*channel_id).u256(maximum_target);
            }
            SetCustomMiningJob {
                channel_id,
                request_id,
                token,
                version,
                prev_hash,
                min_ntime,
                nbits,
                coinbase_tx_version,
                coinbase_prefix,
                coinbase_tx_input_n_sequence,
                coinbase_tx_outputs,
                coinbase_tx_locktime,
                merkle_path,
            } => {
                w.u32(*channel_id)
                    .u32(*request_id)
                    .short_bytes(token)
                    .u32(*version)
                    .u256(prev_hash)
                    .u32(*min_ntime)
                    .u32(*nbits)
                    .u32(*coinbase_tx_version)
                    .short_bytes(coinbase_prefix)
                    .u32(*coinbase_tx_input_n_sequence)
                    .b0_64k(coinbase_tx_outputs)
                    .u32(*coinbase_tx_locktime)
                    .seq0_255_u256(merkle_path);
            }
            SetCustomMiningJobSuccess {
                channel_id,
                request_id,
                job_id,
            } => {
                w.u32(*channel_id).u32(*request_id).u32(*job_id);
            }
            SetCustomMiningJobError {
                channel_id,
                request_id,
                error_code,
            } => {
                w.u32(*channel_id).u32(*request_id).short_bytes(error_code);
            }
            SetGroupChannel {
                group_channel_id,
                channel_ids,
            } => {
                w.u32(*group_channel_id).seq0_64k_u32(channel_ids);
            }
            AllocateMiningJobToken {
                user_identifier,
                request_id,
            } => {
                w.short_bytes(user_identifier).u32(*request_id);
            }
            AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token,
                coinbase_outputs,
            } => {
                w.u32(*request_id)
                    .short_bytes(mining_job_token)
                    .b0_64k(coinbase_outputs);
            }
            ProvideMissingTransactions {
                request_id,
                unknown_tx_position_list,
            } => {
                w.u32(*request_id).seq0_64k_u16(unknown_tx_position_list);
            }
            ProvideMissingTransactionsSuccess {
                request_id,
                transaction_list,
            } => {
                w.u32(*request_id).seq0_64k_b0_16m(transaction_list);
            }
            DeclareMiningJob {
                request_id,
                mining_job_token,
                version,
                coinbase_tx_prefix,
                coinbase_tx_suffix,
                wtxid_list,
                excess_data,
            } => {
                w.u32(*request_id)
                    .short_bytes(mining_job_token)
                    .u32(*version)
                    .b0_64k(coinbase_tx_prefix)
                    .b0_64k(coinbase_tx_suffix)
                    .seq0_64k_u256(wtxid_list)
                    .b0_64k(excess_data);
            }
            DeclareMiningJobSuccess {
                request_id,
                new_mining_job_token,
            } => {
                w.u32(*request_id).short_bytes(new_mining_job_token);
            }
            DeclareMiningJobError {
                request_id,
                error_code,
                error_details,
            } => {
                w.u32(*request_id)
                    .short_bytes(error_code)
                    .b0_64k(error_details);
            }
            PushSolution {
                extranonce,
                prev_hash,
                nonce,
                ntime,
                nbits,
                version,
            } => {
                w.short_bytes(extranonce)
                    .u256(prev_hash)
                    .u32(*nonce)
                    .u32(*ntime)
                    .u32(*nbits)
                    .u32(*version);
            }
            CoinbaseOutputConstraints {
                max_additional_size,
                max_additional_sigops,
            } => {
                w.u32(*max_additional_size).u16(*max_additional_sigops);
            }
            NewTemplate {
                template_id,
                future_template,
                version,
                coinbase_tx_version,
                coinbase_prefix,
                coinbase_tx_input_sequence,
                coinbase_tx_value_remaining,
                coinbase_tx_outputs_count,
                coinbase_tx_outputs,
                coinbase_tx_locktime,
                merkle_path,
            } => {
                w.u64(*template_id)
                    .bool(*future_template)
                    .u32(*version)
                    .u32(*coinbase_tx_version)
                    .short_bytes(coinbase_prefix)
                    .u32(*coinbase_tx_input_sequence)
                    .u64(*coinbase_tx_value_remaining)
                    .u32(*coinbase_tx_outputs_count)
                    .b0_64k(coinbase_tx_outputs)
                    .u32(*coinbase_tx_locktime)
                    .seq0_255_u256(merkle_path);
            }
            TemplateSetNewPrevHash {
                template_id,
                prev_hash,
                header_timestamp,
                nbits,
                target,
            } => {
                w.u64(*template_id)
                    .u256(prev_hash)
                    .u32(*header_timestamp)
                    .u32(*nbits)
                    .u256(target);
            }
            RequestTransactionData { template_id } => {
                w.u64(*template_id);
            }
            RequestTransactionDataSuccess {
                template_id,
                excess_data,
                transaction_list,
            } => {
                w.u64(*template_id)
                    .b0_64k(excess_data)
                    .seq0_64k_b0_16m(transaction_list);
            }
            RequestTransactionDataError {
                template_id,
                error_code,
            } => {
                w.u64(*template_id).short_bytes(error_code);
            }
            SubmitSolution {
                template_id,
                version,
                header_timestamp,
                header_nonce,
                coinbase_tx,
            } => {
                w.u64(*template_id)
                    .u32(*version)
                    .u32(*header_timestamp)
                    .u32(*header_nonce)
                    .b0_64k(coinbase_tx);
            }
        }
        let msg_type = self.msg_type();
        Frame {
            extension_type: if channel_bit(msg_type) {
                CHANNEL_MSG_BIT
            } else {
                0
            },
            msg_type,
            payload: w.0,
        }
    }

    /// Decode a core-protocol frame. Unknown message types, fields that run past the payload,
    /// bytes left over after the last field, and forbidden values are all errors.
    pub fn decode(frame: &Frame) -> Result<Message> {
        use Message::*;
        ensure!(
            frame.extension() == 0,
            "extension 0x{:04x} is not a core protocol message",
            frame.extension()
        );
        let mut r = Reader::new(&frame.payload);
        let m = match frame.msg_type {
            msg::SETUP_CONNECTION => SetupConnection {
                protocol: r.u8()?,
                min_version: r.u16()?,
                max_version: r.u16()?,
                flags: r.u32()?,
                endpoint_host: r.str0_255()?,
                endpoint_port: r.u16()?,
                vendor: r.str0_255()?,
                hardware_version: r.str0_255()?,
                firmware: r.str0_255()?,
                device_id: r.str0_255()?,
            },
            msg::SETUP_CONNECTION_SUCCESS => SetupConnectionSuccess {
                used_version: r.u16()?,
                flags: r.u32()?,
            },
            msg::SETUP_CONNECTION_ERROR => SetupConnectionError {
                flags: r.u32()?,
                error_code: r.str0_255()?,
            },
            msg::CHANNEL_ENDPOINT_CHANGED => ChannelEndpointChanged {
                channel_id: r.u32()?,
            },
            msg::RECONNECT => Reconnect {
                new_host: r.str0_255()?,
                new_port: r.u16()?,
            },
            msg::OPEN_STANDARD_MINING_CHANNEL => OpenStandardMiningChannel {
                request_id: r.u32()?,
                user_identity: r.str0_255()?,
                nominal_hash_rate: r.f32()?,
                max_target: r.u256()?,
            },
            msg::OPEN_STANDARD_MINING_CHANNEL_SUCCESS => OpenStandardMiningChannelSuccess {
                request_id: r.u32()?,
                channel_id: r.u32()?,
                target: r.u256()?,
                extranonce_prefix: r.b0_32()?,
                group_channel_id: r.u32()?,
            },
            msg::OPEN_EXTENDED_MINING_CHANNEL => OpenExtendedMiningChannel {
                request_id: r.u32()?,
                user_identity: r.str0_255()?,
                nominal_hash_rate: r.f32()?,
                max_target: r.u256()?,
                min_extranonce_size: r.u16()?,
            },
            msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => OpenExtendedMiningChannelSuccess {
                request_id: r.u32()?,
                channel_id: r.u32()?,
                target: r.u256()?,
                extranonce_size: r.u16()?,
                extranonce_prefix: r.b0_32()?,
                group_channel_id: r.u32()?,
            },
            msg::OPEN_MINING_CHANNEL_ERROR => OpenMiningChannelError {
                request_id: r.u32()?,
                error_code: r.str0_255()?,
            },
            msg::UPDATE_CHANNEL => UpdateChannel {
                channel_id: r.u32()?,
                nominal_hash_rate: r.f32()?,
                max_target: r.u256()?,
            },
            msg::UPDATE_CHANNEL_ERROR => UpdateChannelError {
                channel_id: r.u32()?,
                error_code: r.str0_255()?,
            },
            msg::CLOSE_CHANNEL => CloseChannel {
                channel_id: r.u32()?,
                reason_code: r.str0_255()?,
            },
            msg::SET_EXTRANONCE_PREFIX => SetExtranoncePrefix {
                channel_id: r.u32()?,
                extranonce_prefix: r.b0_32()?,
            },
            msg::SUBMIT_SHARES_STANDARD => SubmitSharesStandard {
                channel_id: r.u32()?,
                sequence_number: r.u32()?,
                job_id: r.u32()?,
                nonce: r.u32()?,
                ntime: r.u32()?,
                version: r.u32()?,
            },
            msg::SUBMIT_SHARES_EXTENDED => SubmitSharesExtended {
                channel_id: r.u32()?,
                sequence_number: r.u32()?,
                job_id: r.u32()?,
                nonce: r.u32()?,
                ntime: r.u32()?,
                version: r.u32()?,
                extranonce: r.b0_32()?,
            },
            msg::SUBMIT_SHARES_SUCCESS => SubmitSharesSuccess {
                channel_id: r.u32()?,
                last_sequence_number: r.u32()?,
                new_submits_accepted_count: r.u32()?,
                new_shares_sum: r.u64()?,
            },
            msg::SUBMIT_SHARES_ERROR => SubmitSharesError {
                channel_id: r.u32()?,
                sequence_number: r.u32()?,
                error_code: r.str0_255()?,
            },
            msg::NEW_MINING_JOB => NewMiningJob {
                channel_id: r.u32()?,
                job_id: r.u32()?,
                min_ntime: r.option_u32()?,
                version: r.u32()?,
                merkle_root: r.u256()?,
            },
            msg::NEW_EXTENDED_MINING_JOB => NewExtendedMiningJob {
                channel_id: r.u32()?,
                job_id: r.u32()?,
                min_ntime: r.option_u32()?,
                version: r.u32()?,
                version_rolling_allowed: r.bool()?,
                merkle_path: r.seq0_255_u256()?,
                coinbase_tx_prefix: r.b0_64k()?,
                coinbase_tx_suffix: r.b0_64k()?,
            },
            msg::SET_NEW_PREV_HASH => SetNewPrevHash {
                channel_id: r.u32()?,
                job_id: r.u32()?,
                prev_hash: r.u256()?,
                min_ntime: r.u32()?,
                nbits: r.u32()?,
            },
            msg::SET_TARGET => SetTarget {
                channel_id: r.u32()?,
                maximum_target: r.u256()?,
            },
            msg::SET_CUSTOM_MINING_JOB => SetCustomMiningJob {
                channel_id: r.u32()?,
                request_id: r.u32()?,
                token: r.b0_255()?,
                version: r.u32()?,
                prev_hash: r.u256()?,
                min_ntime: r.u32()?,
                nbits: r.u32()?,
                coinbase_tx_version: r.u32()?,
                coinbase_prefix: r.b0_255()?,
                coinbase_tx_input_n_sequence: r.u32()?,
                coinbase_tx_outputs: r.b0_64k()?,
                coinbase_tx_locktime: r.u32()?,
                merkle_path: r.seq0_255_u256()?,
            },
            msg::SET_CUSTOM_MINING_JOB_SUCCESS => SetCustomMiningJobSuccess {
                channel_id: r.u32()?,
                request_id: r.u32()?,
                job_id: r.u32()?,
            },
            msg::SET_CUSTOM_MINING_JOB_ERROR => SetCustomMiningJobError {
                channel_id: r.u32()?,
                request_id: r.u32()?,
                error_code: r.str0_255()?,
            },
            msg::SET_GROUP_CHANNEL => SetGroupChannel {
                group_channel_id: r.u32()?,
                channel_ids: r.seq0_64k_u32()?,
            },
            msg::ALLOCATE_MINING_JOB_TOKEN => AllocateMiningJobToken {
                user_identifier: r.str0_255()?,
                request_id: r.u32()?,
            },
            msg::ALLOCATE_MINING_JOB_TOKEN_SUCCESS => AllocateMiningJobTokenSuccess {
                request_id: r.u32()?,
                mining_job_token: r.b0_255()?,
                coinbase_outputs: r.b0_64k()?,
            },
            msg::PROVIDE_MISSING_TRANSACTIONS => ProvideMissingTransactions {
                request_id: r.u32()?,
                unknown_tx_position_list: r.seq0_64k_u16()?,
            },
            msg::PROVIDE_MISSING_TRANSACTIONS_SUCCESS => ProvideMissingTransactionsSuccess {
                request_id: r.u32()?,
                transaction_list: r.seq0_64k_b0_16m()?,
            },
            msg::DECLARE_MINING_JOB => DeclareMiningJob {
                request_id: r.u32()?,
                mining_job_token: r.b0_255()?,
                version: r.u32()?,
                coinbase_tx_prefix: r.b0_64k()?,
                coinbase_tx_suffix: r.b0_64k()?,
                wtxid_list: r.seq0_64k_u256()?,
                excess_data: r.b0_64k()?,
            },
            msg::DECLARE_MINING_JOB_SUCCESS => DeclareMiningJobSuccess {
                request_id: r.u32()?,
                new_mining_job_token: r.b0_255()?,
            },
            msg::DECLARE_MINING_JOB_ERROR => DeclareMiningJobError {
                request_id: r.u32()?,
                error_code: r.str0_255()?,
                error_details: r.b0_64k()?,
            },
            msg::PUSH_SOLUTION => PushSolution {
                extranonce: r.b0_32()?,
                prev_hash: r.u256()?,
                nonce: r.u32()?,
                ntime: r.u32()?,
                nbits: r.u32()?,
                version: r.u32()?,
            },
            msg::COINBASE_OUTPUT_CONSTRAINTS => CoinbaseOutputConstraints {
                max_additional_size: r.u32()?,
                max_additional_sigops: r.u16()?,
            },
            msg::NEW_TEMPLATE => NewTemplate {
                template_id: r.u64()?,
                future_template: r.bool()?,
                version: r.u32()?,
                coinbase_tx_version: r.u32()?,
                coinbase_prefix: r.b0_255()?,
                coinbase_tx_input_sequence: r.u32()?,
                coinbase_tx_value_remaining: r.u64()?,
                coinbase_tx_outputs_count: r.u32()?,
                coinbase_tx_outputs: r.b0_64k()?,
                coinbase_tx_locktime: r.u32()?,
                merkle_path: r.seq0_255_u256()?,
            },
            msg::TEMPLATE_SET_NEW_PREV_HASH => TemplateSetNewPrevHash {
                template_id: r.u64()?,
                prev_hash: r.u256()?,
                header_timestamp: r.u32()?,
                nbits: r.u32()?,
                target: r.u256()?,
            },
            msg::REQUEST_TRANSACTION_DATA => RequestTransactionData {
                template_id: r.u64()?,
            },
            msg::REQUEST_TRANSACTION_DATA_SUCCESS => RequestTransactionDataSuccess {
                template_id: r.u64()?,
                excess_data: r.b0_64k()?,
                transaction_list: r.seq0_64k_b0_16m()?,
            },
            msg::REQUEST_TRANSACTION_DATA_ERROR => RequestTransactionDataError {
                template_id: r.u64()?,
                error_code: r.str0_255()?,
            },
            msg::SUBMIT_SOLUTION => SubmitSolution {
                template_id: r.u64()?,
                version: r.u32()?,
                header_timestamp: r.u32()?,
                header_nonce: r.u32()?,
                coinbase_tx: r.b0_64k()?,
            },
            other => bail!(
                "message type 0x{other:02x} ({}) is not handled",
                name_of(other)
            ),
        };
        r.finish()
            .with_context(|| format!("{} is malformed", name_of(frame.msg_type)))?;
        Ok(m)
    }
}

pub fn name_of(msg_type: u8) -> &'static str {
    match msg_type {
        msg::SETUP_CONNECTION => "SetupConnection",
        msg::SETUP_CONNECTION_SUCCESS => "SetupConnection.Success",
        msg::SETUP_CONNECTION_ERROR => "SetupConnection.Error",
        msg::CHANNEL_ENDPOINT_CHANGED => "ChannelEndpointChanged",
        msg::RECONNECT => "Reconnect",
        msg::OPEN_STANDARD_MINING_CHANNEL => "OpenStandardMiningChannel",
        msg::OPEN_STANDARD_MINING_CHANNEL_SUCCESS => "OpenStandardMiningChannel.Success",
        msg::OPEN_MINING_CHANNEL_ERROR => "OpenMiningChannel.Error",
        msg::OPEN_EXTENDED_MINING_CHANNEL => "OpenExtendedMiningChannel",
        msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => "OpenExtendedMiningChannel.Success",
        msg::NEW_MINING_JOB => "NewMiningJob",
        msg::UPDATE_CHANNEL => "UpdateChannel",
        msg::UPDATE_CHANNEL_ERROR => "UpdateChannel.Error",
        msg::CLOSE_CHANNEL => "CloseChannel",
        msg::SET_EXTRANONCE_PREFIX => "SetExtranoncePrefix",
        msg::SUBMIT_SHARES_STANDARD => "SubmitSharesStandard",
        msg::SUBMIT_SHARES_EXTENDED => "SubmitSharesExtended",
        msg::SUBMIT_SHARES_SUCCESS => "SubmitShares.Success",
        msg::SUBMIT_SHARES_ERROR => "SubmitShares.Error",
        msg::NEW_EXTENDED_MINING_JOB => "NewExtendedMiningJob",
        msg::SET_NEW_PREV_HASH => "SetNewPrevHash",
        msg::SET_TARGET => "SetTarget",
        msg::SET_CUSTOM_MINING_JOB => "SetCustomMiningJob",
        msg::SET_CUSTOM_MINING_JOB_SUCCESS => "SetCustomMiningJob.Success",
        msg::SET_CUSTOM_MINING_JOB_ERROR => "SetCustomMiningJob.Error",
        msg::SET_GROUP_CHANNEL => "SetGroupChannel",
        msg::ALLOCATE_MINING_JOB_TOKEN => "AllocateMiningJobToken",
        msg::ALLOCATE_MINING_JOB_TOKEN_SUCCESS => "AllocateMiningJobToken.Success",
        msg::PROVIDE_MISSING_TRANSACTIONS => "ProvideMissingTransactions",
        msg::PROVIDE_MISSING_TRANSACTIONS_SUCCESS => "ProvideMissingTransactions.Success",
        msg::DECLARE_MINING_JOB => "DeclareMiningJob",
        msg::DECLARE_MINING_JOB_SUCCESS => "DeclareMiningJob.Success",
        msg::DECLARE_MINING_JOB_ERROR => "DeclareMiningJob.Error",
        msg::PUSH_SOLUTION => "PushSolution",
        msg::COINBASE_OUTPUT_CONSTRAINTS => "CoinbaseOutputConstraints",
        msg::NEW_TEMPLATE => "NewTemplate",
        msg::TEMPLATE_SET_NEW_PREV_HASH => "SetNewPrevHash (Template Distribution)",
        msg::REQUEST_TRANSACTION_DATA => "RequestTransactionData",
        msg::REQUEST_TRANSACTION_DATA_SUCCESS => "RequestTransactionData.Success",
        msg::REQUEST_TRANSACTION_DATA_ERROR => "RequestTransactionData.Error",
        msg::SUBMIT_SOLUTION => "SubmitSolution",
        _ => "unknown",
    }
}

/// A peer-supplied string as events and logs show it: lossy UTF-8 with controls dropped.
pub fn text(bytes: &[u8]) -> String {
    crate::utils::sanitize::strip_controls(&String::from_utf8_lossy(bytes))
}

/// Error codes are printable ASCII (sv2-spec §3.5), at most 255 bytes.
pub fn valid_error_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 255 && code.bytes().all(|b| (0x20..0x7f).contains(&b))
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// The 80-byte block header a share commits to. Hashes go in as the raw bytes U256 carries.
pub fn header(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[4..36].copy_from_slice(prev_hash);
    h[36..68].copy_from_slice(merkle_root);
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&nbits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// Whether a hash, read as a little-endian 256-bit number, is at most the target.
pub fn meets(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if hash[i] != target[i] {
            return hash[i] < target[i];
        }
    }
    true
}

/// A little-endian 256-bit number as a float.
pub fn le_value(n: &[u8; 32]) -> f64 {
    n.iter()
        .rev()
        .fold(0f64, |acc, b| acc * 256.0 + f64::from(*b))
}

/// The difficulty a hash meets: DIFF1 / hash.
pub fn difficulty(hash: &[u8; 32]) -> f64 {
    let v = le_value(hash);
    if v == 0.0 {
        f64::MAX
    } else {
        DIFF1 / v
    }
}

/// The difficulty a target stands for.
pub fn target_difficulty(target: &[u8; 32]) -> f64 {
    difficulty(target)
}

/// The target for a difficulty: DIFF1 / difficulty, the largest target when that overflows.
pub fn target_for(difficulty: f64) -> [u8; 32] {
    if !(difficulty.is_finite() && difficulty > 0.0) {
        return [0xff; 32];
    }
    let t = DIFF1 / difficulty;
    if t.is_nan() || t >= 2f64.powi(256) {
        return [0xff; 32];
    }
    if t < 1.0 {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    // t = m · 2^e with a 53-bit integer m; write m shifted left by e.
    let bits = t.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1075;
    let mantissa = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let mut out = [0u8; 32];
    if exp < 0 {
        let v = mantissa >> (-exp);
        out[..8].copy_from_slice(&v.to_le_bytes());
        return out;
    }
    let (byte_shift, bit_shift) = ((exp / 8) as usize, (exp % 8) as u32);
    let wide = u128::from(mantissa) << bit_shift;
    for (i, b) in wide.to_le_bytes().iter().enumerate() {
        if let Some(slot) = out.get_mut(byte_shift + i) {
            *slot = *b;
        }
    }
    out
}

/// The smaller of two targets.
pub fn min_target(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    if meets(&a, &b) {
        a
    } else {
        b
    }
}

/// A hash as block explorers and RPC show it: byte-reversed hex.
pub fn display_hex(hash: &[u8; 32]) -> String {
    let mut h = *hash;
    h.reverse();
    hex::encode(h)
}

/// A hash written as RPC shows it, back to raw bytes. None means all zeros.
pub fn parse_display_hash(s: Option<&str>) -> Result<[u8; 32]> {
    let Some(s) = s.filter(|s| !s.is_empty()) else {
        return Ok([0u8; 32]);
    };
    let mut b: [u8; 32] = hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("prev_hash must be 64 hex digits")?;
    b.reverse();
    Ok(b)
}

/// The merkle root a coinbase and a path (deepest first) give.
pub fn merkle_root(coinbase: &[u8], path: &[[u8; 32]]) -> [u8; 32] {
    let mut root = sha256d(coinbase);
    for leaf in path {
        let mut both = [0u8; 64];
        both[..32].copy_from_slice(&root);
        both[32..].copy_from_slice(leaf);
        root = sha256d(&both);
    }
    root
}

/// A script push of `data` (at most 75 bytes, a single opcode).
fn push(script: &mut Vec<u8>, data: &[u8]) {
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

/// BIP 34's height push: the minimal little-endian encoding of a positive height.
fn height_push(height: u32) -> Vec<u8> {
    let mut n = height.to_le_bytes().to_vec();
    while n.len() > 1 && n[n.len() - 1] == 0 {
        n.pop();
    }
    if n[n.len() - 1] & 0x80 != 0 {
        n.push(0);
    }
    n
}

/// A pool job's coinbase, split where the extranonce goes: a version-2 transaction with one
/// input whose scriptSig pushes the BIP 34 height, the message and `extranonce_len` bytes of
/// extranonce (prefix and miner's part together), and one zero-value `OP_RETURN "netget"`
/// output. Nothing else is in the block, so the merkle path is empty.
pub fn coinbase_halves(height: u32, message: &[u8], extranonce_len: usize) -> (Vec<u8>, Vec<u8>) {
    let message = &message[..message.len().min(MAX_COINBASE_MESSAGE)];
    let mut script = Vec::new();
    push(&mut script, &height_push(height));
    if !message.is_empty() {
        push(&mut script, message);
    }
    script.push(extranonce_len as u8);
    let script_len = script.len() + extranonce_len;
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&2u32.to_le_bytes());
    prefix.push(1);
    prefix.extend_from_slice(&[0u8; 32]);
    prefix.extend_from_slice(&u32::MAX.to_le_bytes());
    prefix.push(script_len as u8);
    prefix.extend_from_slice(&script);
    let mut suffix = Vec::new();
    suffix.extend_from_slice(&u32::MAX.to_le_bytes());
    suffix.push(1);
    suffix.extend_from_slice(&0u64.to_le_bytes());
    let out_script = [&[0x6a, 6][..], b"netget"].concat();
    suffix.push(out_script.len() as u8);
    suffix.extend_from_slice(&out_script);
    suffix.extend_from_slice(&0u32.to_le_bytes());
    (prefix, suffix)
}

/// Whether a share's version differs from the job's only in the bits a miner may roll.
pub fn version_allowed(job_version: u32, share_version: u32, rolling: bool) -> bool {
    if rolling {
        (job_version ^ share_version) & !VERSION_ROLLING_MASK == 0
    } else {
        job_version == share_version
    }
}

pub fn now_secs() -> u32 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// SetupConnection flags by name, for events.
pub fn flag_names(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & REQUIRES_STANDARD_JOBS != 0 {
        out.push("REQUIRES_STANDARD_JOBS");
    }
    if flags & REQUIRES_WORK_SELECTION != 0 {
        out.push("REQUIRES_WORK_SELECTION");
    }
    if flags & REQUIRES_VERSION_ROLLING != 0 {
        out.push("REQUIRES_VERSION_ROLLING");
    }
    if flags & !0b111 != 0 {
        out.push("UNKNOWN");
    }
    out
}

/// Responder side of the handshake on a fresh connection: read `-> e` within `deadline`,
/// answer with the static key and its certificate. The session keys come back.
pub async fn accept_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    static_key: &super::noise::EllKey,
    authority: &super::noise::Authority,
    validity_secs: u32,
    deadline: Duration,
) -> Result<Session> {
    let mut first = [0u8; super::noise::INITIATOR_MESSAGE_LEN];
    tokio::time::timeout(deadline, stream.read_exact(&mut first))
        .await
        .context("Stratum V2 handshake deadline")?
        .context("connection closed during the Noise handshake")?;
    let (reply, session) =
        super::noise::respond(&first, static_key, authority, validity_secs, now_secs())?;
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&reply))
        .await
        .context("Stratum V2 write deadline")??;
    Ok(session)
}

/// Initiator side: send `-> e`, read the responder's answer within `deadline` and verify its
/// certificate against `authority` before returning the session.
pub async fn connect_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authority: &[u8; 32],
    deadline: Duration,
) -> Result<(Session, super::noise::Certificate)> {
    let (initiator, first) = super::noise::Initiator::start()?;
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&first))
        .await
        .context("Stratum V2 write deadline")??;
    let mut reply = [0u8; super::noise::RESPONDER_MESSAGE_LEN];
    tokio::time::timeout(deadline, stream.read_exact(&mut reply))
        .await
        .context("Stratum V2 handshake deadline")?
        .context("the pool closed the connection during the Noise handshake")?;
    initiator.finish(&reply, authority, now_secs())
}
