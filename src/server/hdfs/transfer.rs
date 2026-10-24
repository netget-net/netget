//! Hadoop's DataTransferProtocol, version 28: the op header (two-byte version, one-byte op,
//! a varint-delimited op message), varint-delimited responses and acks, and the packets that
//! carry block data — `PLEN` (four bytes: itself, the checksums and the data), `HLEN` (two
//! bytes), a `PacketHeaderProto`, the chunk checksums (four bytes each, big-endian) and the
//! data. Checksums are CRC32C or CRC32 over chunks of `bytesPerChecksum` bytes. Shared by the
//! DataNode, the HDFS client and the fuzz target.
use super::proto::hdfs::{ChecksumTypeProto, PacketHeaderProto};
use anyhow::{bail, ensure, Context, Result};
use prost::Message;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const DATA_TRANSFER_VERSION: u16 = 28;

/// Op codes (`org.apache.hadoop.hdfs.protocol.datatransfer.Op`).
pub mod op {
    pub const WRITE_BLOCK: u8 = 80;
    pub const READ_BLOCK: u8 = 81;
    pub const READ_METADATA: u8 = 82;
    pub const REPLACE_BLOCK: u8 = 83;
    pub const COPY_BLOCK: u8 = 84;
    pub const BLOCK_CHECKSUM: u8 = 85;
    pub const TRANSFER_BLOCK: u8 = 86;
    pub const REQUEST_SHORT_CIRCUIT_FDS: u8 = 87;
    pub const RELEASE_SHORT_CIRCUIT_FDS: u8 = 88;
    pub const REQUEST_SHORT_CIRCUIT_SHM: u8 = 89;
    pub const BLOCK_GROUP_CHECKSUM: u8 = 90;
    pub const CUSTOM: u8 = 127;

    pub fn name(op: u8) -> &'static str {
        match op {
            WRITE_BLOCK => "WRITE_BLOCK",
            READ_BLOCK => "READ_BLOCK",
            READ_METADATA => "READ_METADATA",
            REPLACE_BLOCK => "REPLACE_BLOCK",
            COPY_BLOCK => "COPY_BLOCK",
            BLOCK_CHECKSUM => "BLOCK_CHECKSUM",
            TRANSFER_BLOCK => "TRANSFER_BLOCK",
            REQUEST_SHORT_CIRCUIT_FDS => "REQUEST_SHORT_CIRCUIT_FDS",
            RELEASE_SHORT_CIRCUIT_FDS => "RELEASE_SHORT_CIRCUIT_FDS",
            REQUEST_SHORT_CIRCUIT_SHM => "REQUEST_SHORT_CIRCUIT_SHM",
            BLOCK_GROUP_CHECKSUM => "BLOCK_GROUP_CHECKSUM",
            CUSTOM => "CUSTOM",
            _ => "UNKNOWN",
        }
    }
}

/// The largest op message or response read (an op names a block and a few nodes).
pub const MAX_OP_MESSAGE: usize = 64 * 1024;
/// The most data one packet may carry, decided from PLEN and the header before it is read.
/// Hadoop's own DataNode refuses packets over 16 MB; its client sends 64 KiB.
pub const MAX_PACKET_DATA: usize = 1 << 20;
/// The largest packet header (HLEN).
pub const MAX_PACKET_HEADER: usize = 1024;
/// The chunk sizes accepted: Hadoop's default is 512.
pub const MIN_BYTES_PER_CHECKSUM: u32 = 16;
pub const MAX_BYTES_PER_CHECKSUM: u32 = 64 * 1024;
/// The chunk size NetGet uses for what it sends.
pub const BYTES_PER_CHECKSUM: u32 = 512;
/// The data NetGet puts in one packet it sends.
pub const SEND_PACKET_DATA: usize = 64 * 1024;
/// The varint in front of a delimited message.
const MAX_VARINT_BYTES: usize = 5;

/// The checksum types: CRC32C and CRC32 (NULL only where checksums are not sent at all).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checksum {
    Null,
    Crc32,
    Crc32c,
}

impl Checksum {
    pub fn from_proto(t: i32) -> Option<Self> {
        match ChecksumTypeProto::try_from(t).ok()? {
            ChecksumTypeProto::ChecksumNull => Some(Checksum::Null),
            ChecksumTypeProto::ChecksumCrc32 => Some(Checksum::Crc32),
            ChecksumTypeProto::ChecksumCrc32c => Some(Checksum::Crc32c),
        }
    }
    pub fn proto(self) -> i32 {
        let t = match self {
            Checksum::Null => ChecksumTypeProto::ChecksumNull,
            Checksum::Crc32 => ChecksumTypeProto::ChecksumCrc32,
            Checksum::Crc32c => ChecksumTypeProto::ChecksumCrc32c,
        };
        t as i32
    }
    pub fn name(self) -> &'static str {
        match self {
            Checksum::Null => "NULL",
            Checksum::Crc32 => "CRC32",
            Checksum::Crc32c => "CRC32C",
        }
    }
    /// Bytes of checksum per chunk.
    pub fn size(self) -> usize {
        match self {
            Checksum::Null => 0,
            _ => 4,
        }
    }
    pub fn of(self, chunk: &[u8]) -> u32 {
        match self {
            Checksum::Null => 0,
            Checksum::Crc32 => crc32fast::hash(chunk),
            Checksum::Crc32c => crc32c::crc32c(chunk),
        }
    }
}

/// The checksums of `data` in chunks of `bpc` bytes, big-endian, as a packet carries them.
pub fn checksums(kind: Checksum, bpc: u32, data: &[u8]) -> Vec<u8> {
    if kind == Checksum::Null {
        return vec![];
    }
    let mut out = Vec::with_capacity(data.len().div_ceil(bpc as usize) * 4);
    for chunk in data.chunks(bpc as usize) {
        out.extend_from_slice(&kind.of(chunk).to_be_bytes());
    }
    out
}

/// Check `data` against the checksums a packet carried: `Err(i)` names the first chunk whose
/// checksum does not match (or the count, when the checksum bytes do not fit the data).
pub fn verify(
    kind: Checksum,
    bpc: u32,
    data: &[u8],
    sums: &[u8],
) -> std::result::Result<(), usize> {
    if kind == Checksum::Null {
        return if sums.is_empty() { Ok(()) } else { Err(0) };
    }
    let chunks = data.len().div_ceil(bpc as usize);
    if sums.len() != chunks * 4 {
        return Err(chunks);
    }
    for (i, (chunk, sum)) in data.chunks(bpc as usize).zip(sums.chunks(4)).enumerate() {
        if kind.of(chunk).to_be_bytes() != sum {
            return Err(i);
        }
    }
    Ok(())
}

/// One packet.
#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    pub header: PacketHeaderProto,
    pub sums: Vec<u8>,
    pub data: Vec<u8>,
}

/// The bounds a packet is read under.
#[derive(Clone, Copy, Debug)]
pub struct PacketLimits {
    pub max_data: usize,
    pub max_sums: usize,
}

impl PacketLimits {
    /// The bounds for packets carrying chunks of `bpc` bytes with `kind` checksums.
    pub fn for_chunks(kind: Checksum, bpc: u32) -> Self {
        let max_data = MAX_PACKET_DATA;
        Self {
            max_data,
            max_sums: max_data.div_ceil(bpc.max(1) as usize) * kind.size(),
        }
    }
    /// The widest bounds any accepted chunk size allows (the fuzz target's).
    pub fn widest() -> Self {
        Self::for_chunks(Checksum::Crc32c, MIN_BYTES_PER_CHECKSUM)
    }
}

pub fn encode_packet(header: &PacketHeaderProto, sums: &[u8], data: &[u8]) -> Vec<u8> {
    let h = header.encode_to_vec();
    let plen = 4 + sums.len() + data.len();
    let mut out = Vec::with_capacity(6 + h.len() + sums.len() + data.len());
    out.extend_from_slice(&(plen as u32).to_be_bytes());
    out.extend_from_slice(&(h.len() as u16).to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(sums);
    out.extend_from_slice(data);
    out
}

/// A packet that carries `data` from `offset` in its block, its checksums computed.
pub fn data_packet(
    kind: Checksum,
    bpc: u32,
    offset: u64,
    seqno: i64,
    last: bool,
    data: &[u8],
) -> Vec<u8> {
    let header = PacketHeaderProto {
        offset_in_block: offset as i64,
        seqno,
        last_packet_in_block: last,
        data_len: data.len() as i32,
        sync_block: Some(false),
    };
    encode_packet(&header, &checksums(kind, bpc, data), data)
}

/// Check PLEN and HLEN before anything else of a packet is read; the payload length (checksums
/// and data) after the header.
pub fn check_prefix(plen: u32, hlen: u16, limits: &PacketLimits) -> Result<usize> {
    ensure!(plen >= 4, "PLEN {plen} is smaller than itself");
    ensure!(
        (hlen as usize) <= MAX_PACKET_HEADER,
        "a packet header of {hlen} bytes is over {MAX_PACKET_HEADER}"
    );
    let payload = plen as usize - 4;
    ensure!(
        payload <= limits.max_data + limits.max_sums,
        "a packet of {payload} bytes is over the bound"
    );
    Ok(payload)
}

/// Check a decoded header against the payload that follows it: the data length the header
/// names must fit the payload and leave the checksums within their bound.
pub fn check_header(h: &PacketHeaderProto, payload: usize, limits: &PacketLimits) -> Result<()> {
    ensure!(h.data_len >= 0, "a negative data length");
    let data = h.data_len as usize;
    ensure!(
        data <= limits.max_data,
        "{data} bytes of data is over the bound"
    );
    ensure!(
        data <= payload,
        "the header names {data} bytes of data in a payload of {payload}"
    );
    ensure!(
        payload - data <= limits.max_sums,
        "{} bytes of checksums is over the bound",
        payload - data
    );
    ensure!(h.offset_in_block >= 0, "a negative offset in the block");
    Ok(())
}

/// Decode one packet from the front of `buf`; the packet and the bytes it took.
pub fn decode_packet(buf: &[u8], limits: &PacketLimits) -> Result<(Packet, usize)> {
    ensure!(buf.len() >= 6, "a packet prefix is six bytes");
    let plen = u32::from_be_bytes(buf[0..4].try_into().expect("four bytes"));
    let hlen = u16::from_be_bytes([buf[4], buf[5]]);
    let payload = check_prefix(plen, hlen, limits)?;
    let end = 6 + hlen as usize + payload;
    ensure!(buf.len() >= end, "the packet runs past the buffer");
    let header = PacketHeaderProto::decode(&buf[6..6 + hlen as usize])
        .context("a malformed packet header")?;
    check_header(&header, payload, limits)?;
    let body = &buf[6 + hlen as usize..end];
    let data_len = header.data_len as usize;
    let sums = body[..payload - data_len].to_vec();
    let data = body[payload - data_len..].to_vec();
    Ok((Packet { header, sums, data }, end))
}

#[derive(Debug)]
pub enum ReadError {
    Closed,
    /// Nothing began before the idle deadline.
    Idle,
    /// The first byte arrived and the rest did not arrive in time.
    Timeout,
    Invalid(anyhow::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Closed => write!(f, "the peer closed the connection"),
            ReadError::Idle => write!(f, "nothing began before the idle deadline"),
            ReadError::Timeout => write!(f, "the rest did not arrive in time"),
            ReadError::Invalid(e) => write!(f, "{e:#}"),
            ReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadError::Closed
        } else {
            ReadError::Io(e)
        }
    }
}

/// Wait up to `idle` for one byte (`Closed` at end of stream).
async fn first_byte<R: AsyncRead + Unpin>(
    r: &mut R,
    idle: Duration,
) -> std::result::Result<u8, ReadError> {
    let mut b = [0u8; 1];
    match tokio::time::timeout(idle, r.read(&mut b)).await {
        Err(_) => Err(ReadError::Idle),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(0)) => Err(ReadError::Closed),
        Ok(Ok(_)) => Ok(b[0]),
    }
}

/// Read one packet: its first byte within `idle`, the rest within `rest`.
pub async fn read_packet<R: AsyncRead + Unpin>(
    r: &mut R,
    limits: &PacketLimits,
    idle: Duration,
    rest: Duration,
) -> std::result::Result<Packet, ReadError> {
    let b0 = first_byte(r, idle).await?;
    let body = async {
        let mut prefix = [0u8; 6];
        prefix[0] = b0;
        r.read_exact(&mut prefix[1..]).await?;
        let plen = u32::from_be_bytes(prefix[0..4].try_into().expect("four bytes"));
        let hlen = u16::from_be_bytes([prefix[4], prefix[5]]);
        let payload = check_prefix(plen, hlen, limits).map_err(ReadError::Invalid)?;
        let mut h = vec![0u8; hlen as usize];
        r.read_exact(&mut h).await?;
        let header = PacketHeaderProto::decode(h.as_slice())
            .map_err(|e| ReadError::Invalid(anyhow::anyhow!("a malformed packet header: {e}")))?;
        check_header(&header, payload, limits).map_err(ReadError::Invalid)?;
        let mut body = vec![0u8; payload];
        r.read_exact(&mut body).await?;
        let data = body.split_off(payload - header.data_len as usize);
        Ok::<_, ReadError>(Packet {
            header,
            sums: body,
            data,
        })
    };
    match tokio::time::timeout(rest, body).await {
        Err(_) => Err(ReadError::Timeout),
        Ok(r) => r,
    }
}

/// Read and decode a varint-delimited message (see [`read_delimited_bytes`]).
pub async fn read_delimited<M: Message + Default, R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
    idle: Duration,
    rest: Duration,
) -> std::result::Result<M, ReadError> {
    let bytes = read_delimited_bytes(r, max, idle, rest).await?;
    M::decode(bytes.as_slice())
        .map_err(|e| ReadError::Invalid(anyhow::anyhow!("a malformed message: {e}")))
}

/// Read a varint-delimited message's bytes, at most `max` of them: its first byte within
/// `idle`, the rest within `rest`. The length is checked before the body is read.
pub async fn read_delimited_bytes<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
    idle: Duration,
    rest: Duration,
) -> std::result::Result<Vec<u8>, ReadError> {
    let b0 = first_byte(r, idle).await?;
    let body = async {
        let mut len: u64 = (b0 & 0x7F) as u64;
        let mut more = b0 & 0x80 != 0;
        let mut i = 1;
        while more {
            if i >= MAX_VARINT_BYTES {
                return Err(ReadError::Invalid(anyhow::anyhow!(
                    "a delimited length longer than five bytes"
                )));
            }
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await?;
            len |= ((b[0] & 0x7F) as u64) << (7 * i);
            more = b[0] & 0x80 != 0;
            i += 1;
        }
        if len > max as u64 {
            return Err(ReadError::Invalid(anyhow::anyhow!(
                "a message of {len} bytes is over {max}"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    };
    match tokio::time::timeout(rest, body).await {
        Err(_) => Err(ReadError::Timeout),
        Ok(r) => r,
    }
}

/// Read an op header: the version and op code, then the delimited op message's bytes.
pub async fn read_op<R: AsyncRead + Unpin>(
    r: &mut R,
    idle: Duration,
    rest: Duration,
) -> std::result::Result<(u16, u8, Vec<u8>), ReadError> {
    let b0 = first_byte(r, idle).await?;
    let body = async {
        let mut rest_of = [0u8; 2];
        r.read_exact(&mut rest_of).await?;
        let version = u16::from_be_bytes([b0, rest_of[0]]);
        Ok::<_, ReadError>((version, rest_of[1]))
    };
    let (version, code) = match tokio::time::timeout(rest, body).await {
        Err(_) => return Err(ReadError::Timeout),
        Ok(r) => r?,
    };
    if version != DATA_TRANSFER_VERSION {
        return Ok((version, code, vec![]));
    }
    let message = read_delimited_bytes(r, MAX_OP_MESSAGE, rest, rest).await?;
    Ok((version, code, message))
}

/// An op request: the version, the op code and the delimited op message.
pub fn op_request(code: u8, message: &impl Message) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&DATA_TRANSFER_VERSION.to_be_bytes());
    out.push(code);
    out.extend_from_slice(&message.encode_length_delimited_to_vec());
    out
}

/// Decode an op message read by [`read_op`].
pub fn decode_op<M: Message + Default>(bytes: &[u8]) -> Result<M> {
    M::decode(bytes).context("a malformed op message")
}

/// MD5 over a block's chunk checksums: what OP_BLOCK_CHECKSUM answers.
pub fn block_md5(sums: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(sums);
    h.finalize().into()
}

/// Whether a packet of `len` bytes at `offset` in its block keeps the block's chunks aligned:
/// one that starts inside a chunk must end at or before that chunk's end, because its
/// checksums are taken from its own first byte. This is how an append continues a partial
/// last chunk — that chunk travels alone, its checksum over the new bytes only — and what
/// Hadoop's DataNode means by "a partial chunk must be sent in an individual packet".
pub fn keeps_chunks_aligned(offset: u64, len: usize, bpc: u32) -> bool {
    let into = offset % bpc.max(1) as u64;
    into == 0 || into + len as u64 <= bpc as u64
}

/// How a writer cuts `len` bytes starting at `offset` in a block into packets of at most `max`
/// bytes: when `offset` is inside a chunk the first packet ends at that chunk's end (or at the
/// end of the data), and every later packet starts on a chunk boundary and carries whole chunks
/// (the last one excepted). `(offset in block, length)` per packet, in order.
pub fn packet_spans(offset: u64, len: u64, bpc: u32, max: usize) -> Vec<(u64, u64)> {
    let bpc = bpc.max(1) as u64;
    // Whole chunks per packet, at least one.
    let per = ((max as u64 / bpc).max(1)) * bpc;
    let mut out = Vec::new();
    let mut at = offset;
    let end = offset.saturating_add(len);
    if !at.is_multiple_of(bpc) && at < end {
        let n = (bpc - at % bpc).min(end - at);
        out.push((at, n));
        at += n;
    }
    while at < end {
        let n = per.min(end - at);
        out.push((at, n));
        at += n;
    }
    out
}

/// The chunk size a request asks for, within bounds.
pub fn check_bytes_per_checksum(bpc: u32) -> Result<u32> {
    if !(MIN_BYTES_PER_CHECKSUM..=MAX_BYTES_PER_CHECKSUM).contains(&bpc) {
        bail!(
            "bytesPerChecksum {bpc} is outside {MIN_BYTES_PER_CHECKSUM}..={MAX_BYTES_PER_CHECKSUM}"
        );
    }
    Ok(bpc)
}
