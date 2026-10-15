//! Recursive Length Prefix (RLP), Ethereum's serialisation, with the bounds a peer cannot move.
//!
//! RLP is recursive by construction — a list holds items that may be lists — and one byte
//! (`0xc1`…) opens a level, so a decoder without a depth counter is a stack overflow a peer can
//! buy for a few kilobytes. Every decode here carries `depth` and refuses past
//! [`MAX_RLP_DEPTH`]; the deepest structure devp2p actually sends (an uncle header inside a block
//! body inside a `BlockBodies` response) is five levels deep. The item count is bounded too
//! ([`MAX_RLP_ITEMS`]): one byte is one item, and each item costs a `Vec` slot here.
//!
//! Decoding is **canonical-only**, as go-ethereum's is: a single byte below `0x80` written with a
//! length prefix, a length with leading zeros, or a long form for a payload of 55 bytes or fewer
//! is refused. That is not pedantry — it is what makes `encode(decode(x)) == x`, which is what
//! lets a block hash computed from a decoded header be the hash of the bytes the peer sent.
use anyhow::{bail, ensure, Context, Result};

/// The deepest nesting accepted. devp2p's deepest real structure is five levels.
pub const MAX_RLP_DEPTH: usize = 16;
/// The most items (strings and lists) one decode may produce.
pub const MAX_RLP_ITEMS: usize = 200_000;

/// One RLP item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

impl Rlp {
    pub fn empty_list() -> Rlp {
        Rlp::List(Vec::new())
    }

    /// An unsigned integer: big-endian, no leading zeros, zero as the empty string.
    pub fn uint(n: u64) -> Rlp {
        Rlp::Bytes(trim_leading_zeros(&n.to_be_bytes()).to_vec())
    }

    /// An unsigned big integer given as big-endian bytes (leading zeros dropped).
    pub fn big_uint(be: &[u8]) -> Rlp {
        Rlp::Bytes(trim_leading_zeros(be).to_vec())
    }

    pub fn bytes(b: &[u8]) -> Rlp {
        Rlp::Bytes(b.to_vec())
    }

    pub fn string(s: &str) -> Rlp {
        Rlp::Bytes(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Rlp::Bytes(b) => Ok(b),
            Rlp::List(_) => bail!("expected a byte string, found a list"),
        }
    }

    pub fn as_list(&self) -> Result<&[Rlp]> {
        match self {
            Rlp::List(l) => Ok(l),
            Rlp::Bytes(_) => bail!("expected a list, found a byte string"),
        }
    }

    /// A canonical unsigned integer of at most eight bytes.
    pub fn as_u64(&self) -> Result<u64> {
        let b = self.as_bytes()?;
        ensure!(
            b.len() <= 8,
            "integer of {} bytes is above 64 bits",
            b.len()
        );
        ensure!(
            b.first() != Some(&0),
            "non-canonical integer (leading zero byte)"
        );
        Ok(b.iter().fold(0u64, |n, d| (n << 8) | u64::from(*d)))
    }

    /// A canonical unsigned big integer of at most 32 bytes, as its minimal big-endian bytes.
    pub fn as_big_uint(&self) -> Result<&[u8]> {
        let b = self.as_bytes()?;
        ensure!(
            b.len() <= 32,
            "integer of {} bytes is above 256 bits",
            b.len()
        );
        ensure!(
            b.first() != Some(&0),
            "non-canonical integer (leading zero byte)"
        );
        Ok(b)
    }

    /// A boolean: RLP has none, so devp2p writes 0 (empty string) or 1.
    pub fn as_bool(&self) -> Result<bool> {
        match self.as_u64()? {
            0 => Ok(false),
            1 => Ok(true),
            n => bail!("boolean {n} is neither 0 nor 1"),
        }
    }

    /// A byte string of exactly `N` bytes.
    pub fn as_fixed<const N: usize>(&self) -> Result<[u8; N]> {
        let b = self.as_bytes()?;
        b.try_into()
            .map_err(|_| anyhow::anyhow!("expected {N} bytes, found {}", b.len()))
    }

    /// Encode this item.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Rlp::Bytes(b) => {
                if b.len() == 1 && b[0] < 0x80 {
                    out.push(b[0]);
                } else {
                    put_length(out, 0x80, b.len());
                    out.extend_from_slice(b);
                }
            }
            Rlp::List(items) => {
                let mut payload = Vec::new();
                for item in items {
                    item.encode_into(&mut payload);
                }
                put_length(out, 0xc0, payload.len());
                out.extend_from_slice(&payload);
            }
        }
    }
}

fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|d| *d != 0).unwrap_or(b.len());
    &b[start..]
}

fn put_length(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len <= 55 {
        out.push(offset + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let be = trim_leading_zeros(&be);
        out.push(offset + 55 + be.len() as u8);
        out.extend_from_slice(be);
    }
}

/// Decode exactly one item that spans the whole input.
pub fn decode(input: &[u8]) -> Result<Rlp> {
    let (item, used) = decode_prefix(input)?;
    ensure!(
        used == input.len(),
        "{} bytes trail the RLP item",
        input.len() - used
    );
    Ok(item)
}

/// Decode one item from the start of `input`; returns it and the bytes it used. Trailing bytes
/// are the caller's business (the RLPx handshake pads its messages).
pub fn decode_prefix(input: &[u8]) -> Result<(Rlp, usize)> {
    let mut items = 0usize;
    decode_at(input, 0, &mut items)
}

/// Where an item's payload is, read from its prefix: (is_list, payload start, payload length).
fn header(input: &[u8]) -> Result<(bool, usize, usize)> {
    let b = *input.first().context("RLP item is empty")?;
    let (list, start, len) = match b {
        0x00..=0x7f => return Ok((false, 0, 1)),
        0x80..=0xb7 => (false, 1, usize::from(b - 0x80)),
        0xc0..=0xf7 => (true, 1, usize::from(b - 0xc0)),
        0xb8..=0xbf | 0xf8..=0xff => {
            let list = b >= 0xf8;
            let len_of_len = usize::from(b - if list { 0xf7 } else { 0xb7 });
            let len_bytes = input
                .get(1..1 + len_of_len)
                .context("RLP length runs past the input")?;
            ensure!(len_bytes[0] != 0, "non-canonical RLP length (leading zero)");
            ensure!(
                len_of_len <= 8,
                "RLP length of {len_of_len} bytes is impossible"
            );
            let len = len_bytes.iter().fold(0u64, |n, d| (n << 8) | u64::from(*d));
            ensure!(
                len > 55,
                "non-canonical RLP length: long form for {len} bytes"
            );
            let len = usize::try_from(len).context("RLP length above usize")?;
            (list, 1 + len_of_len, len)
        }
    };
    let end = start.checked_add(len).context("RLP length overflows")?;
    ensure!(
        end <= input.len(),
        "RLP item declares {len} bytes, {} remain",
        input.len() - start.min(input.len())
    );
    if !list && start == 1 && len == 1 {
        ensure!(
            input[1] >= 0x80,
            "non-canonical RLP: single byte {:#04x} with a length prefix",
            input[1]
        );
    }
    Ok((list, start, len))
}

fn decode_at(input: &[u8], depth: usize, items: &mut usize) -> Result<(Rlp, usize)> {
    *items += 1;
    ensure!(
        *items <= MAX_RLP_ITEMS,
        "RLP holds more than {MAX_RLP_ITEMS} items"
    );
    let (list, start, len) = header(input)?;
    let payload = &input[start..start + len];
    if !list {
        if start == 0 {
            return Ok((Rlp::Bytes(vec![input[0]]), 1));
        }
        return Ok((Rlp::Bytes(payload.to_vec()), start + len));
    }
    ensure!(
        depth < MAX_RLP_DEPTH,
        "RLP nesting deeper than {MAX_RLP_DEPTH} levels"
    );
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (item, used) = decode_at(&payload[pos..], depth + 1, items)?;
        out.push(item);
        pos += used;
    }
    Ok((Rlp::List(out), start + len))
}

/// Split a devp2p frame into its message code (an RLP integer) and the payload after it.
pub fn split_code(frame: &[u8]) -> Result<(u64, &[u8])> {
    let (list, start, len) = header(frame)?;
    ensure!(!list, "message code is a list");
    let code_bytes = if start == 0 {
        &frame[..1]
    } else {
        &frame[start..start + len]
    };
    let code = Rlp::Bytes(code_bytes.to_vec())
        .as_u64()
        .context("message code")?;
    let used = if start == 0 { 1 } else { start + len };
    Ok((code, &frame[used..]))
}
