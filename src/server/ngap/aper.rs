//! ALIGNED PER (ITU-T X.691) — the subset NGAP needs, hand-written and bounded.
//!
//! NGAP (TS 38.413 section 9.4) is encoded with the ALIGNED variant of PER. Every IE's value is
//! an *open type* — a length-prefixed, independently encoded octet string — so a receiver can step
//! over an IE it does not understand by its length alone. That property is what makes a hand-rolled
//! subset honest: NetGet decodes the IEs of the procedures it implements and skips the rest by
//! length, reporting their ids, rather than pretending to understand the whole 38.413 module.
//!
//! Every read is bounds-checked against the input, and every count or length the peer declares is
//! checked against the constraint *and* against the octets actually present before anything is
//! allocated for it. A [`Reader`] never recurses, so there is no depth to bound here; the schema
//! walk in `codec.rs` is a fixed, non-recursive sequence of calls.
//!
//! The rules implemented, with their X.691 clause:
//!
//! - **Constrained whole number** (11.5.7 / 10.5.7): range 1 is empty; range ≤ 255 is a bit-field
//!   of the minimum width, *not* aligned; range 256 is one aligned octet; range ≤ 64K is two
//!   aligned octets; beyond that the value takes a 1..N octet field whose length (minus one) is
//!   itself a constrained whole number, followed by the aligned octets.
//! - **Length determinant** (11.9): a size constraint with `ub < 64K` is a constrained whole number
//!   and is not aligned when its range is ≤ 255; otherwise the general form — aligned, one octet
//!   below 128, two octets (`10xxxxxx`) below 16384. Fragmentation (≥ 16384) is refused: nothing in
//!   the NGAP subset NetGet speaks comes near it, and a peer that announces it is answered with a
//!   transfer-syntax error rather than buffered.
//! - **Normally small non-negative whole number** (11.6): extension indices and extension-addition
//!   counts. Values above 63 are refused.
//! - **Open type** (11.2): aligned general length, then a complete encoding.

use std::fmt;

/// A decode or encode refusal. Carries what was being read so the log names the field; nothing
/// in it ever reaches the peer (the peer gets a Cause value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AperError(pub String);

impl fmt::Display for AperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AperError {}

pub type AperResult<T> = Result<T, AperError>;

pub fn err<T>(msg: impl Into<String>) -> AperResult<T> {
    Err(AperError(msg.into()))
}

/// The largest length NetGet will accept from a general length determinant: one below the
/// fragmentation threshold (X.691 11.9.3.8). Anything at or above it is refused.
pub const MAX_UNFRAGMENTED: usize = 16_383;

/// Bits needed to encode `range` distinct values (`range >= 1`).
pub fn bits_for_range(range: u64) -> u32 {
    if range <= 1 {
        0
    } else {
        64 - (range - 1).leading_zeros()
    }
}

/// Octets needed to hold `value` (at least one).
fn octets_for(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(8).max(1)
}

// ============================================================================
// Reader
// ============================================================================

/// A bit cursor over one complete APER encoding.
pub struct Reader<'a> {
    data: &'a [u8],
    /// Position in bits from the start of `data`.
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    /// Octets left after aligning, for checking a declared length before trusting it.
    pub fn remaining_octets_aligned(&self) -> usize {
        let aligned = self.pos.div_ceil(8);
        self.data.len().saturating_sub(aligned)
    }

    pub fn align(&mut self) {
        self.pos = self.pos.div_ceil(8) * 8;
    }

    pub fn bits(&mut self, n: u32, what: &str) -> AperResult<u64> {
        if n > 64 {
            return err(format!("{what}: {n}-bit field is wider than 64"));
        }
        if self.remaining_bits() < n as usize {
            return err(format!(
                "{what}: needs {n} bits, {} remain",
                self.remaining_bits()
            ));
        }
        let mut value = 0u64;
        for _ in 0..n {
            let byte = self.data[self.pos / 8];
            let bit = (byte >> (7 - (self.pos % 8))) & 1;
            value = (value << 1) | bit as u64;
            self.pos += 1;
        }
        Ok(value)
    }

    pub fn bit(&mut self, what: &str) -> AperResult<bool> {
        Ok(self.bits(1, what)? == 1)
    }

    /// `n` octets starting at the next octet boundary.
    pub fn octets_aligned(&mut self, n: usize, what: &str) -> AperResult<&'a [u8]> {
        self.align();
        let start = self.pos / 8;
        if self.data.len() - start < n {
            return err(format!(
                "{what}: declares {n} octets, {} remain",
                self.data.len() - start
            ));
        }
        self.pos += n * 8;
        Ok(&self.data[start..start + n])
    }

    /// `n` octets that are not aligned (fixed-size strings of at most two octets).
    pub fn octets_unaligned(&mut self, n: usize, what: &str) -> AperResult<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.bits(8, what)? as u8);
        }
        Ok(out)
    }

    /// X.691 10.5.7, ALIGNED variant.
    pub fn constrained(&mut self, lb: u64, ub: u64, what: &str) -> AperResult<u64> {
        if ub < lb {
            return err(format!("{what}: empty range"));
        }
        let range = (ub - lb).checked_add(1);
        let value = match range {
            Some(1) => 0,
            Some(r) if r <= 255 => self.bits(bits_for_range(r), what)?,
            Some(256) => {
                self.align();
                self.bits(8, what)?
            }
            Some(r) if r <= 65_536 => {
                self.align();
                self.bits(16, what)?
            }
            _ => {
                // Indefinite-length case: (octets - 1) as a constrained whole number, then the
                // octets, aligned.
                let max_octets = octets_for(ub - lb) as u64;
                let len = self.bits(bits_for_range(max_octets), what)? + 1;
                let raw = self.octets_aligned(len as usize, what)?;
                raw.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
            }
        };
        let v = lb
            .checked_add(value)
            .ok_or_else(|| AperError(format!("{what}: value overflows")))?;
        if v > ub {
            return err(format!("{what}: {v} is above the upper bound {ub}"));
        }
        Ok(v)
    }

    /// General (unconstrained) length determinant, X.691 11.9.3.6-11.9.3.8. Fragmented lengths
    /// are refused.
    pub fn general_length(&mut self, what: &str) -> AperResult<usize> {
        self.align();
        let first = self.bits(8, what)? as usize;
        if first & 0x80 == 0 {
            return Ok(first);
        }
        if first & 0xC0 == 0x80 {
            let second = self.bits(8, what)? as usize;
            return Ok(((first & 0x3F) << 8) | second);
        }
        err(format!(
            "{what}: fragmented length (≥16384) is not accepted"
        ))
    }

    /// A length or count bounded by a size constraint `lb..=ub` (X.691 11.9.4).
    pub fn size(&mut self, lb: usize, ub: usize, what: &str) -> AperResult<usize> {
        let n = if ub < 65_536 {
            self.constrained(lb as u64, ub as u64, what)? as usize
        } else {
            self.general_length(what)?
        };
        if n < lb || n > ub {
            return err(format!("{what}: size {n} outside {lb}..{ub}"));
        }
        Ok(n)
    }

    /// X.691 11.6.
    pub fn normally_small(&mut self, what: &str) -> AperResult<u64> {
        if self.bit(what)? {
            return err(format!(
                "{what}: normally-small value above 63 is not accepted"
            ));
        }
        self.bits(6, what)
    }

    /// An ENUMERATED with `root` root values, extensible or not. Returns `(extended, index)`.
    pub fn enumerated(
        &mut self,
        root: u64,
        extensible: bool,
        what: &str,
    ) -> AperResult<(bool, u64)> {
        if extensible && self.bit(what)? {
            return Ok((true, self.normally_small(what)?));
        }
        Ok((false, self.constrained(0, root - 1, what)?))
    }

    /// An open type's contents: the octets of one complete inner encoding.
    pub fn open_type(&mut self, what: &str) -> AperResult<&'a [u8]> {
        let len = self.general_length(what)?;
        if len > self.remaining_octets_aligned() {
            return err(format!(
                "{what}: open type declares {len} octets, {} remain",
                self.remaining_octets_aligned()
            ));
        }
        self.octets_aligned(len, what)
    }

    /// OCTET STRING with no size constraint: general length, aligned octets.
    pub fn octet_string(&mut self, max: usize, what: &str) -> AperResult<&'a [u8]> {
        let len = self.general_length(what)?;
        if len > max {
            return err(format!(
                "{what}: {len} octets exceeds the {max}-octet bound"
            ));
        }
        self.octets_aligned(len, what)
    }

    /// OCTET STRING (SIZE(n)) — X.691 17.6/17.7.
    pub fn fixed_octets(&mut self, n: usize, what: &str) -> AperResult<Vec<u8>> {
        if n <= 2 {
            self.octets_unaligned(n, what)
        } else {
            Ok(self.octets_aligned(n, what)?.to_vec())
        }
    }

    /// BIT STRING (SIZE(n)) — X.691 16.9/16.10. Returned right-aligned in a u64.
    pub fn fixed_bits(&mut self, n: u32, what: &str) -> AperResult<u64> {
        if n > 16 {
            self.align();
        }
        self.bits(n, what)
    }

    /// BIT STRING (SIZE(lb..ub)) with `ub < 64K` and `ub <= 64` — X.691 16.11. Returns
    /// `(value, length_in_bits)`.
    pub fn varying_bits(&mut self, lb: u32, ub: u32, what: &str) -> AperResult<(u64, u32)> {
        let n = self.size(lb as usize, ub as usize, what)? as u32;
        if n > 64 {
            return err(format!("{what}: {n} bits is wider than 64"));
        }
        self.align();
        Ok((self.bits(n, what)?, n))
    }

    /// The extension bit of a SEQUENCE or CHOICE with an extension marker.
    pub fn extension_bit(&mut self, what: &str) -> AperResult<bool> {
        self.bit(what)
    }

    /// Step over a SEQUENCE's extension additions (X.691 19.7-19.9): a normally-small count, a
    /// presence bitmap, then one open type per present addition. Returns how many were present.
    pub fn skip_extension_additions(&mut self, what: &str) -> AperResult<usize> {
        let n = self.normally_small(what)? as u32 + 1;
        let mut present = 0usize;
        for _ in 0..n {
            if self.bit(what)? {
                present += 1;
            }
        }
        for _ in 0..present {
            self.open_type(what)?;
        }
        Ok(present)
    }

    /// PrintableString (SIZE(lb..ub, ...)) with 8-bit characters (X.691 30.5, ALIGNED).
    pub fn printable_string(&mut self, lb: usize, ub: usize, what: &str) -> AperResult<String> {
        let extended = self.bit(what)?;
        let n = if extended {
            // Outside the root: a semi-constrained length. Accept it only up to the root's own
            // upper bound — the extension exists for a later release, not for a bigger buffer.
            let n = self.general_length(what)?;
            if n > ub {
                return err(format!("{what}: {n} characters exceeds {ub}"));
            }
            n
        } else {
            self.constrained(lb as u64, ub as u64, what)? as usize
        };
        // X.691 30.5.7: alignment follows the constraint's upper bound, not this string's length.
        let raw = if ub * 8 > 16 || extended {
            self.octets_aligned(n, what)?.to_vec()
        } else {
            self.octets_unaligned(n, what)?
        };
        if !raw.iter().all(|b| is_printable(*b)) {
            return err(format!("{what}: not a PrintableString"));
        }
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    /// True when every remaining bit is zero padding of the final octet.
    pub fn at_end(&self) -> bool {
        let aligned = self.pos.div_ceil(8);
        aligned >= self.data.len()
    }
}

/// X.680 41.4 Table 10: the PrintableString character set.
pub fn is_printable(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b)
}

// ============================================================================
// Writer
// ============================================================================

/// A bit cursor building one complete APER encoding.
#[derive(Default)]
pub struct Writer {
    data: Vec<u8>,
    /// Bits used in the final octet of `data` (0 means the last octet is full or there is none).
    bit_len: usize,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bits(&mut self, value: u64, n: u32) {
        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            if self.bit_len.is_multiple_of(8) {
                self.data.push(0);
            }
            if bit == 1 {
                let last = self.data.len() - 1;
                self.data[last] |= 1 << (7 - (self.bit_len % 8));
            }
            self.bit_len += 1;
        }
    }

    pub fn bit(&mut self, b: bool) {
        self.bits(b as u64, 1);
    }

    pub fn align(&mut self) {
        self.bit_len = self.bit_len.div_ceil(8) * 8;
    }

    pub fn octets_aligned(&mut self, bytes: &[u8]) {
        self.align();
        self.data.extend_from_slice(bytes);
        self.bit_len += bytes.len() * 8;
    }

    pub fn octets_unaligned(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.bits(*b as u64, 8);
        }
    }

    pub fn constrained(&mut self, value: u64, lb: u64, ub: u64, what: &str) -> AperResult<()> {
        if value < lb || value > ub {
            return err(format!("{what}: {value} outside {lb}..{ub}"));
        }
        let v = value - lb;
        match (ub - lb).checked_add(1) {
            Some(1) => {}
            Some(r) if r <= 255 => self.bits(v, bits_for_range(r)),
            Some(256) => {
                self.align();
                self.bits(v, 8);
            }
            Some(r) if r <= 65_536 => {
                self.align();
                self.bits(v, 16);
            }
            _ => {
                let max_octets = octets_for(ub - lb) as u64;
                let len = octets_for(v);
                self.bits(len as u64 - 1, bits_for_range(max_octets));
                self.align();
                for i in (0..len).rev() {
                    self.bits((v >> (8 * i)) & 0xFF, 8);
                }
            }
        }
        Ok(())
    }

    pub fn general_length(&mut self, n: usize, what: &str) -> AperResult<()> {
        self.align();
        if n < 128 {
            self.bits(n as u64, 8);
        } else if n <= MAX_UNFRAGMENTED {
            self.bits(0x8000 | n as u64, 16);
        } else {
            return err(format!(
                "{what}: {n} would need a fragmented length, which NetGet does not write"
            ));
        }
        Ok(())
    }

    pub fn size(&mut self, n: usize, lb: usize, ub: usize, what: &str) -> AperResult<()> {
        if n < lb || n > ub {
            return err(format!("{what}: size {n} outside {lb}..{ub}"));
        }
        if ub < 65_536 {
            self.constrained(n as u64, lb as u64, ub as u64, what)
        } else {
            self.general_length(n, what)
        }
    }

    pub fn normally_small(&mut self, value: u64, what: &str) -> AperResult<()> {
        if value > 63 {
            return err(format!("{what}: {value} is not a normally-small number"));
        }
        self.bit(false);
        self.bits(value, 6);
        Ok(())
    }

    /// ENUMERATED: `index` in the root when `!extended`, in the extension list otherwise.
    pub fn enumerated(
        &mut self,
        index: u64,
        extended: bool,
        root: u64,
        extensible: bool,
        what: &str,
    ) -> AperResult<()> {
        if extensible {
            self.bit(extended);
        } else if extended {
            return err(format!("{what}: not extensible"));
        }
        if extended {
            self.normally_small(index, what)
        } else {
            self.constrained(index, 0, root - 1, what)
        }
    }

    /// Append `inner` (one complete encoding) as an open type.
    pub fn open_type(&mut self, inner: &[u8], what: &str) -> AperResult<()> {
        self.general_length(inner.len(), what)?;
        self.octets_aligned(inner);
        Ok(())
    }

    pub fn octet_string(&mut self, bytes: &[u8], what: &str) -> AperResult<()> {
        self.general_length(bytes.len(), what)?;
        self.octets_aligned(bytes);
        Ok(())
    }

    pub fn fixed_octets(&mut self, bytes: &[u8]) {
        if bytes.len() <= 2 {
            self.octets_unaligned(bytes);
        } else {
            self.octets_aligned(bytes);
        }
    }

    pub fn fixed_bits(&mut self, value: u64, n: u32) {
        if n > 16 {
            self.align();
        }
        self.bits(value, n);
    }

    pub fn varying_bits(
        &mut self,
        value: u64,
        n: u32,
        lb: u32,
        ub: u32,
        what: &str,
    ) -> AperResult<()> {
        if n < 64 && value >> n != 0 {
            return err(format!("{what}: {value} does not fit in {n} bits"));
        }
        self.size(n as usize, lb as usize, ub as usize, what)?;
        self.align();
        self.bits(value, n);
        Ok(())
    }

    pub fn printable_string(
        &mut self,
        s: &str,
        lb: usize,
        ub: usize,
        what: &str,
    ) -> AperResult<()> {
        let raw = s.as_bytes();
        if !raw.iter().all(|b| is_printable(*b)) {
            return err(format!(
                "{what}: {s:?} is not a PrintableString (letters, digits, space and '()+,-./:=?)"
            ));
        }
        if raw.len() < lb || raw.len() > ub {
            return err(format!(
                "{what}: {} characters outside {lb}..{ub}",
                raw.len()
            ));
        }
        self.bit(false);
        self.constrained(raw.len() as u64, lb as u64, ub as u64, what)?;
        if ub * 8 > 16 {
            self.octets_aligned(raw);
        } else {
            self.octets_unaligned(raw);
        }
        Ok(())
    }

    /// The finished encoding. X.691 11.1: a complete encoding is at least one octet.
    pub fn finish(mut self) -> Vec<u8> {
        if self.data.is_empty() {
            self.data.push(0);
        }
        self.data
    }
}
