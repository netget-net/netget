//! ALIGNED PER (ITU-T X.691), driven by the schema tables in `schema.rs`.
//!
//! H.225.0 and H.245 are big ASN.1 modules — the parts NetGet speaks reach about seven hundred
//! types — and every message's root fields have to be understood to reach the next one: PER has
//! no tags, so a field nobody can decode makes everything after it unreadable. Rather than hand
//! code a walker per message, `scripts/h323_asn1_schema.py` turns the ITU modules into a table
//! of [`Ty`] values and this module interprets it in both directions:
//!
//! - [`decode`] reads one complete encoding into JSON: a SEQUENCE is an object of its present
//!   fields, a CHOICE a one-key object naming the alternative, an ENUMERATED its name, an OCTET
//!   STRING lowercase hex, a BIT STRING a string of `0`/`1`, an OBJECT IDENTIFIER its dotted
//!   form, NULL `null`.
//! - [`encode`] writes the same JSON back. Unknown keys are refused rather than ignored, so a
//!   misspelt field is an error and not a silently missing one.
//!
//! # Bounds
//!
//! Every read is checked against the input, and every count or length the peer declares is
//! checked against its constraint *and* against what is actually left before anything is
//! allocated for it. Nesting is bounded by [`MAX_PER_DEPTH`] — H.225.0's `GenericData` and
//! H.245's `GenericParameter` are recursive, and without the bound a few hundred bytes of
//! nested `compound`/`nested` parameters would overflow the stack — and the number of values in
//! one decode by [`MAX_PER_NODES`], because a SEQUENCE OF NULL costs no bits per element.
//! Fragmented lengths (≥ 16384, X.691 11.9.3.8) are refused: nothing NetGet speaks comes near
//! one. A normally-small number above 63 (an extension index or bitmap that long) is refused.
//!
//! Types the generator could not express (`SIGNED{}`, `ENCRYPTED{}`, `HASHED{}`,
//! `GeneralString`) are [`Ty::Opaque`]: an extension addition of that type is stepped over by
//! its open-type length; in a root position the decode stops with an error naming it.

use serde_json::{json, Map, Value};
use std::fmt;

/// Deepest nesting of types in one decode or encode. Real H.225.0 messages nest about fifteen
/// deep (Setup → UU-PDU → Setup-UUIE → EndpointType → GatewayInfo → SupportedProtocols → …).
pub const MAX_PER_DEPTH: u32 = 40;
/// Most values one decode may produce.
pub const MAX_PER_NODES: usize = 20_000;
/// The largest unfragmented length (X.691 11.9.3.8).
pub const MAX_UNFRAGMENTED: usize = 16_383;

#[derive(Debug, Clone, Copy)]
pub struct Range {
    pub lb: Option<i64>,
    pub ub: Option<i64>,
    pub ext: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Size {
    pub lb: u32,
    pub ub: Option<u32>,
    pub ext: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharKind {
    Ia5,
    Bmp,
    Numeric,
    Printable,
    /// GeneralString: not a known-multiplier type, so PER writes an unconstrained length in
    /// octets and the octets themselves (X.691 30.6). NetGet reads them as Latin-1.
    General,
}

#[derive(Debug)]
pub struct Field {
    pub name: &'static str,
    pub ty: u16,
    pub optional: bool,
}

#[derive(Debug)]
pub enum Ty {
    Null,
    Boolean,
    Oid,
    Int(Range),
    Enum {
        root: &'static [&'static str],
        ext: Option<&'static [&'static str]>,
    },
    Octets(Size),
    Bits(Size),
    Chars {
        kind: CharKind,
        size: Size,
        alphabet: Option<&'static str>,
    },
    Seq {
        root: &'static [Field],
        ext: Option<&'static [Field]>,
    },
    Choice {
        root: &'static [Field],
        ext: Option<&'static [Field]>,
    },
    SeqOf {
        size: Size,
        item: u16,
    },
    Alias(u16),
    Opaque(&'static str),
}

/// A decode or encode refusal, naming the field path. Nothing in it reaches a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerError(pub String);

impl fmt::Display for PerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PerError {}

pub type PerResult<T> = Result<T, PerError>;

fn ty(index: u16) -> &'static Ty {
    &super::schema::TYPES[index as usize]
}

/// Bits needed to encode `range` distinct values (`range >= 1`).
fn bits_for_range(range: u64) -> u32 {
    if range <= 1 {
        0
    } else {
        64 - (range - 1).leading_zeros()
    }
}

fn octets_for(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(8).max(1)
}

/// Characters of a known-multiplier string type's effective alphabet, sorted by value
/// (X.680's canonical order), and the bits per character in the ALIGNED variant.
fn alphabet(kind: CharKind, from: Option<&'static str>) -> (Vec<u32>, u32) {
    let mut chars: Vec<u32> = match (from, kind) {
        (Some(a), _) => a.chars().map(|c| c as u32).collect(),
        (None, CharKind::Numeric) => " 0123456789".chars().map(|c| c as u32).collect(),
        (None, CharKind::Printable) => {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
                .chars()
                .map(|c| c as u32)
                .collect()
        }
        (None, CharKind::Ia5) => (0..128).collect(),
        (None, CharKind::Bmp) => Vec::new(),
        (None, CharKind::General) => (0..256).collect(),
    };
    chars.sort_unstable();
    chars.dedup();
    if kind == CharKind::Bmp && from.is_none() {
        return (chars, 16);
    }
    if kind == CharKind::General {
        return (chars, 8);
    }
    let n = chars.len() as u64;
    let bits = bits_for_range(n);
    // X.691 30.5.2: in the ALIGNED variant b is rounded up to a power of two.
    let b = match bits {
        0..=1 => bits,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => 16,
    };
    (chars, b)
}

// ============================================================================
// Bit reader / writer
// ============================================================================

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    fn align(&mut self) {
        self.pos = self.pos.div_ceil(8) * 8;
        if self.pos > self.data.len() * 8 {
            self.pos = self.data.len() * 8;
        }
    }

    fn bits(&mut self, n: u32, what: &str) -> PerResult<u64> {
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

    fn octets(&mut self, n: usize, what: &str) -> PerResult<&'a [u8]> {
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

    fn octets_unaligned(&mut self, n: usize, what: &str) -> PerResult<Vec<u8>> {
        if self.remaining_bits() < n * 8 {
            return err(format!("{what}: declares {n} octets past the end"));
        }
        (0..n).map(|_| Ok(self.bits(8, what)? as u8)).collect()
    }

    /// Constrained whole number in `0..range` (X.691 11.5.7, ALIGNED).
    fn whole(&mut self, range: u64, what: &str) -> PerResult<u64> {
        match range {
            0 | 1 => Ok(0),
            r if r <= 255 => self.bits(bits_for_range(r), what),
            256 => {
                self.align();
                self.bits(8, what)
            }
            r if r <= 65_536 => {
                self.align();
                self.bits(16, what)
            }
            r => {
                let max_octets = octets_for(r - 1) as u64;
                let len = self.bits(bits_for_range(max_octets), what)? + 1;
                let raw = self.octets(len as usize, what)?;
                Ok(raw.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
            }
        }
    }

    fn general_length(&mut self, what: &str) -> PerResult<usize> {
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

    fn normally_small(&mut self, what: &str) -> PerResult<u64> {
        if self.bits(1, what)? == 1 {
            return err(format!("{what}: normally-small value above 63"));
        }
        self.bits(6, what)
    }

    /// A length or count under `size`; `extended` tells whether the extension bit was set.
    fn length(&mut self, size: Size, what: &str) -> PerResult<usize> {
        if size.ext && self.bits(1, what)? == 1 {
            return self.general_length(what);
        }
        let n = match size.ub {
            Some(ub) if ub == size.lb => ub as usize,
            Some(ub) if ub < 65_536 => {
                size.lb as usize + self.whole((ub - size.lb) as u64 + 1, what)? as usize
            }
            _ => self.general_length(what)?,
        };
        if n < size.lb as usize || size.ub.is_some_and(|ub| n > ub as usize) {
            return err(format!(
                "{what}: size {n} outside {}..{:?}",
                size.lb, size.ub
            ));
        }
        Ok(n)
    }

    fn open_type(&mut self, what: &str) -> PerResult<&'a [u8]> {
        let len = self.general_length(what)?;
        self.octets(len, what)
    }
}

#[derive(Default)]
struct Writer {
    data: Vec<u8>,
    bit_len: usize,
}

impl Writer {
    fn bits(&mut self, value: u64, n: u32) {
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

    fn align(&mut self) {
        self.bit_len = self.bit_len.div_ceil(8) * 8;
    }

    fn octets(&mut self, bytes: &[u8]) {
        self.align();
        self.data.extend_from_slice(bytes);
        self.bit_len += bytes.len() * 8;
    }

    fn octets_unaligned(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.bits(*b as u64, 8);
        }
    }

    fn whole(&mut self, v: u64, range: u64) {
        match range {
            0 | 1 => {}
            r if r <= 255 => self.bits(v, bits_for_range(r)),
            256 => {
                self.align();
                self.bits(v, 8);
            }
            r if r <= 65_536 => {
                self.align();
                self.bits(v, 16);
            }
            r => {
                let max_octets = octets_for(r - 1) as u64;
                let len = octets_for(v);
                self.bits(len as u64 - 1, bits_for_range(max_octets));
                self.align();
                for i in (0..len).rev() {
                    self.bits((v >> (8 * i)) & 0xFF, 8);
                }
            }
        }
    }

    fn general_length(&mut self, n: usize, what: &str) -> PerResult<()> {
        self.align();
        if n < 128 {
            self.bits(n as u64, 8);
        } else if n <= MAX_UNFRAGMENTED {
            self.bits(0x8000 | n as u64, 16);
        } else {
            return err(format!("{what}: {n} needs a fragmented length"));
        }
        Ok(())
    }

    fn normally_small(&mut self, v: u64, what: &str) -> PerResult<()> {
        if v > 63 {
            return err(format!("{what}: {v} is not a normally-small number"));
        }
        self.bits(0, 1);
        self.bits(v, 6);
        Ok(())
    }

    fn length(&mut self, n: usize, size: Size, what: &str) -> PerResult<()> {
        let in_root = n >= size.lb as usize && size.ub.is_none_or(|ub| n <= ub as usize);
        if !in_root {
            return err(format!(
                "{what}: size {n} outside {}..{:?}",
                size.lb, size.ub
            ));
        }
        if size.ext {
            self.bits(0, 1);
        }
        match size.ub {
            Some(ub) if ub == size.lb => {}
            Some(ub) if ub < 65_536 => {
                self.whole((n - size.lb as usize) as u64, (ub - size.lb) as u64 + 1)
            }
            _ => self.general_length(n, what)?,
        }
        Ok(())
    }

    fn open_type(&mut self, inner: &[u8], what: &str) -> PerResult<()> {
        self.general_length(inner.len(), what)?;
        self.octets(inner);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        if self.data.is_empty() {
            self.data.push(0);
        }
        self.data
    }
}

fn err<T>(msg: impl Into<String>) -> PerResult<T> {
    Err(PerError(msg.into()))
}

// ============================================================================
// Decode
// ============================================================================

/// Decode one complete encoding of schema type `root`.
pub fn decode(root: u16, data: &[u8]) -> PerResult<Value> {
    let mut nodes = 0usize;
    decode_at(root, data, 0, &mut nodes)
}

fn decode_at(root: u16, data: &[u8], depth: u32, nodes: &mut usize) -> PerResult<Value> {
    let mut d = Decoder {
        r: Reader { data, pos: 0 },
        nodes,
    };
    d.value(root, "", depth)
}

struct Decoder<'a, 'n> {
    r: Reader<'a>,
    nodes: &'n mut usize,
}

impl Decoder<'_, '_> {
    fn value(&mut self, index: u16, path: &str, depth: u32) -> PerResult<Value> {
        if depth > MAX_PER_DEPTH {
            return err(format!("{path}: nested deeper than {MAX_PER_DEPTH}"));
        }
        *self.nodes += 1;
        if *self.nodes > MAX_PER_NODES {
            return err(format!("{path}: more than {MAX_PER_NODES} values"));
        }
        let what = if path.is_empty() {
            super::schema::NAMES
                .get(index as usize)
                .copied()
                .unwrap_or("value")
        } else {
            path
        };
        match ty(index) {
            Ty::Alias(target) => self.value(*target, path, depth + 1),
            Ty::Null => Ok(Value::Null),
            Ty::Boolean => Ok(Value::Bool(self.r.bits(1, what)? == 1)),
            Ty::Int(range) => self.integer(*range, what),
            Ty::Enum { root, ext } => {
                if ext.is_some() && self.r.bits(1, what)? == 1 {
                    let i = self.r.normally_small(what)? as usize;
                    return Ok(match ext.and_then(|e| e.get(i)) {
                        Some(name) => json!(name),
                        None => json!(format!("_unknown_{i}")),
                    });
                }
                let i = self.r.whole(root.len() as u64, what)? as usize;
                root.get(i)
                    .map(|n| json!(n))
                    .ok_or_else(|| PerError(format!("{what}: enumeration index {i}")))
            }
            Ty::Octets(size) => {
                let n = self.r.length(*size, what)?;
                let fixed = !size.ext && size.ub == Some(size.lb);
                let raw = if n == 0 {
                    Vec::new()
                } else if fixed && n <= 2 {
                    self.r.octets_unaligned(n, what)?
                } else {
                    self.r.octets(n, what)?.to_vec()
                };
                Ok(json!(hex::encode(raw)))
            }
            Ty::Bits(size) => {
                let n = self.r.length(*size, what)?;
                if n > self.r.remaining_bits() {
                    return err(format!("{what}: declares {n} bits past the end"));
                }
                let fixed = !size.ext && size.ub == Some(size.lb);
                if n > 0 && !(fixed && n <= 16) {
                    self.r.align();
                }
                let mut s = String::with_capacity(n);
                for _ in 0..n {
                    s.push(if self.r.bits(1, what)? == 1 { '1' } else { '0' });
                }
                Ok(json!(s))
            }
            Ty::Chars {
                kind,
                size,
                alphabet: from,
            } => self.chars(*kind, *size, *from, what),
            Ty::Oid => {
                let len = self.r.general_length(what)?;
                let raw = self.r.octets(len, what)?;
                Ok(json!(oid_to_string(raw).ok_or_else(|| PerError(
                    format!("{what}: malformed OBJECT IDENTIFIER")
                ))?))
            }
            Ty::Seq { root, ext } => self.sequence(root, *ext, path, depth),
            Ty::Choice { root, ext } => {
                if ext.is_some() && self.r.bits(1, what)? == 1 {
                    let i = self.r.normally_small(what)? as usize;
                    let inner = self.r.open_type(what)?;
                    return match ext.and_then(|e| e.get(i)) {
                        Some(f) => {
                            let sub = join(path, f.name);
                            let v = self.open(f.ty, inner, &sub, depth)?;
                            Ok(json!({ f.name: v }))
                        }
                        None => Ok(json!({ "_unknown_extension": i })),
                    };
                }
                let i = self.r.whole(root.len() as u64, what)? as usize;
                let f = root
                    .get(i)
                    .ok_or_else(|| PerError(format!("{what}: alternative {i}")))?;
                let sub = join(path, f.name);
                let v = self.value(f.ty, &sub, depth + 1)?;
                Ok(json!({ f.name: v }))
            }
            Ty::SeqOf { size, item } => {
                let n = self.r.length(*size, what)?;
                if n > MAX_PER_NODES {
                    return err(format!("{what}: {n} elements"));
                }
                let mut out = Vec::with_capacity(n.min(64));
                for i in 0..n {
                    let sub = format!("{path}[{i}]");
                    out.push(self.value(*item, &sub, depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            Ty::Opaque(why) => err(format!("{what}: {why} is outside NetGet's PER subset")),
        }
    }

    fn open(&mut self, index: u16, inner: &[u8], path: &str, depth: u32) -> PerResult<Value> {
        let mut d = Decoder {
            r: Reader {
                data: inner,
                pos: 0,
            },
            nodes: self.nodes,
        };
        d.value(index, path, depth + 1)
    }

    fn sequence(
        &mut self,
        root: &'static [Field],
        ext: Option<&'static [Field]>,
        path: &str,
        depth: u32,
    ) -> PerResult<Value> {
        let what = if path.is_empty() { "sequence" } else { path };
        let extended = ext.is_some() && self.r.bits(1, what)? == 1;
        let optional = root.iter().filter(|f| f.optional).count();
        let mut present = Vec::with_capacity(optional);
        for _ in 0..optional {
            present.push(self.r.bits(1, what)? == 1);
        }
        let mut obj = Map::new();
        let mut opt = present.into_iter();
        for f in root {
            if f.optional && !opt.next().unwrap_or(false) {
                continue;
            }
            let sub = join(path, f.name);
            let v = self.value(f.ty, &sub, depth + 1)?;
            obj.insert(f.name.to_string(), v);
        }
        if extended {
            let n = self.r.normally_small(what)? as usize + 1;
            let mut bitmap = Vec::with_capacity(n);
            for _ in 0..n {
                bitmap.push(self.r.bits(1, what)? == 1);
            }
            let additions = ext.unwrap_or(&[]);
            for (i, on) in bitmap.into_iter().enumerate() {
                if !on {
                    continue;
                }
                let inner = self.r.open_type(what)?;
                let Some(f) = additions.get(i) else {
                    continue;
                };
                if let Ty::Opaque(_) = resolve(f.ty) {
                    // Stepped over by its length: H.235 SIGNED{}/ENCRYPTED{} tokens and the like.
                    obj.insert(f.name.to_string(), json!({"_opaque_octets": inner.len()}));
                    continue;
                }
                let sub = join(path, f.name);
                let v = self.open(f.ty, inner, &sub, depth)?;
                obj.insert(f.name.to_string(), v);
            }
        }
        Ok(Value::Object(obj))
    }

    fn integer(&mut self, range: Range, what: &str) -> PerResult<Value> {
        if range.ext && self.r.bits(1, what)? == 1 {
            return self.unconstrained(what);
        }
        match (range.lb, range.ub) {
            (Some(lb), Some(ub)) => {
                let span = (ub - lb) as u64 + 1;
                let v = self.r.whole(span, what)?;
                let v = lb + v as i64;
                if v > ub {
                    return err(format!("{what}: {v} is above {ub}"));
                }
                Ok(json!(v))
            }
            (Some(lb), None) => {
                let len = self.r.general_length(what)?;
                if len == 0 || len > 8 {
                    return err(format!("{what}: {len}-octet integer"));
                }
                let raw = self.r.octets(len, what)?;
                let v = raw.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
                Ok(json!(lb.saturating_add(v as i64)))
            }
            _ => self.unconstrained(what),
        }
    }

    fn unconstrained(&mut self, what: &str) -> PerResult<Value> {
        let len = self.r.general_length(what)?;
        if len == 0 || len > 8 {
            return err(format!("{what}: {len}-octet integer"));
        }
        let raw = self.r.octets(len, what)?;
        let mut v: i64 = if raw[0] & 0x80 != 0 { -1 } else { 0 };
        for b in raw {
            v = (v << 8) | *b as i64;
        }
        Ok(json!(v))
    }

    fn chars(
        &mut self,
        kind: CharKind,
        size: Size,
        from: Option<&'static str>,
        what: &str,
    ) -> PerResult<Value> {
        let (set, b) = alphabet(kind, from);
        let n = self.r.length(size, what)?;
        if n * b as usize > self.r.remaining_bits() {
            return err(format!("{what}: {n} characters past the end"));
        }
        let fixed = !size.ext && size.ub == Some(size.lb);
        let aligned = n > 0
            && match size.ub {
                Some(ub) if fixed => ub as usize * b as usize > 16,
                Some(ub) => ub as usize * b as usize > 16,
                None => true,
            };
        if aligned {
            self.r.align();
        }
        let remap = set.last().is_some_and(|max| *max as u64 > (1u64 << b) - 1);
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            let raw = self.r.bits(b, what)? as u32;
            let code = if remap {
                *set.get(raw as usize)
                    .ok_or_else(|| PerError(format!("{what}: character index {raw}")))?
            } else {
                raw
            };
            if !set.is_empty() && !remap && set.binary_search(&code).is_err() {
                return err(format!("{what}: character {code:#x} is not permitted"));
            }
            s.push(char::from_u32(code).unwrap_or('\u{fffd}'));
        }
        Ok(json!(s))
    }
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{path}.{name}")
    }
}

/// Follow aliases to the type that is not one. Aliases in the schema never form a cycle (the
/// generator only aliases a name to a different name), but the walk is bounded anyway.
fn resolve(mut index: u16) -> &'static Ty {
    for _ in 0..16 {
        match ty(index) {
            Ty::Alias(t) => index = *t,
            other => return other,
        }
    }
    ty(index)
}

pub fn oid_to_string(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 64 {
        return None;
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    let mut in_arc = false;
    for b in raw {
        if acc > (u64::MAX >> 8) {
            return None;
        }
        acc = (acc << 7) | (*b & 0x7F) as u64;
        in_arc = true;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (acc / 40).min(2);
                arcs.push(first);
                arcs.push(acc - first * 40);
            } else {
                arcs.push(acc);
            }
            acc = 0;
            in_arc = false;
        }
    }
    if in_arc {
        return None;
    }
    Some(
        arcs.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

pub fn oid_from_string(s: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = s
        .split('.')
        .map(|a| a.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) || arcs.len() > 32 {
        return None;
    }
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7F) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        out.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    Some(out)
}

// ============================================================================
// Encode
// ============================================================================

/// Encode `value` as schema type `root`: one complete encoding.
pub fn encode(root: u16, value: &Value) -> PerResult<Vec<u8>> {
    let mut w = Writer::default();
    put(&mut w, root, value, "", 0)?;
    Ok(w.finish())
}

fn put(w: &mut Writer, index: u16, v: &Value, path: &str, depth: u32) -> PerResult<()> {
    if depth > MAX_PER_DEPTH {
        return err(format!("{path}: nested deeper than {MAX_PER_DEPTH}"));
    }
    let what = if path.is_empty() {
        super::schema::NAMES
            .get(index as usize)
            .copied()
            .unwrap_or("value")
    } else {
        path
    };
    match ty(index) {
        Ty::Alias(t) => put(w, *t, v, path, depth + 1),
        Ty::Null => {
            if !v.is_null() {
                return err(format!("{what}: NULL takes null"));
            }
            Ok(())
        }
        Ty::Boolean => {
            let b = v
                .as_bool()
                .ok_or_else(|| PerError(format!("{what}: expected a boolean")))?;
            w.bits(b as u64, 1);
            Ok(())
        }
        Ty::Int(range) => put_integer(w, *range, v, what),
        Ty::Enum { root, ext } => {
            let name = v
                .as_str()
                .ok_or_else(|| PerError(format!("{what}: expected an enumeration name")))?;
            if let Some(i) = root.iter().position(|n| *n == name) {
                if ext.is_some() {
                    w.bits(0, 1);
                }
                w.whole(i as u64, root.len() as u64);
                return Ok(());
            }
            if let Some(i) = ext.and_then(|e| e.iter().position(|n| *n == name)) {
                w.bits(1, 1);
                return w.normally_small(i as u64, what);
            }
            err(format!("{what}: {name:?} is not one of {root:?}"))
        }
        Ty::Octets(size) => {
            let raw = v
                .as_str()
                .and_then(|s| hex::decode(s).ok())
                .ok_or_else(|| PerError(format!("{what}: expected hex octets")))?;
            w.length(raw.len(), *size, what)?;
            let fixed = !size.ext && size.ub == Some(size.lb);
            if raw.is_empty() {
            } else if fixed && raw.len() <= 2 {
                w.octets_unaligned(&raw);
            } else {
                w.octets(&raw);
            }
            Ok(())
        }
        Ty::Bits(size) => {
            let s = v
                .as_str()
                .filter(|s| s.chars().all(|c| c == '0' || c == '1'))
                .ok_or_else(|| PerError(format!("{what}: expected a string of 0 and 1")))?;
            w.length(s.len(), *size, what)?;
            let fixed = !size.ext && size.ub == Some(size.lb);
            if !s.is_empty() && !(fixed && s.len() <= 16) {
                w.align();
            }
            for c in s.chars() {
                w.bits((c == '1') as u64, 1);
            }
            Ok(())
        }
        Ty::Chars {
            kind,
            size,
            alphabet: from,
        } => {
            let s = v
                .as_str()
                .ok_or_else(|| PerError(format!("{what}: expected a string")))?;
            let (set, b) = alphabet(*kind, *from);
            let codes: Vec<u32> = s.chars().map(|c| c as u32).collect();
            for c in &codes {
                let ok = if set.is_empty() {
                    *c <= 0xFFFF && !(0xD800..0xE000).contains(c)
                } else {
                    set.binary_search(c).is_ok()
                };
                if !ok {
                    return err(format!(
                        "{what}: {:?} is not permitted in this string",
                        char::from_u32(*c).unwrap_or('?')
                    ));
                }
            }
            let n = codes.len();
            w.length(n, *size, what)?;
            let fixed = !size.ext && size.ub == Some(size.lb);
            let aligned = n > 0
                && match size.ub {
                    Some(ub) if fixed => ub as usize * b as usize > 16,
                    Some(ub) => ub as usize * b as usize > 16,
                    None => true,
                };
            if aligned {
                w.align();
            }
            let remap = set.last().is_some_and(|max| *max as u64 > (1u64 << b) - 1);
            for c in codes {
                let code = if remap {
                    set.binary_search(&c).unwrap_or(0) as u64
                } else {
                    c as u64
                };
                w.bits(code, b);
            }
            Ok(())
        }
        Ty::Oid => {
            let raw = v
                .as_str()
                .and_then(oid_from_string)
                .ok_or_else(|| PerError(format!("{what}: expected a dotted OBJECT IDENTIFIER")))?;
            w.general_length(raw.len(), what)?;
            w.octets(&raw);
            Ok(())
        }
        Ty::Seq { root, ext } => {
            let obj = v
                .as_object()
                .ok_or_else(|| PerError(format!("{what}: expected an object")))?;
            for key in obj.keys() {
                let known = root.iter().any(|f| f.name == key)
                    || ext.is_some_and(|e| e.iter().any(|f| f.name == key));
                if !known {
                    return err(format!("{what}: unknown field {key:?}"));
                }
            }
            let additions: Vec<&Field> = ext
                .map(|e| e.iter().filter(|f| obj.contains_key(f.name)).collect())
                .unwrap_or_default();
            if ext.is_some() {
                w.bits(!additions.is_empty() as u64, 1);
            }
            for f in root.iter().filter(|f| f.optional) {
                w.bits(obj.contains_key(f.name) as u64, 1);
            }
            for f in root.iter() {
                match obj.get(f.name) {
                    Some(fv) => put(w, f.ty, fv, &join(path, f.name), depth + 1)?,
                    None if f.optional => {}
                    None => return err(format!("{what}: missing field {:?}", f.name)),
                }
            }
            if let (Some(all), false) = (ext, additions.is_empty()) {
                // The bitmap runs to the last addition present (X.691 19.8 allows any length
                // covering the present ones; a receiver of an older version ignores the rest).
                let last = all
                    .iter()
                    .rposition(|f| obj.contains_key(f.name))
                    .unwrap_or(0);
                w.normally_small(last as u64, what)?;
                for f in &all[..=last] {
                    w.bits(obj.contains_key(f.name) as u64, 1);
                }
                for f in &all[..=last] {
                    if let Some(fv) = obj.get(f.name) {
                        let mut inner = Writer::default();
                        put(&mut inner, f.ty, fv, &join(path, f.name), depth + 1)?;
                        w.open_type(&inner.finish(), what)?;
                    }
                }
            }
            Ok(())
        }
        Ty::Choice { root, ext } => {
            let obj = v
                .as_object()
                .filter(|o| o.len() == 1)
                .ok_or_else(|| PerError(format!("{what}: a CHOICE is an object with one key")))?;
            let (key, fv) = obj.iter().next().expect("one key");
            if let Some(i) = root.iter().position(|f| f.name == key) {
                if ext.is_some() {
                    w.bits(0, 1);
                }
                w.whole(i as u64, root.len() as u64);
                return put(w, root[i].ty, fv, &join(path, key), depth + 1);
            }
            if let Some(i) = ext.and_then(|e| e.iter().position(|f| f.name == key)) {
                let f = &ext.expect("checked")[i];
                w.bits(1, 1);
                w.normally_small(i as u64, what)?;
                let mut inner = Writer::default();
                put(&mut inner, f.ty, fv, &join(path, key), depth + 1)?;
                return w.open_type(&inner.finish(), what);
            }
            err(format!("{what}: {key:?} is not an alternative"))
        }
        Ty::SeqOf { size, item } => {
            let arr = v
                .as_array()
                .ok_or_else(|| PerError(format!("{what}: expected an array")))?;
            w.length(arr.len(), *size, what)?;
            for (i, e) in arr.iter().enumerate() {
                put(w, *item, e, &format!("{path}[{i}]"), depth + 1)?;
            }
            Ok(())
        }
        Ty::Opaque(why) => err(format!("{what}: NetGet cannot encode {why}")),
    }
}

fn put_integer(w: &mut Writer, range: Range, v: &Value, what: &str) -> PerResult<()> {
    let n = v
        .as_i64()
        .ok_or_else(|| PerError(format!("{what}: expected an integer")))?;
    let in_root = range.lb.is_none_or(|lb| n >= lb) && range.ub.is_none_or(|ub| n <= ub);
    if !in_root {
        if !range.ext {
            return err(format!(
                "{what}: {n} outside {:?}..{:?}",
                range.lb, range.ub
            ));
        }
        w.bits(1, 1);
        return put_unconstrained(w, n, what);
    }
    if range.ext {
        w.bits(0, 1);
    }
    match (range.lb, range.ub) {
        (Some(lb), Some(ub)) => {
            w.whole((n - lb) as u64, (ub - lb) as u64 + 1);
            Ok(())
        }
        (Some(lb), None) => {
            let v = (n - lb) as u64;
            let len = octets_for(v);
            w.general_length(len, what)?;
            let bytes = v.to_be_bytes();
            w.octets(&bytes[8 - len..]);
            Ok(())
        }
        _ => put_unconstrained(w, n, what),
    }
}

fn put_unconstrained(w: &mut Writer, n: i64, what: &str) -> PerResult<()> {
    let bytes = n.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let redundant = (bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    w.general_length(8 - start, what)?;
    w.octets(&bytes[start..]);
    Ok(())
}
