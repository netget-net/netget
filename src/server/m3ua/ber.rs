//! A bounded BER reader and writer (ITU-T X.690) for the subset TCAP, MAP and CAP use.
//!
//! Hand-written rather than generated: the SS7 upper layers need perhaps forty ASN.1 types out of
//! the thousands in 3GPP TS 29.002 and 29.078, every one of them a SEQUENCE of tagged OCTET
//! STRINGs, INTEGERs, ENUMERATEDs, NULLs and nested SEQUENCEs. A generic tree of [`Tlv`] plus
//! per-operation field mappings (`map.rs`, `cap.rs`) is a few hundred lines; `rasn` with the 3GPP
//! modules would be thousands of generated types and a second copy of a crate the tree already
//! carries at another version for SNMP.
//!
//! # Bounds
//!
//! BER is recursive and a peer chooses the nesting, so every decode carries a depth and an
//! element budget:
//!
//! - [`MAX_BER_DEPTH`] constructed levels. The deepest real structure here (TCAP → component
//!   portion → invoke → MAP argument → SubscriberInfo → LocationInformation → CHOICE) is about 9.
//! - [`MAX_BER_ELEMENTS`] TLVs per decode, so a flat message of zero-length elements cannot cost
//!   more than a fixed amount of work.
//! - Lengths are checked against the octets actually present before anything is allocated;
//!   indefinite lengths are accepted (some stacks use them for the dialogue portion) and their
//!   end-of-contents is found within the same budget.
//! - Tag numbers are limited to three subsequent octets (2^21), far above anything a 3GPP module
//!   uses (CAP's highest is 59).
//!
//! Nothing here allocates more than the input already occupies, and no input can recurse past
//! the depth bound — the recursion takes a `depth` parameter and refuses at the bound.

use std::fmt;

/// Constructed nesting levels a decode will follow.
pub const MAX_BER_DEPTH: usize = 16;
/// TLVs a single decode may produce, counted across every level.
pub const MAX_BER_ELEMENTS: usize = 1024;

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_APPLICATION: u8 = 1;
pub const CLASS_CONTEXT: u8 = 2;
pub const CLASS_PRIVATE: u8 = 3;

/// Universal tag numbers used here.
pub const UNIV_BOOLEAN: u32 = 1;
pub const UNIV_INTEGER: u32 = 2;
pub const UNIV_BIT_STRING: u32 = 3;
pub const UNIV_OCTET_STRING: u32 = 4;
pub const UNIV_NULL: u32 = 5;
pub const UNIV_OID: u32 = 6;
pub const UNIV_EXTERNAL: u32 = 8;
pub const UNIV_ENUMERATED: u32 = 10;
pub const UNIV_SEQUENCE: u32 = 16;

/// A BER decode failure. The text names the position and what was wrong; it goes to the log,
/// never to the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BerError(pub String);

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BER: {}", self.0)
    }
}

impl std::error::Error for BerError {}

fn err<T>(msg: impl Into<String>) -> Result<T, BerError> {
    Err(BerError(msg.into()))
}

/// An identifier octet group: class, primitive/constructed, tag number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const fn universal(number: u32, constructed: bool) -> Self {
        Tag {
            class: CLASS_UNIVERSAL,
            constructed,
            number,
        }
    }
    pub const fn application(number: u32, constructed: bool) -> Self {
        Tag {
            class: CLASS_APPLICATION,
            constructed,
            number,
        }
    }
    pub const fn context(number: u32, constructed: bool) -> Self {
        Tag {
            class: CLASS_CONTEXT,
            constructed,
            number,
        }
    }
    pub const SEQUENCE: Tag = Tag::universal(UNIV_SEQUENCE, true);
    pub const INTEGER: Tag = Tag::universal(UNIV_INTEGER, false);
    pub const OCTET_STRING: Tag = Tag::universal(UNIV_OCTET_STRING, false);
    pub const ENUMERATED: Tag = Tag::universal(UNIV_ENUMERATED, false);
    pub const NULL: Tag = Tag::universal(UNIV_NULL, false);
    pub const BOOLEAN: Tag = Tag::universal(UNIV_BOOLEAN, false);
    pub const OID: Tag = Tag::universal(UNIV_OID, false);

    /// Whether `self` is `other` irrespective of the primitive/constructed bit.
    pub fn same(&self, class: u8, number: u32) -> bool {
        self.class == class && self.number == number
    }

    pub fn is_context(&self, number: u32) -> bool {
        self.same(CLASS_CONTEXT, number)
    }

    pub fn is_universal(&self, number: u32) -> bool {
        self.same(CLASS_UNIVERSAL, number)
    }

    /// The identifier octets.
    pub fn encode(&self) -> Vec<u8> {
        let first = (self.class << 6) | if self.constructed { 0x20 } else { 0 };
        if self.number < 31 {
            return vec![first | self.number as u8];
        }
        let mut out = vec![first | 0x1f];
        let mut groups = Vec::new();
        let mut n = self.number;
        loop {
            groups.push((n & 0x7f) as u8);
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        for (i, g) in groups.iter().rev().enumerate() {
            let more = i + 1 < groups.len();
            out.push(if more { g | 0x80 } else { *g });
        }
        out
    }

    /// A short human-readable form, e.g. `[2]`, `[APPLICATION 11]`, `UNIVERSAL 4`.
    pub fn label(&self) -> String {
        match self.class {
            CLASS_CONTEXT => format!("[{}]", self.number),
            CLASS_APPLICATION => format!("[APPLICATION {}]", self.number),
            CLASS_PRIVATE => format!("[PRIVATE {}]", self.number),
            _ => format!("UNIVERSAL {}", self.number),
        }
    }
}

/// One decoded TLV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlv {
    pub tag: Tag,
    /// Primitive contents; empty for a constructed element.
    pub value: Vec<u8>,
    /// Children of a constructed element.
    pub children: Vec<Tlv>,
}

impl Tlv {
    pub fn primitive(tag: Tag, value: impl Into<Vec<u8>>) -> Self {
        Tlv {
            tag,
            value: value.into(),
            children: Vec::new(),
        }
    }

    pub fn constructed(tag: Tag, children: Vec<Tlv>) -> Self {
        Tlv {
            tag,
            value: Vec::new(),
            children,
        }
    }

    /// The first child with this context-specific tag number.
    pub fn ctx(&self, number: u32) -> Option<&Tlv> {
        self.children.iter().find(|c| c.tag.is_context(number))
    }

    /// The first child with this universal tag number.
    pub fn univ(&self, number: u32) -> Option<&Tlv> {
        self.children.iter().find(|c| c.tag.is_universal(number))
    }

    /// The first child with exactly this class and number.
    pub fn child(&self, class: u8, number: u32) -> Option<&Tlv> {
        self.children.iter().find(|c| c.tag.same(class, number))
    }

    /// INTEGER / ENUMERATED contents as a signed value (at most 8 octets).
    pub fn as_i64(&self) -> Result<i64, BerError> {
        decode_integer(&self.value)
    }

    pub fn as_bool(&self) -> Result<bool, BerError> {
        match self.value.as_slice() {
            [b] => Ok(*b != 0),
            _ => err(format!(
                "BOOLEAN {} has {} octets, expected 1",
                self.tag.label(),
                self.value.len()
            )),
        }
    }

    /// Re-encode with definite lengths.
    pub fn encode(&self) -> Vec<u8> {
        if self.tag.constructed {
            let mut body = Vec::new();
            for c in &self.children {
                body.extend_from_slice(&c.encode());
            }
            tlv(self.tag, &body)
        } else {
            tlv(self.tag, &self.value)
        }
    }

    /// The tags present among this element's children, for reporting what was not interpreted.
    pub fn child_labels(&self) -> Vec<String> {
        self.children.iter().map(|c| c.tag.label()).collect()
    }
}

/// Encode one TLV with a definite length.
pub fn tlv(tag: Tag, contents: &[u8]) -> Vec<u8> {
    let mut out = tag.encode();
    push_length(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

/// Encode a constructed TLV from already-encoded children.
pub fn seq(tag: Tag, children: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = children.iter().flatten().copied().collect();
    tlv(tag, &body)
}

fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Minimal two's-complement INTEGER contents.
pub fn integer_contents(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let b = bytes[start];
        let next = bytes[start + 1];
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

pub fn integer(tag: Tag, v: i64) -> Vec<u8> {
    tlv(tag, &integer_contents(v))
}

pub fn decode_integer(contents: &[u8]) -> Result<i64, BerError> {
    if contents.is_empty() || contents.len() > 8 {
        return err(format!(
            "INTEGER of {} octets (1..8 accepted)",
            contents.len()
        ));
    }
    let mut v: i64 = if contents[0] & 0x80 != 0 { -1 } else { 0 };
    for b in contents {
        v = (v << 8) | *b as i64;
    }
    Ok(v)
}

/// OBJECT IDENTIFIER contents from arcs.
pub fn oid_contents(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    if arcs.len() < 2 {
        return out;
    }
    let mut push = |mut v: u64| {
        let mut groups = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            groups.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        groups.reverse();
        out.extend_from_slice(&groups);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    out
}

/// Arcs from OBJECT IDENTIFIER contents. At most 32 arcs, each within 56 bits.
pub fn decode_oid(contents: &[u8]) -> Result<Vec<u64>, BerError> {
    if contents.is_empty() {
        return err("empty OBJECT IDENTIFIER");
    }
    let mut arcs = Vec::new();
    let mut v: u64 = 0;
    let mut octets = 0;
    for (i, b) in contents.iter().enumerate() {
        octets += 1;
        if octets > 8 {
            return err("OBJECT IDENTIFIER arc longer than 8 octets");
        }
        v = (v << 7) | (*b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first);
                arcs.push(v - first * 40);
            } else {
                arcs.push(v);
            }
            if arcs.len() > 32 {
                return err("OBJECT IDENTIFIER with more than 32 arcs");
            }
            v = 0;
            octets = 0;
        } else if i + 1 == contents.len() {
            return err("OBJECT IDENTIFIER ends inside an arc");
        }
    }
    Ok(arcs)
}

pub fn oid_string(arcs: &[u64]) -> String {
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// A cursor over BER octets carrying the element budget shared across one decode.
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    elements: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Reader {
            input,
            pos: 0,
            elements: 0,
        }
    }

    fn byte(&mut self) -> Result<u8, BerError> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or_else(|| BerError(format!("truncated at octet {}", self.pos)))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_tag(&mut self) -> Result<Tag, BerError> {
        let first = self.byte()?;
        let class = first >> 6;
        let constructed = first & 0x20 != 0;
        let mut number = (first & 0x1f) as u32;
        if number == 0x1f {
            number = 0;
            let mut count = 0;
            loop {
                let b = self.byte()?;
                count += 1;
                if count > 3 {
                    return err("tag number longer than 3 octets");
                }
                number = (number << 7) | (b & 0x7f) as u32;
                if b & 0x80 == 0 {
                    break;
                }
            }
        }
        Ok(Tag {
            class,
            constructed,
            number,
        })
    }

    /// `None` for the indefinite form.
    fn read_length(&mut self) -> Result<Option<usize>, BerError> {
        let first = self.byte()?;
        if first < 0x80 {
            return Ok(Some(first as usize));
        }
        if first == 0x80 {
            return Ok(None);
        }
        let n = (first & 0x7f) as usize;
        if n > 4 {
            return err(format!("length of {n} octets (at most 4 accepted)"));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.byte()? as usize;
        }
        Ok(Some(len))
    }

    /// Read one element, following constructed contents down to `MAX_BER_DEPTH`.
    fn element(&mut self, depth: usize) -> Result<Tlv, BerError> {
        if depth >= MAX_BER_DEPTH {
            return err(format!(
                "nesting deeper than {MAX_BER_DEPTH} levels at octet {}",
                self.pos
            ));
        }
        self.elements += 1;
        if self.elements > MAX_BER_ELEMENTS {
            return err(format!("more than {MAX_BER_ELEMENTS} elements"));
        }
        let start = self.pos;
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        match len {
            Some(len) => {
                let end = self.pos.checked_add(len).filter(|e| *e <= self.input.len());
                let Some(end) = end else {
                    return err(format!(
                        "{} at octet {start} declares {len} octets, {} remain",
                        tag.label(),
                        self.input.len().saturating_sub(self.pos)
                    ));
                };
                if tag.constructed {
                    let mut children = Vec::new();
                    while self.pos < end {
                        children.push(self.bounded_child(end, depth + 1)?);
                    }
                    if self.pos != end {
                        return err(format!(
                            "{} at octet {start}: contents overrun the declared length",
                            tag.label()
                        ));
                    }
                    Ok(Tlv::constructed(tag, children))
                } else {
                    let value = self.input[self.pos..end].to_vec();
                    self.pos = end;
                    Ok(Tlv::primitive(tag, value))
                }
            }
            None => {
                if !tag.constructed {
                    return err(format!(
                        "primitive {} at octet {start} uses the indefinite length form",
                        tag.label()
                    ));
                }
                let mut children = Vec::new();
                loop {
                    if self.input.get(self.pos..self.pos + 2) == Some(&[0, 0]) {
                        self.pos += 2;
                        break;
                    }
                    if self.pos >= self.input.len() {
                        return err(format!(
                            "{} at octet {start}: no end-of-contents before the end",
                            tag.label()
                        ));
                    }
                    children.push(self.element(depth + 1)?);
                }
                Ok(Tlv::constructed(tag, children))
            }
        }
    }

    /// A child that must end by `end`.
    fn bounded_child(&mut self, end: usize, depth: usize) -> Result<Tlv, BerError> {
        let saved = self.input;
        self.input = &saved[..end];
        let r = self.element(depth);
        self.input = saved;
        r
    }
}

/// Decode exactly one element occupying all of `input`.
pub fn decode(input: &[u8]) -> Result<Tlv, BerError> {
    let mut r = Reader::new(input);
    let t = r.element(0)?;
    if r.pos != input.len() {
        return err(format!(
            "{} trailing octets after the element",
            input.len() - r.pos
        ));
    }
    Ok(t)
}

/// Decode a run of elements occupying all of `input` (contents of an implicit SEQUENCE).
pub fn decode_all(input: &[u8]) -> Result<Vec<Tlv>, BerError> {
    let mut r = Reader::new(input);
    let mut out = Vec::new();
    while r.pos < input.len() {
        out.push(r.element(0)?);
    }
    Ok(out)
}

/// Hex rendering for identifiers that have no other natural text form (transaction ids, LMSI).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a hex identifier the model supplied. Only for fields that are opaque identifiers by
/// nature; every encoded value is built from structured fields instead.
pub fn unhex(s: &str) -> Result<Vec<u8>, BerError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(format!("{s:?} is not an even-length hex string"));
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect())
}

/// The direct children of the one element in `input`, by tag and contents, without descending
/// into any of them. Definite lengths only. For recovering a transaction id from a message whose
/// full decode was refused (a depth bomb must still be answered with a P-Abort), so it does no
/// recursion at all.
pub fn shallow_children(input: &[u8]) -> Option<Vec<(Tag, &[u8])>> {
    let mut r = Reader::new(input);
    let _top = r.read_tag().ok()?;
    let len = r.read_length().ok()??;
    let end = r.pos.checked_add(len).filter(|e| *e <= input.len())?;
    let mut out = Vec::new();
    while r.pos < end && out.len() < MAX_BER_ELEMENTS {
        let tag = r.read_tag().ok()?;
        let len = r.read_length().ok()??;
        let stop = r.pos.checked_add(len).filter(|e| *e <= end)?;
        out.push((tag, &input[r.pos..stop]));
        r.pos = stop;
    }
    Some(out)
}
