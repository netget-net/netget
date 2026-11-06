//! A bound on CBOR nesting and declared sizes, applied before `serde_cbor` sees the bytes.
//!
//! The `usb-fido2` server decodes every CTAP2 command's parameters with
//! `serde_cbor::from_slice`, from bytes a USB/IP peer chose. USB/IP authenticates nothing, so
//! this is reachable from one TCP connection.
//!
//! `serde_cbor` 0.11 does count its own recursion: `Deserializer::recursion_checked` refuses
//! past 128 levels (`remaining_depth`, `src/de.rs`), counting arrays, maps and tags alike, so
//! a depth bomb on its own does not overflow a 2 MiB tokio worker. What that leaves is a
//! decoder whose stack use is set by the peer, and it is not small. Measured against 0.11.2,
//! decoding to `serde_cbor::Value` on a thread of a given stack size:
//!
//! | build | depth | stack | result |
//! |---|---|---|---|
//! | debug | 126 arrays or maps | 768 KiB | **stack overflow** |
//! | debug | 126 | 1 MiB | decodes |
//! | debug | 9 maps | 64 KiB | **stack overflow** |
//! | release | 126 | 64 KiB | decodes |
//!
//! So a debug or test build spends ~7 KiB a level — between 768 KiB and 1 MiB of a worker's
//! 2 MiB at the crate's own limit — before NetGet has walked the result at all, and at one byte
//! a level (`0x81` opens an array of one) that costs the peer 128 bytes. The bound here is
//! CTAP2's own: CTAP 2.1 §8 ("Message Encoding") limits every message to four levels of
//! nested maps and arrays, so a conforming platform never sends more than four, and
//! [`MAX_CTAP2_CBOR_DEPTH`] allows twice that.
//!
//! The scan is iterative: [`scan_cbor_item`] keeps the number of children still owed by each
//! open container in a fixed array of [`MAX_CTAP2_CBOR_DEPTH`] slots, allocates nothing and
//! never recurses. It also refuses, before anything is allocated for them:
//!
//! - a byte or text string whose declared length runs past the input,
//! - an array or map declaring more items than there are bytes left (every item is at least
//!   one byte), so no count the peer chose can size an allocation,
//! - indefinite-length items, which CTAP2's canonical encoding forbids (§8: "Indefinite-length
//!   items must be made into definite-length items"), and the reserved additional-information
//!   values 28–30, which no CBOR encoder emits.
//!
//! Only input it reports [`CborScan::Complete`] reaches `serde_cbor`, through
//! [`decode_bounded`], which the CTAP2 parser calls. It is deliberately never more permissive
//! than `serde_cbor` about structure: anything it passes, the crate still validates (UTF-8 in
//! text strings, map key ordering is not checked by either).

/// Deepest CBOR nesting a CTAP2 command may use before it is refused. The command's
/// parameter map is level 1; each array, map or tag inside it adds one. CTAP2 itself allows
/// four (module docs); this is twice that, so a platform that miscounts by a level or two is
/// still served.
pub const MAX_CTAP2_CBOR_DEPTH: usize = 8;

/// The verdict on one CBOR data item at the front of a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborScan {
    /// One whole, structurally sound item occupies the first `consumed` bytes.
    Complete { consumed: usize },
    /// Nested deeper than the limit. Refused as soon as the first level past it opens.
    TooDeep { limit: usize },
    /// Not a CBOR item this decoder will accept; the reason names the first defect found.
    Malformed(&'static str),
}

/// Walk one CBOR data item iteratively, refusing anything nested deeper than
/// [`MAX_CTAP2_CBOR_DEPTH`]. O(n), allocates nothing, never recurses. Bytes after the item are
/// not looked at; [`decode_bounded`] refuses them.
pub fn scan_cbor_item(data: &[u8]) -> CborScan {
    scan_cbor_item_with_limit(data, MAX_CTAP2_CBOR_DEPTH)
}

/// [`scan_cbor_item`] with an explicit limit, clamped to [`MAX_CTAP2_CBOR_DEPTH`] (which sizes
/// the fixed array of open containers).
pub fn scan_cbor_item_with_limit(data: &[u8], max_depth: usize) -> CborScan {
    let max_depth = max_depth.min(MAX_CTAP2_CBOR_DEPTH);
    // `owed[d]` is how many child items the container open at depth d+1 still expects.
    let mut owed = [0u64; MAX_CTAP2_CBOR_DEPTH];
    let mut depth = 0usize;
    let mut pos = 0usize;

    loop {
        let Some(&initial) = data.get(pos) else {
            return CborScan::Malformed("truncated: an item is missing");
        };
        pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;

        // The argument: the value itself (0..=23), or 1/2/4/8 bytes after the initial byte.
        let arg_len = match info {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28..=30 => return CborScan::Malformed("reserved additional information"),
            _ => return CborScan::Malformed("indefinite-length item or stray break"),
        };
        let arg = if arg_len == 0 {
            u64::from(info)
        } else {
            let Some(bytes) = data.get(pos..pos + arg_len) else {
                return CborScan::Malformed("truncated: an argument is missing");
            };
            pos += arg_len;
            bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
        };
        let left = (data.len() - pos) as u64;

        // How many child items this item opens, if it is a container.
        let children = match major {
            // Unsigned and negative integers; simple values and floats (the argument was the
            // value, already consumed).
            0 | 1 | 7 => None,
            // Byte and text strings: the declared length must be present.
            2 | 3 => {
                if arg > left {
                    return CborScan::Malformed("a string's declared length runs past the input");
                }
                pos += arg as usize;
                None
            }
            // Array of `arg` items, each at least one byte.
            4 => {
                if arg > left {
                    return CborScan::Malformed("an array declares more items than bytes remain");
                }
                Some(arg)
            }
            // Map of `arg` pairs.
            5 => match arg.checked_mul(2) {
                Some(n) if n <= left => Some(n),
                _ => return CborScan::Malformed("a map declares more pairs than bytes remain"),
            },
            // A tag wraps exactly one item, and serde_cbor recurses into it like a container.
            _ => Some(1),
        };

        match children {
            Some(n) if n > 0 => {
                if depth >= max_depth {
                    return CborScan::TooDeep { limit: max_depth };
                }
                owed[depth] = n;
                depth += 1;
            }
            // A leaf, or an empty container (which is complete as soon as it opens). Either
            // way one item finished: pay it to the innermost open container, and close every
            // container that is now full, each of which is in turn one finished item of its
            // parent.
            _ => loop {
                if depth == 0 {
                    return CborScan::Complete { consumed: pos };
                }
                owed[depth - 1] -= 1;
                if owed[depth - 1] > 0 {
                    break;
                }
                depth -= 1;
            },
        }
    }
}

/// Why [`decode_bounded`] refused its input.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub enum CborRefusal {
    /// Nested deeper than [`MAX_CTAP2_CBOR_DEPTH`].
    TooDeep { limit: usize },
    /// Refused by the scan before decoding.
    Malformed(&'static str),
    /// One whole item followed by more bytes. CTAP2 parameters are exactly one item.
    TrailingBytes { consumed: usize, total: usize },
    /// The scan passed it and `serde_cbor` still refused it (UTF-8, an unsupported simple
    /// value, ...).
    Decode(serde_cbor::Error),
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Display for CborRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborRefusal::TooDeep { limit } => {
                write!(f, "CBOR nesting exceeds {limit} levels")
            }
            CborRefusal::Malformed(reason) => write!(f, "malformed CBOR: {reason}"),
            CborRefusal::TrailingBytes { consumed, total } => write!(
                f,
                "{} bytes after a complete CBOR item of {consumed} bytes",
                total - consumed
            ),
            CborRefusal::Decode(e) => write!(f, "CBOR decode failed: {e}"),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::error::Error for CborRefusal {}

/// Decode exactly one CBOR item into a `serde_cbor::Value`, after [`scan_cbor_item`] has
/// passed it. This is the only way peer-supplied CBOR reaches `serde_cbor` in NetGet; the
/// CTAP2 parser (`src/server/usb/fido2/ctap2.rs`) calls it.
#[cfg(not(target_arch = "wasm32"))]
pub fn decode_bounded(data: &[u8]) -> Result<serde_cbor::Value, CborRefusal> {
    match scan_cbor_item(data) {
        CborScan::Complete { consumed } if consumed == data.len() => {
            serde_cbor::from_slice(data).map_err(CborRefusal::Decode)
        }
        CborScan::Complete { consumed } => Err(CborRefusal::TrailingBytes {
            consumed,
            total: data.len(),
        }),
        CborScan::TooDeep { limit } => Err(CborRefusal::TooDeep { limit }),
        CborScan::Malformed(reason) => Err(CborRefusal::Malformed(reason)),
    }
}
