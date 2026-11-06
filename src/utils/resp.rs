//! A bound on RESP2 nesting and declared lengths, applied before a decoder ever sees the bytes.
//!
//! `redis-protocol` 6.0 has no depth limit. `resp2::decode` walks a frame with
//! `d_parse_frame` → `d_parse_array` → `nom::multi::count(d_parse_frame, len)`, one level of
//! Rust recursion per nested array, and `build_owned_frame` then recurses over the result a
//! second time. Nothing in either path counts how deep it has gone.
//!
//! `*1\r\n` opens a level in **four bytes**, so a few hundred kilobytes overflow a tokio
//! worker's 2 MiB stack, and the Redis server's only size bound is its 64 MiB
//! incomplete-frame buffer. **This is not a panic.** A Rust stack overflow raises `SIGSEGV`
//! against the guard page and the runtime aborts; `tokio::spawn` cannot contain it. One
//! unauthenticated connection takes the whole of netget down with it. Confirmed by sending
//! 100 000 levels to the unguarded server: the test binary died with
//! `fatal runtime error: stack overflow`.
//!
//! So the bytes are walked *iteratively* first. [`scan_resp2_frame`] keeps one counter per
//! open aggregate in a fixed array of [`MAX_RESP_DEPTH`] slots, allocates nothing, never
//! recurses, and reads each byte at most twice (once to find a line's CRLF, once to parse it).
//! Only a frame it reports as [`RespScan::Complete`] is handed to the decoder. A frame read in
//! pieces is scanned with a [`RespScanner`], which resumes where the last read stopped, so the
//! "at most twice" holds across reads and not only within one.
//!
//! It follows the decoder's grammar exactly where the two could otherwise disagree — a length
//! is parsed with the same `str::parse::<isize>` the crate uses, a bulk string's two trailing
//! bytes are skipped without being checked for CRLF just as `nom_take(2)` does — because a
//! guard that rejected something the decoder would have accepted is a behaviour change, and one
//! that accepted something the decoder would then recurse into is no guard at all.
//!
//! **Declared lengths.** `nom` 7.1.3's `count` caps its initial `Vec::with_capacity` at
//! 64 KiB (`MAX_INITIAL_CAPACITY_BYTES`, `src/multi/mod.rs:577`), so `*4000000000\r\n` is not
//! an allocation bomb by itself. With depth bounded, the most the decoder can pre-allocate at
//! once is [`MAX_RESP_DEPTH`] × 64 KiB. What a declared length *is* is a promise about bytes
//! that have not arrived, and one the caller's buffer cap guarantees can never be kept should
//! be refused on the header rather than after the peer has filled the buffer.
//! [`RespLimits::max_bulk_len`] does that for `$N`, and [`RespLimits::max_elements`] bounds
//! both any single `*N` and the total number of values in one frame, which is what bounds the
//! decoder's per-value allocation (a `RangeFrame` and then an `OwnedFrame` for every three-byte
//! `+\r\n` the peer sends).

/// Deepest nesting of arrays a RESP2 frame may use before it is refused.
///
/// A Redis *request* never nests at all — real Redis rejects an array inside a command with
/// `Protocol error: expected '$', got '*'` — and the deepest reply shapes in common use (an
/// `EXEC` of `XREAD`s) are four or five levels. 32 is far above both and several thousand
/// levels short of what overflows a worker thread.
pub const MAX_RESP_DEPTH: usize = 32;

/// Largest declared array length, and the most values one frame may contain in total.
///
/// 2^20 values is far past any command a model is asked to answer (NetGet flattens a command
/// into one string for the event), and bounds what `decode` allocates for one frame to a few
/// tens of megabytes — the same order as the 64 MiB buffer cap the Redis server applies to the
/// bytes.
pub const MAX_RESP_ELEMENTS: usize = 1 << 20;

/// The bounds [`scan_resp2_frame`] enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RespLimits {
    /// Deepest array nesting accepted. Clamped to [`MAX_RESP_DEPTH`], which sizes the scan's
    /// fixed counter array.
    pub max_depth: usize,
    /// Largest declared `*N`, and the most values in one frame.
    pub max_elements: usize,
    /// Largest declared `$N`. Set it to the caller's buffer cap: a bulk string longer than the
    /// buffer can never complete.
    pub max_bulk_len: usize,
}

impl RespLimits {
    /// [`MAX_RESP_DEPTH`] and [`MAX_RESP_ELEMENTS`], with the caller's bulk-length cap.
    pub const fn with_max_bulk_len(max_bulk_len: usize) -> Self {
        Self {
            max_depth: MAX_RESP_DEPTH,
            max_elements: MAX_RESP_ELEMENTS,
            max_bulk_len,
        }
    }
}

/// Which declared length was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespLength {
    /// An `*N` longer than [`RespLimits::max_elements`], or one that would take the frame's
    /// total past it.
    Aggregate,
    /// A `$N` longer than [`RespLimits::max_bulk_len`].
    Bulk,
}

/// The verdict on the front of a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespScan {
    /// One whole frame occupies the first `consumed` bytes. `resp2::decode` will return the
    /// same count for it.
    Complete { consumed: usize },
    /// Nothing wrong so far and the frame is not finished; read more.
    Incomplete,
    /// Arrays nested deeper than the limit. Refused as soon as the first level past it is
    /// opened, whether or not the rest of the frame has arrived.
    TooDeep { limit: usize },
    /// A declared length past its limit. Refused on the header line.
    TooLong(RespLength),
    /// Not RESP2: a type byte the decoder does not know, or a length or integer it cannot
    /// parse. The decoder would return an error at the same point.
    Malformed,
}

/// Scan the RESP2 frame at the front of `data` without recursing or allocating.
///
/// Call it on the unconsumed buffer before every `resp2::decode`, and decode only on
/// [`RespScan::Complete`]. It is O(n) in the bytes up to the end of the frame or the point of
/// refusal. A caller that reads a frame in pieces should keep a [`RespScanner`] instead, which
/// gives the same verdicts without walking the same bytes again on every read.
pub fn scan_resp2_frame(data: &[u8], limits: &RespLimits) -> RespScan {
    RespScanner::new().scan(data, limits)
}

/// [`scan_resp2_frame`] for a frame that arrives in pieces: it remembers where an
/// [`RespScan::Incomplete`] verdict stopped and resumes there.
///
/// Scanning from the start of the frame on every read made an unfinished frame cost the sum of
/// all its prefixes. A simple string has no length prefix, so finding its end means looking for
/// CRLF, and a peer trickling one 64 MiB line in 4 KiB reads bought ~16 000 walks of up to
/// 64 MiB each — minutes of one async worker, before the caller's buffer cap was reached. A
/// frame of a million small values cost the same shape at a smaller constant. Resumed, each
/// byte is looked at once (a bulk string's payload not at all), so a frame costs O(its length)
/// however it is split.
///
/// The state it keeps is a position at a value boundary in the frame plus the open-array
/// counters at that point, and for the value there: how far its first line has been searched
/// for CRLF, or where that line ends. So `data` must start at the same frame on every call and
/// only grow — the caller may drain bytes *before* the frame, never inside it. Any verdict other
/// than `Incomplete` resets it for the next frame.
#[derive(Debug, Clone)]
pub struct RespScanner {
    /// Start of the value the scan is at, relative to the frame start.
    pos: usize,
    /// `remaining[d]` is how many values the array open at depth `d + 1` still expects.
    remaining: [usize; MAX_RESP_DEPTH],
    depth: usize,
    /// Values counted before `pos`, open arrays included.
    values: usize,
    /// No CRLF ends the first line of the value at `pos` before this offset (less one byte,
    /// since a `\r` at the end may be completed by a `\n` that has not arrived).
    searched: usize,
    /// Where the first line of the value at `pos` ends, once found.
    line_end: Option<usize>,
    /// The value at `pos` is a bulk string ending here, whose payload had not all arrived.
    bulk_end: Option<usize>,
}

impl Default for RespScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RespScanner {
    pub const fn new() -> Self {
        Self {
            pos: 0,
            remaining: [0; MAX_RESP_DEPTH],
            depth: 0,
            values: 0,
            searched: 0,
            line_end: None,
            bulk_end: None,
        }
    }

    /// The verdict on the frame at the front of `data`, resuming where the last
    /// `Incomplete` left off.
    pub fn scan(&mut self, data: &[u8], limits: &RespLimits) -> RespScan {
        let verdict = self.resume(data, limits);
        if verdict != RespScan::Incomplete {
            *self = Self::new();
        }
        verdict
    }

    fn resume(&mut self, data: &[u8], limits: &RespLimits) -> RespScan {
        let max_depth = limits.max_depth.min(MAX_RESP_DEPTH);

        loop {
            let start = self.pos;
            let Some(&kind) = data.get(start) else {
                return RespScan::Incomplete;
            };
            let values = self.values + 1;
            if values > limits.max_elements {
                return RespScan::TooLong(RespLength::Aggregate);
            }
            if !matches!(kind, b'+' | b'-' | b':' | b'$' | b'*') {
                return RespScan::Malformed;
            }
            // A bulk string whose header was read on an earlier call and whose payload had not
            // all arrived. Its header is not parsed again: `$` may be followed by any number of
            // leading zeros, so re-parsing it per read would be the same quadratic walk.
            if let Some(after) = self.bulk_end {
                if after > data.len() {
                    return RespScan::Incomplete;
                }
                self.advance(values, after);
                match self.close_arrays() {
                    Some(done) => return done,
                    None => continue,
                }
            }
            let Some(end) = self.line_end(data, start + 1) else {
                return RespScan::Incomplete;
            };
            let line = &data[start + 1..end];
            let mut next = end + 2;

            match kind {
                b':' => {
                    if parse_i64(line).is_none() {
                        return RespScan::Malformed;
                    }
                }
                b'$' => {
                    let Some(len) = parse_isize(line) else {
                        return RespScan::Malformed;
                    };
                    if len != -1 {
                        let Ok(len) = usize::try_from(len) else {
                            return RespScan::Malformed;
                        };
                        if len > limits.max_bulk_len {
                            return RespScan::TooLong(RespLength::Bulk);
                        }
                        // The payload and the two bytes after it, which the decoder takes
                        // without checking that they are CRLF.
                        let Some(after) = next.checked_add(len).and_then(|v| v.checked_add(2))
                        else {
                            return RespScan::TooLong(RespLength::Bulk);
                        };
                        if after > data.len() {
                            self.bulk_end = Some(after);
                            return RespScan::Incomplete;
                        }
                        next = after;
                    }
                }
                b'*' => {
                    let Some(len) = parse_isize(line) else {
                        return RespScan::Malformed;
                    };
                    if len != -1 {
                        let Ok(len) = usize::try_from(len) else {
                            return RespScan::Malformed;
                        };
                        // Refused on the header: the values this promises, on top of those
                        // already counted, would pass the per-frame total.
                        if len > limits.max_elements.saturating_sub(values) {
                            return RespScan::TooLong(RespLength::Aggregate);
                        }
                        // An empty array still costs the decoder a level of recursion, so it
                        // counts against depth too.
                        if self.depth + 1 > max_depth {
                            return RespScan::TooDeep { limit: max_depth };
                        }
                        if len > 0 {
                            self.remaining[self.depth] = len;
                            self.depth += 1;
                            self.advance(values, next);
                            continue;
                        }
                    }
                }
                // `+` and `-`: the line is the value.
                _ => {}
            }

            self.advance(values, next);
            if let Some(done) = self.close_arrays() {
                return done;
            }
        }
    }

    /// A value just finished at `pos`: close every array it was the last element of, and say
    /// whether that finished the frame.
    fn close_arrays(&mut self) -> Option<RespScan> {
        loop {
            if self.depth == 0 {
                return Some(RespScan::Complete { consumed: self.pos });
            }
            self.remaining[self.depth - 1] -= 1;
            if self.remaining[self.depth - 1] > 0 {
                return None;
            }
            self.depth -= 1;
        }
    }

    /// Move to the next value boundary.
    fn advance(&mut self, values: usize, next: usize) {
        self.values = values;
        self.pos = next;
        self.searched = 0;
        self.line_end = None;
        self.bulk_end = None;
    }

    /// The end of the line starting at `from` (the current value's first line), searching only
    /// bytes not already searched.
    fn line_end(&mut self, data: &[u8], from: usize) -> Option<usize> {
        if self.line_end.is_none() {
            let resume = from.max(self.searched.saturating_sub(1));
            match find_crlf(data, resume) {
                Some(end) => self.line_end = Some(end),
                None => self.searched = data.len(),
            }
        }
        self.line_end
    }
}

/// Index of the first `\r\n` at or after `from`, as `nom`'s `take_until("\r\n")` finds it.
fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

/// The decoder's own `str::from_utf8(s)?.parse::<isize>()`, so the two agree on every input.
fn parse_isize(line: &[u8]) -> Option<isize> {
    std::str::from_utf8(line).ok()?.parse::<isize>().ok()
}

/// The decoder's `to_i64`.
fn parse_i64(line: &[u8]) -> Option<i64> {
    std::str::from_utf8(line).ok()?.parse::<i64>().ok()
}
