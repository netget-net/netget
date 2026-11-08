//! A bound on DNS name-compression pointer chains, applied before `hickory-proto` sees the bytes.
//!
//! A compression pointer may aim anywhere earlier in the message, including at another pointer,
//! so a chain of pointers each aiming two bytes back — `C0 0C`, `C0 0E`, `C0 10`, … — can sit
//! where a decoder will not look, such as the RDATA of a NULL record, and any name pointing at
//! its far end follows the whole chain. Pointer offsets are 14 bits, so a chain reaches ~8 000
//! links.
//!
//! **`hickory-proto` 0.26.3**, the version NetGet decodes with, follows pointers in a loop
//! (`rr/domain/name.rs`, `read_inner`), so a chain costs it no stack: the longest chain the
//! format allows (8 180 links, 16 404 bytes) decodes `Ok` on a 64 KiB thread in a debug build.
//! Against it this screen is belt and braces for the stack. It is still the bound on *work*:
//! every name that enters the chain walks all of it, so one DNS-over-TCP message holding a
//! 6 000-link chain and 2 000 records whose owners point at its end costs 0.26.3 2.7 s of a
//! worker in a debug build and 29 ms in a release build — per message, from an unauthenticated
//! peer. At [`MAX_POINTER_HOPS`] the worst message of that shape (3 000 records, 48 KB) costs
//! 33 ms and 2 ms. And a refused message never becomes an event for the model.
//!
//! The releases before 0.26 follow a pointer by **recursing** — 0.24.4 calls `read_inner` on a
//! decoder cloned at the target (`name.rs:1203`), one Rust stack frame per hop, and 0.25.2 does
//! the same (`name.rs:1366`). Measured against 0.24.4 (`Message::from_vec` on a thread of the
//! given stack size):
//!
//! | build | stack | survives | overflows at | message bytes |
//! |---|---|---|---|---|
//! | debug | 2 MiB (a tokio worker) | 1 701 links | **1 702** | 3 448 |
//! | debug | 8 MiB (a main thread) | 6 808 links | **6 809** | 13 662 |
//! | release | 256 KiB | 1 692 links | **1 693** | 3 430 |
//! | release | 2 MiB | 8 180 links (the 14-bit offset's maximum) | — | 16 404 |
//!
//! There, three and a half kilobytes in one UDP datagram took the process down in a debug or test
//! build, and **a stack overflow is not a panic**: it is a `SIGSEGV` against the guard page,
//! which neither `tokio::spawn` nor `catch_unwind` can contain. The screen is what keeps the same
//! input harmless should a decoder that recurses ever sit behind it again.
//!
//! [`screen_dns_message`] computes, for every offset in the message, how many pointer hops a
//! name starting there would follow — in one forward pass, because every hop goes backwards —
//! and refuses the message if any offset exceeds [`MAX_POINTER_HOPS`]. It treats *every* offset
//! as a possible name start, which is stricter than the decoder (it never starts a name inside
//! opaque RDATA), so it cannot miss a chain the decoder would follow.
//!
//! It also refuses a header whose section counts cannot fit the bytes present (every question
//! is at least 5 bytes, every record at least 11). `Message::read` in 0.26.3 still reserves
//! `Vec::with_capacity(count)` for the question section from the header's own `u16` count before
//! reading a question (each record section now reserves at most 8), so twelve bytes claiming
//! 65 535 questions buy a multi-megabyte allocation per datagram; the decoder would fail on those
//! messages anyway.

/// Most compression-pointer hops any name may take.
///
/// A name is at most 255 octets on the wire, and an encoder only ever points at a label, so a
/// name compressed one label per hop takes at most 127 hops — the most a conforming message can
/// need. In practice it is a handful. A decoder that recursed at ~1.2 KB of stack per hop (0.24's,
/// in a debug build) would spend ~150 KB of a 2 MiB worker on 127 hops.
pub const MAX_POINTER_HOPS: u16 = 127;

/// Header length; the section counts are its last eight bytes.
const HEADER_LEN: usize = 12;

/// Refuse a DNS message whose name compression chains further than any conforming message needs,
/// or whose header claims more records than its bytes could hold.
///
/// `Ok(())` means the bytes are safe to hand to `Message::from_vec` / `Message::read`; it does
/// not mean they decode. A message shorter than its header is passed through for the decoder
/// to reject. Allocates two `u16` per message byte, runs in linear time, never recurses.
pub fn screen_dns_message(data: &[u8]) -> Result<(), String> {
    if data.len() < HEADER_LEN {
        return Ok(());
    }
    let count = |at: usize| usize::from(u16::from_be_bytes([data[at], data[at + 1]]));
    let (questions, records) = (count(4), count(6) + count(8) + count(10));
    let least = questions * 5 + records * 11;
    if least > data.len() - HEADER_LEN {
        return Err(format!(
            "DNS header claims {questions} questions and {records} records, which need at \
             least {least} bytes; the message has {} after its header",
            data.len() - HEADER_LEN
        ));
    }

    let deepest = deepest_pointer_chain(data);
    if deepest > MAX_POINTER_HOPS {
        return Err(format!(
            "DNS name compression chains {deepest} pointers deep; the limit is \
             {MAX_POINTER_HOPS}"
        ));
    }
    Ok(())
}

/// Screen `data`, then decode it with `hickory_proto::op::Message::from_vec`.
///
/// Every place NetGet decodes DNS bytes it did not build calls this rather than `from_vec`, so
/// nothing reaches the decoder unscreened. The error is for the log, not the peer.
#[cfg(not(target_arch = "wasm32"))]
pub fn decode_dns_message(data: &[u8]) -> Result<hickory_proto::op::Message, String> {
    screen_dns_message(data).map_err(|reason| format!("refused before decoding: {reason}"))?;
    hickory_proto::op::Message::from_vec(data).map_err(|e| e.to_string())
}

/// The most pointer hops a name starting at any offset of `data` would follow.
fn deepest_pointer_chain(data: &[u8]) -> u16 {
    const RUNS_OFF: u32 = u32::MAX;
    let n = data.len();

    // `stop[p]`: the offset at which a run of labels starting at `p` ends — at a root byte, a
    // pointer, or a reserved label type — or RUNS_OFF if a label runs past the end. Labels
    // only point forwards, so this fills from the back.
    let mut stop = vec![RUNS_OFF; n];
    for p in (0..n).rev() {
        let b = data[p];
        stop[p] = if b == 0 || b & 0xC0 != 0 {
            p as u32
        } else {
            let next = p + 1 + usize::from(b);
            if next < n {
                stop[next]
            } else {
                RUNS_OFF
            }
        };
    }

    // `hops[p]`: pointers followed by a name read from `p`. A pointer is followed only when its
    // target lies before the name being read (`ptr < name_start` in hickory's `read_inner`), so
    // every hop lands on an offset already computed.
    let mut hops = vec![0u16; n];
    let mut deepest = 0u16;
    for p in 0..n {
        let s = stop[p];
        if s == RUNS_OFF {
            continue;
        }
        let s = s as usize;
        if data[s] & 0xC0 != 0xC0 || s + 1 >= n {
            continue;
        }
        let target = usize::from(u16::from_be_bytes([data[s] & 0x3F, data[s + 1]]));
        if target < p {
            hops[p] = hops[target].saturating_add(1);
            deepest = deepest.max(hops[p]);
        }
    }
    deepest
}
