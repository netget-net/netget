//! A bound on DNS name-compression pointer chains, applied before `hickory-proto` sees the bytes.
//!
//! `hickory-proto` 0.24.4 decodes a name in `rr/domain/name.rs`'s `read_inner`, and follows a
//! compression pointer by **calling itself** (`name.rs:1203`) on a decoder cloned at the
//! pointer's target. The only rule is that the target lies before the name being read, so a
//! chain of pointers each aiming two bytes back — `C0 0C`, `C0 0E`, `C0 10`, … — is one Rust
//! stack frame per two bytes, with nothing counting. The chain can sit anywhere a decoder will
//! not look, such as the RDATA of a NULL record, and one owner name pointing at its far end
//! starts the descent. Pointer offsets are 14 bits, so a chain reaches ~8 000 links.
//!
//! Measured against 0.24.4 (`Message::from_vec` on a thread of the given stack size):
//!
//! | build | stack | survives | overflows at | message bytes |
//! |---|---|---|---|---|
//! | debug | 2 MiB (a tokio worker) | 1 701 links | **1 702** | 3 448 |
//! | debug | 8 MiB (a main thread) | 6 808 links | **6 809** | 13 662 |
//! | release | 256 KiB | 1 692 links | **1 693** | 3 430 |
//! | release | 2 MiB | 8 180 links (the 14-bit offset's maximum) | — | 16 404 |
//!
//! In a debug or test build three and a half kilobytes in one unauthenticated UDP datagram and
//! the process is gone — every server it runs with it. A release build spends ~155 bytes a
//! frame, so the longest chain the format allows needs ~1.3 MiB and a 2 MiB worker survives it
//! with ~0.7 MiB to spare: whatever else is on that worker's stack when the decoder runs is the
//! only margin. **This is not a panic**: a stack overflow is a `SIGSEGV` against the guard page,
//! and neither `tokio::spawn` nor `catch_unwind` can contain it. `hickory-proto` 0.26 rewrote
//! `read_inner` as a loop; 0.24 and 0.25 recurse.
//!
//! [`screen_dns_message`] therefore computes, for every offset in the message, how many pointer
//! hops a name starting there would follow — in one forward pass, because every hop goes
//! backwards — and refuses the message if any offset exceeds [`MAX_POINTER_HOPS`]. It treats
//! *every* offset as a possible name start, which is stricter than the decoder (it never
//! starts a name inside opaque RDATA), so it cannot miss a chain the decoder would follow.
//!
//! It also refuses a header whose section counts cannot fit the bytes present (every question
//! is at least 5 bytes, every record at least 11). `Message::read` reserves
//! `Vec::with_capacity(count)` for each section from the header's own `u16` counts before
//! reading a record, so twelve bytes claiming 65 535 answers bought a multi-megabyte allocation
//! per datagram; the decoder would have failed on those messages anyway.

/// Most compression-pointer hops any name may take.
///
/// A name is at most 255 octets on the wire, and an encoder only ever points at a label, so a
/// name compressed one label per hop takes at most 127 hops — the most a conforming message can
/// need. In practice it is a handful. At ~1.2 KB of stack per hop in a debug build, 127 hops is
/// ~150 KB of a 2 MiB worker.
pub const MAX_POINTER_HOPS: u16 = 127;

/// Header length; the section counts are its last eight bytes.
const HEADER_LEN: usize = 12;

/// Refuse a DNS message `hickory-proto` would recurse too deeply on, or whose header claims
/// more records than its bytes could hold.
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
/// nothing reaches the recursive decoder unscreened. The error is for the log, not the peer.
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
    // target lies before the name being read (`ptr < name_start`, `name.rs:1195`), so every
    // hop lands on an offset already computed.
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
