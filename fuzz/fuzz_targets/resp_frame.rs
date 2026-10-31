//! `netget::utils::resp::scan_resp2_frame` — the iterative guard in front of
//! `redis_protocol::resp2::decode`, which recurses once per nested array with no depth limit.
//! It stands between the first bytes of an unauthenticated Redis connection and that decoder.
//!
//! Five properties are asserted, and the third is the one the guard exists for:
//!
//! 1. The guard never panics and never recurses, whatever bytes it is given.
//! 2. It is deterministic — the same bytes produce the same verdict twice.
//! 3. **Anything it reports `Complete`, `decode` survives**, and ends the frame at the same
//!    byte. Handing accepted input to the real decoder is what makes this a test of the
//!    *pair*: removing `MAX_RESP_DEPTH` turns the `depth_bomb` seed into a stack overflow.
//! 4. Where the guard says `Incomplete` or `Malformed`, `decode` agrees — `Ok(None)` or `Err`.
//!    The guard's module doc claims it follows the decoder's grammar exactly; this is the
//!    check on that claim. Both verdicts are only reached with nesting inside the bound, so
//!    decoding them here is safe.
//! 5. **Fed in pieces, a `RespScanner` reaches the same verdict.** The Redis server scans a
//!    frame as it arrives and resumes where the last read stopped rather than starting again,
//!    which is what keeps an unfinished frame from costing the sum of its prefixes. Resuming
//!    is only safe if it can never change the answer, so the input is fed in steps of one to
//!    eight bytes and the first verdict that is not `Incomplete` must be the one-shot verdict
//!    on the whole input.
//!
//! `TooDeep` and `TooLong` are never decoded: those are the inputs the guard is there to keep
//! away from the decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::utils::resp::{scan_resp2_frame, RespLimits, RespScan, RespScanner};
use redis_protocol::resp2::decode::decode;

/// The Redis server's own limits.
const LIMITS: RespLimits = RespLimits::with_max_bulk_len(netget::server::redis::MAX_BULK_LEN);

fuzz_target!(|data: &[u8]| {
    let verdict = scan_resp2_frame(data, &LIMITS);

    assert_eq!(
        verdict,
        scan_resp2_frame(data, &LIMITS),
        "scan_resp2_frame disagreed with itself"
    );

    // Once a prefix is decided, no longer input can change the verdict, so the first decided
    // prefix must agree with the whole.
    let step = usize::from(data.first().copied().unwrap_or(0) % 8) + 1;
    let mut scanner = RespScanner::new();
    let mut end = 0;
    let resumed = loop {
        end = (end + step).min(data.len());
        let v = scanner.scan(&data[..end], &LIMITS);
        if v != RespScan::Incomplete || end == data.len() {
            break v;
        }
    };
    assert_eq!(
        resumed, verdict,
        "a scanner resumed across {step}-byte reads disagreed with a one-shot scan"
    );

    match verdict {
        RespScan::Complete { consumed } => {
            assert!(consumed <= data.len(), "consumed past the end of the input");
            // A stack overflow here is a SIGSEGV, not a panic, so libFuzzer reports it as a
            // crash — the class no ordinary test can observe.
            match decode(data) {
                Ok(Some((_, n))) => assert_eq!(
                    n, consumed,
                    "guard and decoder disagree about where the frame ends"
                ),
                Ok(None) => panic!("guard said Complete, decoder said Incomplete"),
                // `build_owned_frame` rejects a simple error that is not UTF-8, which the
                // guard does not check because it cannot affect nesting.
                Err(_) => {}
            }
        }
        RespScan::Incomplete => {
            assert!(
                matches!(decode(data), Ok(None)),
                "guard said Incomplete, decoder did not"
            );
        }
        RespScan::Malformed => {
            assert!(
                decode(data).is_err(),
                "guard said Malformed, decoder accepted or waited"
            );
        }
        RespScan::TooDeep { .. } | RespScan::TooLong(_) => {}
    }
});
