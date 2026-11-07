//! `netget::utils::cbor_depth` — the iterative guard in front of `serde_cbor`, which decodes the
//! parameters of every CTAP2 command the `usb-fido2` server receives from an unauthenticated
//! USB/IP peer. The server needs the `libusb` feature, and USB protocols cannot be built under
//! cargo-fuzz at all (nusb 0.2.7's `cfg(fuzzing)` code does not compile; see `fuzz/Cargo.toml`),
//! so the guard and the decode live in `src/utils/cbor_depth.rs`, where this target reaches the
//! exact function `Ctap2Request::parse` calls.
//!
//! Four properties:
//!
//! 1. The scan never panics and never recurses, and is deterministic.
//! 2. `decode_bounded` never panics. It is what the server calls, so this is the server's own
//!    decode path. `serde_cbor` runs only on input the scan passed.
//! 3. **Anything the scan reports `Complete`, `serde_cbor` survives**, and where `serde_cbor`
//!    decodes it, it stops at exactly the byte the scan said the item ends at. Disagreeing on
//!    where an item ends would mean the guard measured a different structure from the one the
//!    decoder builds. Removing `MAX_CTAP2_CBOR_DEPTH` lets the `depth_bomb` seed reach
//!    `serde_cbor`'s own 128-level recursion, ~7 KiB of stack a level in a debug build.
//! 4. `TooDeep` is never decoded: that is the input the guard keeps away.
//!
//! No "never refuses what serde_cbor accepts" check, unlike `bson_document`: the guard refuses
//! indefinite-length items on purpose (CTAP2's canonical encoding forbids them), which
//! `serde_cbor` accepts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::utils::cbor_depth::{decode_bounded, scan_cbor_item, CborScan};
use serde::Deserialize;

fuzz_target!(|data: &[u8]| {
    let verdict = scan_cbor_item(data);
    assert_eq!(
        verdict,
        scan_cbor_item(data),
        "scan_cbor_item disagreed with itself"
    );

    let _ = decode_bounded(data);

    if let CborScan::Complete { consumed } = verdict {
        assert!(
            consumed >= 1 && consumed <= data.len(),
            "consumed {consumed} of {}",
            data.len()
        );
        let mut de = serde_cbor::Deserializer::from_slice(&data[..consumed]);
        if serde_cbor::Value::deserialize(&mut de).is_ok() {
            assert_eq!(
                de.byte_offset(),
                consumed,
                "serde_cbor ended the item somewhere other than where the scan did"
            );
        }
    }
});
