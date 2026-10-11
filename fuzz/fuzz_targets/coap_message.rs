//! `netget::server::coap::codec::CoapMessage::decode` — RFC 7252 over an unauthenticated
//! UDP socket. Hand-rolled on purpose, so there is no third-party decoder underneath it.
//!
//! The option walker is the interesting part: CoAP option deltas and lengths use 13/14
//! extension encodings, and the accumulated delta is what turns into an option number. The
//! Observe, Block1 and Block2 values (RFC 7641, RFC 7959) are read from every message too. This
//! target also round-trips whatever decodes, because `encode` is the direction `m3ua` proved
//! can carry a bound the decoder has and the encoder does not.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::coap::codec::{BlockValue, CoapMessage};

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = CoapMessage::decode(data) else {
        return;
    };

    // Accessors the server calls on every admitted datagram, each re-walking the options.
    let _ = msg.uri_path();
    let _ = msg.path_segments();
    let _ = msg.uri_query();
    let _ = msg.is_empty_message();
    let _ = msg.is_request();

    // The Observe and Block-wise options the server reads before deciding anything: every
    // admitted request with Block1 reaches the reassembly table, and every Block2 the cache.
    // A Block value that parses must re-encode to one that parses back to itself — the server
    // echoes Block1 in its 2.31 and a value that changed on the way would desynchronise the
    // client's upload.
    let _ = msg.observe();
    for block in [msg.block1(), msg.block2()].into_iter().flatten().flatten() {
        let _ = block.size();
        let _ = block.offset();
        assert_eq!(
            BlockValue::parse(&block.encode()),
            Some(block),
            "a Block value did not survive its own encoder"
        );
    }

    // Re-encoding an accepted message must itself decode. A message that decodes but whose
    // encoding does not is a desync the server would emit onto the wire.
    //
    // `encode` returns a `Result` — it refuses an over-long token or option value rather than
    // narrowing it to fit — and **that is what broke this target**: it was written when
    // `encode` returned a bare `Vec<u8>`, `0996d00f` made it fallible hours later, and
    // `CoapMessage::decode(&reencoded)` has been an E0308 ever since. Nothing noticed, because
    // `fuzz/` is its own workspace that `cargo check` at the repository root never compiles,
    // and no CI job builds it. A fuzz target that does not compile has not run, so CoAP's
    // "a fuzz target exists and has run clean" was false from September 15 2026 until it was
    // rebuilt in this pass.
    //
    // `expect` rather than a silent `let Ok(..) else`: neither refusal is *reachable* from a
    // decoded message — `decode` bounds tkl at 8 and an option length at u16::MAX, which are
    // exactly the two bounds `encode` checks — so an `Err` here is a real disagreement between
    // the two directions and belongs in a crash artefact rather than in an early return.
    let reencoded = msg
        .encode()
        .expect("encode refused a message decode accepted: the two bounds disagree");
    assert!(
        CoapMessage::decode(&reencoded).is_ok(),
        "a decoded CoAP message re-encoded into something undecodable"
    );
});
