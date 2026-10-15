//! `netget::server::h323` — the ALIGNED PER interpreter over the generated H.225.0 / H.245
//! schema, and the Q.931 envelope it sits in.
//!
//! The PER decoder is driven by a table, so one input reaches several hundred type shapes:
//! every RAS message, every call-signalling UUIE, every H.245 message and a fastStart
//! OpenLogicalChannel. H.225.0's GenericData and H.245's GenericParameter are recursive, so the
//! corpus carries a depth bomb (`depth_bomb`, 100 000 levels of H.245 GenericParameter); the
//! decoder must refuse it at `MAX_PER_DEPTH` rather than overflow the stack.
//!
//! Whatever decodes is encoded again and must decode to the same value: the encoder may refuse
//! a decoded value (an unknown extension index has no name to write back), but anything it
//! writes must be something the decoder reads identically.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::h323::{per, q931, schema};

/// The two recursive types, decoded on their own too: an open type caps an embedded value at
/// 16 383 octets, which caps how deep a bomb can be when it arrives inside a message.
fn named(name: &str) -> u16 {
    schema::NAMES
        .iter()
        .position(|n| *n == name)
        .expect("in the schema") as u16
}

fuzz_target!(|data: &[u8]| {
    for root in [
        schema::H225_RASMESSAGE,
        schema::H225_H323_USERINFORMATION,
        schema::H245_MULTIMEDIASYSTEMCONTROLMESSAGE,
        schema::H245_OPENLOGICALCHANNEL,
        named("H245.GenericParameter"),
        named("H225.GenericData"),
    ] {
        if let Ok(value) = per::decode(root, data) {
            if let Ok(bytes) = per::encode(root, &value) {
                let again = per::decode(root, &bytes).expect("re-encoded value decodes");
                assert_eq!(again, value, "encode then decode changed the value");
            }
        }
    }
    let _ = q931::Q931::parse(data);
});
