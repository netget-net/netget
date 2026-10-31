//! CTAP2 parameters reach `serde_cbor` only through `utils::cbor_depth::decode_bounded`, and
//! that refuses deep or oversized CBOR before the recursive decoder runs.
//!
//! The `usb-fido2` server needs the `libusb` feature, but the guard does not: it lives in
//! `src/utils/cbor_depth.rs` so this test, and `fuzz/fuzz_targets/ctap2_cbor.rs`, run in every
//! build. `Ctap2Request::parse` (`src/server/usb/fido2/ctap2.rs`) calls exactly this function.
//!
//! **The depth bombs run on a 256 KiB thread on purpose.** `serde_cbor` 0.11 stops by itself at
//! 128 levels, but a debug build spends ~7 KiB of stack a level getting there (measured: 126
//! levels overflow 768 KiB). With the bound, decoding costs at most
//! `MAX_CTAP2_CBOR_DEPTH` levels whatever the input says; remove the scan from `decode_bounded`
//! and this test binary aborts with `fatal runtime error: stack overflow` rather than failing,
//! which is how the bound was checked.
//!
//! Run with:
//!   ./cargo-isolated.sh test --test ctap2_cbor_depth_test

use std::collections::BTreeMap;

use netget::utils::cbor_depth::{
    decode_bounded, scan_cbor_item, CborRefusal, CborScan, MAX_CTAP2_CBOR_DEPTH,
};
use serde_cbor::Value;

const SMALL_STACK: usize = 256 * 1024;

/// Run `f` on a thread with a deliberately small stack.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the decode thread panicked")
}

/// `depth` levels of one-element containers around a zero.
fn nested(kind: u8, depth: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(depth * 2 + 1);
    for _ in 0..depth {
        match kind {
            b'a' => v.push(0x81),           // array(1)
            b'm' => v.extend([0xa1, 0x00]), // map(1), key 0
            b't' => v.push(0xc6),           // tag(6)
            _ => unreachable!(),
        }
    }
    v.push(0x00);
    v
}

#[test]
fn depth_bombs_are_refused_before_serde_cbor_recurses() {
    for kind in *b"amt" {
        for depth in [MAX_CTAP2_CBOR_DEPTH + 1, 100, 127, 10_000] {
            let bomb = nested(kind, depth);
            let result = on_small_stack(move || decode_bounded(&bomb).map(|_| ()));
            assert!(
                matches!(result, Err(CborRefusal::TooDeep { limit }) if limit == MAX_CTAP2_CBOR_DEPTH),
                "{} levels of {} must be refused as too deep, got {result:?}",
                depth,
                kind as char
            );
        }
    }
}

#[test]
fn the_deepest_allowed_nesting_still_decodes() {
    for kind in *b"amt" {
        let item = nested(kind, MAX_CTAP2_CBOR_DEPTH);
        let result = on_small_stack(move || decode_bounded(&item).map(|_| ()));
        assert!(
            result.is_ok(),
            "{MAX_CTAP2_CBOR_DEPTH} levels of {} is within the bound, got {result:?}",
            kind as char
        );
    }
}

/// What a platform actually sends: authenticatorMakeCredential's parameters (CTAP 2.1 §6.1),
/// three levels deep at their deepest, and GetAssertion's hmac-secret extension, four.
#[test]
fn real_ctap2_parameters_decode_unchanged() {
    let text = |s: &str| Value::Text(s.to_string());
    let make_credential = Value::Map(BTreeMap::from([
        (Value::Integer(1), Value::Bytes(vec![7; 32])),
        (
            Value::Integer(2),
            Value::Map(BTreeMap::from([(text("id"), text("example.com"))])),
        ),
        (
            Value::Integer(3),
            Value::Map(BTreeMap::from([
                (text("id"), Value::Bytes(vec![8; 16])),
                (text("name"), text("ada")),
            ])),
        ),
        (
            Value::Integer(4),
            Value::Array(vec![Value::Map(BTreeMap::from([
                (text("alg"), Value::Integer(-7)),
                (text("type"), text("public-key")),
            ]))]),
        ),
        (
            Value::Integer(7),
            Value::Map(BTreeMap::from([(text("rk"), Value::Bool(true))])),
        ),
    ]));
    let cose_key = Value::Map(BTreeMap::from([
        (Value::Integer(1), Value::Integer(2)),
        (Value::Integer(-1), Value::Integer(1)),
        (Value::Integer(-2), Value::Bytes(vec![1; 32])),
        (Value::Integer(-3), Value::Bytes(vec![2; 32])),
    ]));
    let get_assertion = Value::Map(BTreeMap::from([
        (Value::Integer(1), text("example.com")),
        (Value::Integer(2), Value::Bytes(vec![9; 32])),
        (
            Value::Integer(4),
            Value::Map(BTreeMap::from([(
                text("hmac-secret"),
                Value::Map(BTreeMap::from([
                    (Value::Integer(1), cose_key),
                    (Value::Integer(2), Value::Bytes(vec![3; 32])),
                    (Value::Integer(3), Value::Bytes(vec![4; 16])),
                ])),
            )])),
        ),
    ]));
    for value in [make_credential, get_assertion] {
        let bytes = serde_cbor::to_vec(&value).expect("encode");
        assert_eq!(
            scan_cbor_item(&bytes),
            CborScan::Complete {
                consumed: bytes.len()
            }
        );
        assert_eq!(decode_bounded(&bytes).expect("decode"), value);
    }
}

#[test]
fn declared_sizes_are_checked_before_anything_is_allocated() {
    let cases: &[(&str, &[u8])] = &[
        ("empty input", &[]),
        (
            "byte string declaring 2^32 bytes",
            &[0x5a, 0xff, 0xff, 0xff, 0xff, 0x00],
        ),
        (
            "text string declaring 2^64-1 bytes",
            &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (
            "array declaring 2^32 items",
            &[0x9a, 0xff, 0xff, 0xff, 0xff, 0x00],
        ),
        (
            "map declaring 2^63 pairs",
            &[0xbb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        ("array missing its second item", &[0x82, 0x00]),
        ("truncated argument", &[0x19, 0x01]),
        ("indefinite-length array", &[0x9f, 0x00, 0xff]),
        ("indefinite-length byte string", &[0x5f, 0x41, 0x00, 0xff]),
        ("stray break", &[0xff]),
        ("reserved additional information", &[0x1c]),
    ];
    for (name, bytes) in cases {
        let result = decode_bounded(bytes);
        assert!(
            matches!(result, Err(CborRefusal::Malformed(_))),
            "{name}: expected a scan refusal, got {result:?}"
        );
    }
    assert!(matches!(
        decode_bounded(&[0xa0, 0x00]),
        Err(CborRefusal::TrailingBytes {
            consumed: 1,
            total: 2
        })
    ));
}
