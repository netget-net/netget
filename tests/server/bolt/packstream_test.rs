//! PackStream and chunking, checked against the specification's own bytes, round-tripped by
//! proptest, and attacked with the two inputs the decoder exists to survive: a depth bomb and a
//! header declaring more than the input holds.
//!
//! The depth and declared-length guards were verified by removing them: without the depth check
//! in `decode_list`/`decode_map`/`decode_struct` the depth-bomb test aborts the test binary with
//! `fatal runtime error: stack overflow`; without `check_declared` the five-byte LIST_32 header
//! first asks `Vec::with_capacity` for four billion `Value`s (~160 GB of address space, which
//! macOS grants lazily and a Linux host with overcommit off refuses by aborting) and only then
//! fails with `UnexpectedEnd`, so the test reports the wrong error.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::packstream --test-threads=100


use netget::server::bolt::packstream::{
    self, chunk, decode, to_bytes, Dechunker, DecodeError, FrameError, Value, MAX_MESSAGE_BYTES,
    MAX_PACKSTREAM_DEPTH,
};
use netget::server::bolt::values::{self, json_to_value, value_to_json};
use proptest::prelude::*;
use serde_json::json;

// --- The specification's literal encodings -----------------------------------------------------

#[test]
fn integers_take_the_smallest_form_at_every_boundary() {
    let cases: &[(i64, &[u8])] = &[
        (0, &[0x00]),
        (127, &[0x7F]),
        (-1, &[0xFF]),
        (-16, &[0xF0]),
        (-17, &[0xC8, 0xEF]),
        (-128, &[0xC8, 0x80]),
        (128, &[0xC9, 0x00, 0x80]),
        (-129, &[0xC9, 0xFF, 0x7F]),
        (32767, &[0xC9, 0x7F, 0xFF]),
        (32768, &[0xCA, 0x00, 0x00, 0x80, 0x00]),
        (-32769, &[0xCA, 0xFF, 0xFF, 0x7F, 0xFF]),
        (2147483647, &[0xCA, 0x7F, 0xFF, 0xFF, 0xFF]),
        (
            2147483648,
            &[0xCB, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
        ),
        (
            i64::MIN,
            &[0xCB, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    ];
    for (value, bytes) in cases {
        assert_eq!(to_bytes(&Value::Int(*value)), *bytes, "encoding of {value}");
        assert_eq!(
            decode(bytes),
            Ok(Value::Int(*value)),
            "decoding of {bytes:02X?}"
        );
    }
}

#[test]
fn every_wider_integer_form_decodes_even_when_a_smaller_one_would_do() {
    // A client may use a wider marker than necessary; the value is the same.
    assert_eq!(decode(&[0xC8, 0x01]), Ok(Value::Int(1)));
    assert_eq!(decode(&[0xC9, 0x00, 0x01]), Ok(Value::Int(1)));
    assert_eq!(decode(&[0xCA, 0, 0, 0, 1]), Ok(Value::Int(1)));
    assert_eq!(decode(&[0xCB, 0, 0, 0, 0, 0, 0, 0, 1]), Ok(Value::Int(1)));
}

#[test]
fn scalars_strings_and_containers_match_the_specification_bytes() {
    assert_eq!(to_bytes(&Value::Null), [0xC0]);
    assert_eq!(to_bytes(&Value::Bool(true)), [0xC3]);
    assert_eq!(to_bytes(&Value::Bool(false)), [0xC2]);
    assert_eq!(
        to_bytes(&Value::Float(1.1)),
        [0xC1, 0x3F, 0xF1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9A]
    );
    assert_eq!(to_bytes(&Value::string("")), [0x80]);
    assert_eq!(to_bytes(&Value::string("A")), [0x81, 0x41]);
    let s15 = "a".repeat(15);
    assert_eq!(to_bytes(&Value::string(&s15))[0], 0x8F);
    let s16 = "a".repeat(16);
    assert_eq!(&to_bytes(&Value::string(&s16))[..2], [0xD0, 0x10]);
    let s256 = "a".repeat(256);
    assert_eq!(&to_bytes(&Value::string(&s256))[..3], [0xD1, 0x01, 0x00]);
    let s65536 = "a".repeat(65536);
    assert_eq!(
        &to_bytes(&Value::string(&s65536))[..5],
        [0xD2, 0x00, 0x01, 0x00, 0x00]
    );
    // "Größenmaßstäbe": multi-byte UTF-8 counts bytes, not chars.
    let umlaut = to_bytes(&Value::string("Größenmaßstäbe"));
    assert_eq!(&umlaut[..2], [0xD0, 0x12]);

    assert_eq!(
        to_bytes(&Value::List(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3)
        ])),
        [0x93, 0x01, 0x02, 0x03]
    );
    let sixteen: Vec<Value> = (0..16).map(Value::Int).collect();
    assert_eq!(&to_bytes(&Value::List(sixteen))[..2], [0xD4, 0x10]);
    assert_eq!(
        to_bytes(&Value::map([("one", Value::string("eins"))])),
        [0xA1, 0x83, 0x6F, 0x6E, 0x65, 0x84, 0x65, 0x69, 0x6E, 0x73]
    );
    assert_eq!(
        to_bytes(&Value::Bytes(vec![1, 2, 3])),
        [0xCC, 0x03, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        to_bytes(&Value::Struct {
            tag: 0x70,
            fields: vec![Value::Map(Vec::new())]
        }),
        [0xB1, 0x70, 0xA0]
    );
}

#[test]
fn a_captured_cypher_shell_goodbye_and_pull_decode() {
    // GOODBYE and PULL {n: 1000} as cypher-shell 2026.09 sent them.
    assert_eq!(
        decode(&[0xB0, 0x02]),
        Ok(Value::Struct {
            tag: 0x02,
            fields: vec![]
        })
    );
    assert_eq!(
        decode(&[0xB1, 0x3F, 0xA1, 0x81, 0x6E, 0xC9, 0x03, 0xE8]),
        Ok(Value::Struct {
            tag: 0x3F,
            fields: vec![Value::map([("n", Value::Int(1000))])]
        })
    );
}

#[test]
fn struct_8_and_struct_16_decode() {
    assert_eq!(
        decode(&[0xDC, 0x01, 0x44, 0x01]),
        Ok(Value::Struct {
            tag: 0x44,
            fields: vec![Value::Int(1)]
        })
    );
    assert_eq!(
        decode(&[0xDD, 0x00, 0x01, 0x44, 0x01]),
        Ok(Value::Struct {
            tag: 0x44,
            fields: vec![Value::Int(1)]
        })
    );
}

#[test]
fn malformed_input_is_refused_not_panicked_on() {
    assert_eq!(decode(&[]), Err(DecodeError::UnexpectedEnd));
    assert_eq!(decode(&[0xC9, 0x01]), Err(DecodeError::UnexpectedEnd));
    assert_eq!(decode(&[0xC4]), Err(DecodeError::ReservedMarker(0xC4)));
    assert_eq!(decode(&[0xE0]), Err(DecodeError::ReservedMarker(0xE0)));
    assert_eq!(decode(&[0xA1, 0x01, 0x01]), Err(DecodeError::NonStringKey));
    assert_eq!(decode(&[0x82, 0xFF, 0xFE]), Err(DecodeError::InvalidUtf8));
    assert_eq!(decode(&[0x01, 0x02]), Err(DecodeError::TrailingBytes(1)));
}

// --- The two guards ------------------------------------------------------------------------------

/// `0x91` is a one-element list: each byte opens a level. 100,000 of them is 100 KB.
#[test]
fn a_depth_bomb_is_refused_as_too_deep_without_overflowing_the_stack() {
    for opener in [0x91u8, 0xA1] {
        let mut bomb = Vec::new();
        for _ in 0..100_000 {
            bomb.push(opener);
            if opener == 0xA1 {
                bomb.extend_from_slice(&[0x81, b'k']);
            }
        }
        bomb.push(0xC0);
        assert_eq!(
            decode(&bomb),
            Err(DecodeError::TooDeep),
            "opener {opener:02X}"
        );
    }
    // Structures nest too.
    let mut bomb = Vec::new();
    for _ in 0..100_000 {
        bomb.extend_from_slice(&[0xB1, 0x4E]);
    }
    bomb.push(0xC0);
    assert_eq!(decode(&bomb), Err(DecodeError::TooDeep));
}

#[test]
fn nesting_exactly_at_the_limit_decodes_and_one_more_does_not() {
    let nested = |levels: usize| {
        let mut bytes = vec![0x91; levels];
        bytes.push(0x01);
        bytes
    };
    assert!(decode(&nested(MAX_PACKSTREAM_DEPTH)).is_ok());
    assert_eq!(
        decode(&nested(MAX_PACKSTREAM_DEPTH + 1)),
        Err(DecodeError::TooDeep)
    );
}

/// Five bytes declaring four billion elements must be refused on the count, before any
/// allocation — the process would otherwise try to reserve ~100 GB.
#[test]
fn a_declared_length_larger_than_the_input_is_refused_before_allocation() {
    for header in [
        vec![0xD6, 0xFF, 0xFF, 0xFF, 0xFF],       // LIST_32
        vec![0xDA, 0xFF, 0xFF, 0xFF, 0xFF],       // MAP_32
        vec![0xD2, 0xFF, 0xFF, 0xFF, 0xFF],       // STRING_32
        vec![0xCE, 0xFF, 0xFF, 0xFF, 0xFF],       // BYTES_32
        vec![0xDD, 0xFF, 0xFF, 0x4E],             // STRUCT_16
        vec![0xD5, 0x00, 0x03, 0x01, 0x02],       // a 3-element list holding 2
        vec![0xD9, 0x00, 0x02, 0x81, 0x61, 0x01], // a 2-entry map holding 1
    ] {
        match decode(&header) {
            Err(DecodeError::DeclaredLengthExceedsInput { .. }) => {}
            other => panic!("{header:02X?} decoded as {other:?}"),
        }
    }
}

// --- Chunking --------------------------------------------------------------------------------------

#[test]
fn a_message_longer_than_one_chunk_is_split_at_65535_and_reassembled() {
    let message = vec![0xAB; 70_000];
    let framed = chunk(&message);
    assert_eq!(&framed[..2], [0xFF, 0xFF], "first chunk is full");
    assert_eq!(
        &framed[2 + 65535..2 + 65535 + 2],
        ((70_000u32 - 65535) as u16).to_be_bytes()
    );
    assert_eq!(&framed[framed.len() - 2..], [0x00, 0x00]);

    let mut d = Dechunker::new(MAX_MESSAGE_BYTES);
    // Byte by byte: a message is only complete at its zero chunk.
    for (i, b) in framed.iter().enumerate() {
        d.push(&[*b]);
        let got = d.next_message().expect("within the limit");
        if i + 1 < framed.len() {
            assert!(got.is_none(), "message completed early at byte {i}");
        } else {
            assert_eq!(got, Some(message.clone()));
        }
    }
}

#[test]
fn noop_chunks_between_messages_are_skipped() {
    let mut d = Dechunker::new(MAX_MESSAGE_BYTES);
    d.push(&[0x00, 0x00, 0x00, 0x00]);
    d.push(&chunk(&[0xB0, 0x0F]));
    d.push(&[0x00, 0x00]);
    d.push(&chunk(&[0xB0, 0x02]));
    assert_eq!(d.next_message(), Ok(Some(vec![0xB0, 0x0F])));
    assert_eq!(d.next_message(), Ok(Some(vec![0xB0, 0x02])));
    assert_eq!(d.next_message(), Ok(None));
}

#[test]
fn the_message_cap_is_enforced_on_the_declared_chunk_size() {
    let mut d = Dechunker::new(MAX_MESSAGE_BYTES);
    // 16 full chunks is exactly 1 MiB - 16 bytes; the next full chunk crosses the cap and is
    // refused on its 2-byte header, before its payload has arrived.
    for _ in 0..16 {
        d.push(&[0xFF, 0xFF]);
        d.push(&vec![0u8; 65535]);
        assert_eq!(d.next_message(), Ok(None));
    }
    d.push(&[0xFF, 0xFF]);
    assert_eq!(
        d.next_message(),
        Err(FrameError::TooLarge {
            limit: MAX_MESSAGE_BYTES
        })
    );

    // Exactly the limit is accepted.
    let mut d = Dechunker::new(MAX_MESSAGE_BYTES);
    d.push(&chunk(&vec![0u8; MAX_MESSAGE_BYTES]));
    assert_eq!(
        d.next_message().map(|m| m.map(|m| m.len())),
        Ok(Some(MAX_MESSAGE_BYTES))
    );
}

// --- Round trips -----------------------------------------------------------------------------------

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        // Every width boundary, not just the uniform distribution over i64.
        prop_oneof![
            -20i64..=130,
            -40_000i64..=40_000,
            Just(i64::from(i32::MIN) - 1),
            Just(i64::from(i32::MAX) + 1),
        ]
        .prop_map(Value::Int),
        any::<f64>()
            .prop_filter("NaN never equals itself", |f| !f.is_nan())
            .prop_map(Value::Float),
        ".{0,40}".prop_map(Value::String),
        "a{250,300}".prop_map(Value::String),
        proptest::collection::vec(any::<u8>(), 0..300).prop_map(Value::Bytes),
    ];
    leaf.prop_recursive(6, 64, 20, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..20).prop_map(Value::List),
            proptest::collection::vec(("[a-z]{1,8}", inner.clone()), 0..20).prop_map(Value::Map),
            (any::<u8>(), proptest::collection::vec(inner, 0..16))
                .prop_map(|(tag, fields)| Value::Struct { tag, fields }),
        ]
    })
}

proptest! {
    #[test]
    fn every_value_round_trips(value in arb_value()) {
        let bytes = to_bytes(&value);
        prop_assert_eq!(decode(&bytes), Ok(value.clone()));
    }

    #[test]
    fn every_value_round_trips_through_chunking(value in arb_value()) {
        let framed = packstream::message_bytes(&value);
        let mut d = Dechunker::new(MAX_MESSAGE_BYTES);
        d.push(&framed);
        let message = d.next_message().expect("within the cap").expect("complete");
        prop_assert_eq!(decode(&message), Ok(value));
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode(&bytes);
    }
}

// --- JSON from the model -----------------------------------------------------------------------

#[test]
fn plain_json_maps_to_the_obvious_packstream_types() {
    let v = json_to_value(&json!(["s", -17, 1.5, true, null, [1], {"k": "v"}])).unwrap();
    assert_eq!(
        v,
        Value::List(vec![
            Value::string("s"),
            Value::Int(-17),
            Value::Float(1.5),
            Value::Bool(true),
            Value::Null,
            Value::List(vec![Value::Int(1)]),
            Value::map([("k", Value::string("v"))]),
        ])
    );
    assert!(json_to_value(&json!(18446744073709551615u64)).is_err());
}

#[test]
fn a_node_becomes_a_bolt_5_node_structure_with_an_element_id() {
    let v = json_to_value(
        &json!({"$node": {"id": 7, "labels": ["Person"], "properties": {"name": "Ann"}}}),
    )
    .unwrap();
    assert_eq!(
        v,
        Value::Struct {
            tag: 0x4E,
            fields: vec![
                Value::Int(7),
                Value::List(vec![Value::string("Person")]),
                Value::map([("name", Value::string("Ann"))]),
                Value::string("7"),
            ]
        }
    );
}

#[test]
fn a_path_walked_backwards_gets_a_negative_relationship_index() {
    let a = json!({"id": 1, "labels": ["A"]});
    let b = json!({"id": 2, "labels": ["B"]});
    let c = json!({"id": 3, "labels": ["C"]});
    // 1 -[10]-> 2 <-[11]- 3 : the second hop runs against its relationship.
    let path = json!({"$path": {
        "nodes": [a, b, c],
        "relationships": [
            {"id": 10, "type": "R", "start": 1, "end": 2},
            {"id": 11, "type": "R", "start": 3, "end": 2}
        ]
    }});
    let Value::Struct { tag, fields } = json_to_value(&path).unwrap() else {
        panic!("not a structure")
    };
    assert_eq!(tag, 0x50);
    assert_eq!(fields.len(), 3);
    let Value::List(nodes) = &fields[0] else {
        panic!()
    };
    let Value::List(rels) = &fields[1] else {
        panic!()
    };
    assert_eq!(nodes.len(), 3);
    assert_eq!(rels.len(), 2);
    assert!(rels
        .iter()
        .all(|r| matches!(r, Value::Struct { tag: 0x72, fields } if fields.len() == 4)));
    assert_eq!(
        fields[2],
        Value::List(vec![
            Value::Int(1),
            Value::Int(1),
            Value::Int(-2),
            Value::Int(2)
        ])
    );

    let broken = json!({"$path": {"nodes": [{"id": 1}, {"id": 2}],
                                  "relationships": [{"id": 10, "type": "R", "start": 1, "end": 5}]}});
    assert!(json_to_value(&broken).is_err());
}

#[test]
fn a_model_value_deeper_than_the_decoder_accepts_is_refused() {
    let mut deep = json!(1);
    for _ in 0..(MAX_PACKSTREAM_DEPTH + 2) {
        deep = json!([deep]);
    }
    assert!(json_to_value(&deep).is_err());
}

#[test]
fn parameters_reach_the_model_as_json_without_raw_bytes() {
    let params = Value::map([
        ("name", Value::string("Ann")),
        ("blob", Value::Bytes(vec![0xDE, 0xAD])),
        (
            "when",
            Value::Struct {
                tag: 0x44,
                fields: vec![Value::Int(19000)],
            },
        ),
    ]);
    assert_eq!(
        value_to_json(&params),
        json!({
            "name": "Ann",
            "blob": {"$bytes_length": 2},
            "when": {"$structure": "Date", "fields": [19000]}
        })
    );
}

#[test]
fn stats_use_the_wire_names_and_derive_contains_updates() {
    let v = values::stats_value(Some(&json!({"nodes_created": 2, "properties-set": 1})))
        .unwrap()
        .unwrap();
    assert_eq!(v.get("nodes-created"), Some(&Value::Int(2)));
    assert_eq!(v.get("properties-set"), Some(&Value::Int(1)));
    assert_eq!(v.get("contains-updates"), Some(&Value::Bool(true)));
    assert!(values::stats_value(Some(&json!({"rows_eaten": 1}))).is_err());
    assert!(values::stats_value(Some(&json!({"nodes_created": -1}))).is_err());
}

#[test]
fn failure_codes_must_have_the_neo4j_shape() {
    assert!(values::valid_failure_code(
        "Neo.ClientError.Statement.SyntaxError"
    ));
    assert!(values::valid_failure_code(
        "Neo.TransientError.Transaction.DeadlockDetected"
    ));
    assert!(values::valid_failure_code(
        "Neo.DatabaseError.General.UnknownError"
    ));
    for bad in [
        "SyntaxError",
        "Neo.ClientError.Statement",
        "Neo.ClientNotification.Statement.CartesianProduct",
        "Neo.ClientError.Statement.Syntax Error",
        "Neo.ClientError..SyntaxError",
        "neo.ClientError.Statement.SyntaxError",
    ] {
        assert!(!values::valid_failure_code(bad), "{bad} was accepted");
    }
}
