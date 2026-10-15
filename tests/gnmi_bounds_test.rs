use netget::server::gnmi::{codec, json, proto::gnmi as pb};
use prost::Message;
use tonic::Code;
fn varint(mut number: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while number >= 128 {
        out.push((number as u8 & 127) | 128);
        number >>= 7;
    }
    out.push(number as u8);
    out
}
fn field(number: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint(u64::from(number) * 8 + 2);
    out.extend(varint(bytes.len() as u64));
    out.extend(bytes);
    out
}
#[test]
fn exact_message_and_plus_one_are_checked_before_decode() {
    let maximum = codec::MAX_MESSAGE_BYTES;
    let exact = field(999, &vec![0; maximum - 5]);
    assert_eq!(exact.len(), maximum);
    codec::validate_wire("gnmi.GetRequest", &exact).unwrap();
    assert_eq!(
        codec::validate_wire("gnmi.GetRequest", &field(999, &vec![0; maximum - 4]))
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
}
#[test]
fn repeated_paths_and_packed_encodings_bound_allocation() {
    for (count, good) in [(128, true), (129, false)] {
        let request = pb::GetRequest {
            path: vec![pb::Path::default(); count],
            ..Default::default()
        };
        assert_eq!(
            codec::validate_wire("gnmi.GetRequest", &request.encode_to_vec()).is_ok(),
            good
        );
        assert_eq!(
            codec::validate_wire("gnmi.CapabilityResponse", &field(2, &vec![3; count])).is_ok(),
            good
        );
    }
    let both = [field(2, &vec![3; 64]), field(2, &vec![3; 65])].concat();
    assert_eq!(
        codec::validate_wire("gnmi.CapabilityResponse", &both)
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
}
#[test]
fn typed_path_names_keys_and_element_counts_bound_before_prost() {
    for (count, good) in [(32, true), (33, false)] {
        let path = pb::Path {
            elem: vec![
                pb::PathElem {
                    name: "interfaces".into(),
                    ..Default::default()
                };
                count
            ],
            ..Default::default()
        };
        assert_eq!(
            codec::validate_wire("gnmi.Path", &path.encode_to_vec()).is_ok(),
            good
        );
    }
    for (count, good) in [(8, true), (9, false)] {
        let elem = pb::PathElem {
            name: "interface".into(),
            key: (0..count)
                .map(|index| (format!("key{index}"), "value".into()))
                .collect(),
        };
        assert_eq!(
            codec::validate_wire("gnmi.PathElem", &elem.encode_to_vec()).is_ok(),
            good
        );
    }
    let elem = pb::PathElem {
        name: "a".repeat(129),
        ..Default::default()
    };
    assert_eq!(
        codec::validate_wire("gnmi.PathElem", &elem.encode_to_vec())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
}
#[test]
fn opaque_values_extensions_truncation_and_varint_overflow_fail_closed() {
    for tag in [5, 9, 13] {
        assert_eq!(
            codec::validate_wire("gnmi.TypedValue", &field(tag, b"binary"))
                .unwrap_err()
                .code(),
            Code::Unimplemented
        );
    }
    assert_eq!(
        codec::validate_wire("gnmi.CapabilityRequest", &field(1, b""))
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    for bytes in [
        vec![18, 255, 255, 255, 127],
        vec![0],
        vec![8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
        vec![11],
        vec![18, 1],
    ] {
        assert_eq!(
            codec::validate_wire("gnmi.GetRequest", &bytes)
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
}
#[test]
fn json_expansion_depth_nodes_and_duplicate_keys_are_bounded() {
    for (length, good) in [
        (codec::MAX_VALUE_BYTES, true),
        (codec::MAX_VALUE_BYTES + 1, false),
    ] {
        let bytes = format!("\"{}\"", "a".repeat(length - 2));
        assert_eq!(json::parse(bytes.as_bytes()).is_ok(), good);
        assert_eq!(
            codec::validate_wire("gnmi.TypedValue", &field(11, bytes.as_bytes())).is_ok(),
            good
        );
    }
    for (depth, good) in [(32, true), (33, false)] {
        let bytes = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        let result = json::parse(bytes.as_bytes());
        assert_eq!(result.is_ok(), good);
        if !good {
            assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
        }
    }
    for (count, good) in [(codec::MAX_NODES - 1, true), (codec::MAX_NODES, false)] {
        let bytes = serde_json::to_vec(&vec![serde_json::Value::Null; count]).unwrap();
        assert_eq!(json::parse(&bytes).is_ok(), good);
    }
    assert!(json::parse(br#"{"a":1,"a":2}"#).is_err());
    assert!(json::parse(b"{}false").is_err());
}
#[test]
fn total_wire_field_nodes_are_bounded_even_when_singular_fields_repeat() {
    for (count, good) in [(codec::MAX_NODES, true), (codec::MAX_NODES + 1, false)] {
        let bytes = [10, 0].repeat(count);
        assert_eq!(
            codec::validate_wire("gnmi.TypedValue", &bytes).is_ok(),
            good
        );
    }
}
