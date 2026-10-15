//! In-memory schema/value fixtures only: no protoc, model, socket, or external peer.

use anyhow::Result;
use netget::server::grpc::value_codec::{
    ValueLimitExceeded, MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_NODES,
    VALUE_NODE_OVERHEAD_BYTES,
};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MapKey, MessageDescriptor, Value};
use prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet, MessageOptions,
    OneofDescriptorProto,
};
use serde_json::{json, Value as Json};

type Encode = fn(&Json, &MessageDescriptor) -> Result<DynamicMessage>;
type Decode = fn(&DynamicMessage) -> Result<Json>;
fn codecs() -> [(&'static str, Encode, Decode); 2] {
    [
        (
            "client",
            netget::client::grpc::json_to_dynamic_message,
            netget::client::grpc::dynamic_message_to_json,
        ),
        (
            "server",
            netget::server::grpc::json_to_dynamic_message,
            netget::server::grpc::dynamic_message_to_json,
        ),
    ]
}

fn field(
    name: &str,
    number: i32,
    kind: Type,
    repeated: bool,
    type_name: Option<&str>,
) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.into()),
        number: Some(number),
        r#type: Some(kind as i32),
        label: Some(if repeated {
            Label::Repeated
        } else {
            Label::Optional
        } as i32),
        type_name: type_name.map(str::to_owned),
        ..Default::default()
    }
}

fn descriptor() -> MessageDescriptor {
    let mut first = field("first", 10, Type::String, false, None);
    first.oneof_index = Some(0);
    let mut second = field("second", 11, Type::String, false, None);
    second.oneof_index = Some(0);
    let node = DescriptorProto {
        name: Some("Node".into()),
        field: vec![
            field("name", 1, Type::String, false, None),
            field("child", 2, Type::Message, false, Some(".audit.Node")),
            field("children", 3, Type::Message, true, Some(".audit.Node")),
            field(
                "named",
                4,
                Type::Message,
                true,
                Some(".audit.Node.NamedEntry"),
            ),
            field("samples", 5, Type::Int32, true, None),
            field("blob", 6, Type::Bytes, false, None),
            field("small", 7, Type::Float, false, None),
            field("big", 8, Type::Double, false, None),
            field(
                "numeric",
                9,
                Type::Message,
                true,
                Some(".audit.Node.NumericEntry"),
            ),
            first,
            second,
        ],
        nested_type: vec![
            DescriptorProto {
                name: Some("NamedEntry".into()),
                field: vec![
                    field("key", 1, Type::String, false, None),
                    field("value", 2, Type::Message, false, Some(".audit.Node")),
                ],
                options: Some(MessageOptions {
                    map_entry: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
            DescriptorProto {
                name: Some("NumericEntry".into()),
                field: vec![
                    field("key", 1, Type::Int32, false, None),
                    field("value", 2, Type::String, false, None),
                ],
                options: Some(MessageOptions {
                    map_entry: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
        oneof_decl: vec![OneofDescriptorProto {
            name: Some("choice".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    DescriptorPool::from_file_descriptor_set(FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("value-bounds.proto".into()),
            package: Some("audit".into()),
            syntax: Some("proto3".into()),
            message_type: vec![node],
            ..Default::default()
        }],
    })
    .unwrap()
    .get_message_by_name("audit.Node")
    .unwrap()
}

fn assert_limit(error: anyhow::Error, dimension: &str) {
    let limit = error
        .downcast_ref::<ValueLimitExceeded>()
        .unwrap_or_else(|| panic!("expected {dimension} limit, got {error:#}"));
    assert_eq!(limit.dimension, dimension);
}

fn nested_json(levels: usize, field: &str) -> Json {
    let mut value = json!({});
    for _ in 0..levels {
        value = match field {
            "child" => json!({"child": value}),
            "children" => json!({"children": [value]}),
            "named" => json!({"named": {"entry": value}}),
            _ => unreachable!(),
        };
    }
    value
}

#[test]
fn valid_nested_messages_lists_maps_and_bytes_round_trip_through_protobuf() {
    let descriptor = descriptor();
    let original = json!({
        "name": "root", "child": {"name": "child"},
        "children": [{"name": "one"}, {"name": "two", "child": {"name": "leaf"}}],
        "named": {"left": {"name": "map child", "samples": [1, -2, 3]}},
        "numeric": {"-3": "negative", "7": "positive"},
        "blob": "AAH/", "small": 1.25, "big": 2.5, "first": "selected"
    });
    for (side, encode, decode) in codecs() {
        let message = encode(&original, &descriptor).unwrap();
        let decoded =
            DynamicMessage::decode(descriptor.clone(), message.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decode(&decoded).unwrap(), original, "{side}");
    }
}

#[test]
fn message_list_and_map_depth_limits_are_explicit_at_the_exact_boundary() {
    let descriptor = descriptor();
    for (_, encode, decode) in codecs() {
        for (field, step) in [("child", 1), ("children", 2), ("named", 2)] {
            let allowed = nested_json(MAX_VALUE_DEPTH / step, field);
            let message = encode(&allowed, &descriptor).unwrap();
            assert_eq!(decode(&message).unwrap(), allowed);
            let rejected = nested_json(MAX_VALUE_DEPTH / step + 1, field);
            assert_limit(encode(&rejected, &descriptor).unwrap_err(), "depth");
        }
    }
}

#[test]
fn programmatically_constructed_protobuf_trees_cannot_bypass_depth_checks() {
    let descriptor = descriptor();
    let child = descriptor.get_field_by_name("child").unwrap();
    let mut message = DynamicMessage::new(descriptor.clone());
    for _ in 0..=MAX_VALUE_DEPTH {
        let mut parent = DynamicMessage::new(descriptor.clone());
        parent
            .try_set_field(&child, Value::Message(message))
            .unwrap();
        message = parent;
    }
    for (_, _, decode) in codecs() {
        assert_limit(decode(&message).unwrap_err(), "depth");
    }
    let mut list = Value::I32(1);
    for _ in 0..=MAX_VALUE_DEPTH {
        list = Value::List(vec![list]);
    }
    assert_limit(
        netget::server::grpc::proto_value_to_json(&list).unwrap_err(),
        "depth",
    );
}

#[test]
fn node_budget_is_shared_by_repeated_values_in_both_directions() {
    let descriptor = descriptor();
    let allowed = json!({"samples": vec![1; MAX_VALUE_NODES - 2]});
    let rejected = json!({"samples": vec![1; MAX_VALUE_NODES - 1]});
    for (_, encode, decode) in codecs() {
        let message = encode(&allowed, &descriptor).unwrap();
        assert_eq!(decode(&message).unwrap(), allowed);
        assert_limit(encode(&rejected, &descriptor).unwrap_err(), "nodes");
    }
    let too_wide = Value::List(vec![Value::I32(1); MAX_VALUE_NODES]);
    assert_limit(
        netget::server::grpc::proto_value_to_json(&too_wide).unwrap_err(),
        "nodes",
    );
}

#[test]
fn byte_budget_checks_exact_size_aggregate_content_and_base64_expansion() {
    let allowed = Value::String("x".repeat(MAX_VALUE_BYTES - VALUE_NODE_OVERHEAD_BYTES));
    assert!(netget::server::grpc::proto_value_to_json(&allowed).is_ok());
    let rejected = Value::String("x".repeat(MAX_VALUE_BYTES - VALUE_NODE_OVERHEAD_BYTES + 1));
    assert_limit(
        netget::server::grpc::proto_value_to_json(&rejected).unwrap_err(),
        "bytes",
    );
    let aggregate = Value::List(vec![Value::String("x".repeat(MAX_VALUE_BYTES / 2)); 2]);
    assert_limit(
        netget::server::grpc::proto_value_to_json(&aggregate).unwrap_err(),
        "bytes",
    );
    let bytes = Value::Bytes(vec![0; (MAX_VALUE_BYTES / 4) * 3].into());
    assert_limit(
        netget::server::grpc::proto_value_to_json(&bytes).unwrap_err(),
        "bytes",
    );
    let descriptor = descriptor();
    let large_json = json!({"name": "x".repeat(MAX_VALUE_BYTES)});
    for (_, encode, _) in codecs() {
        assert_limit(encode(&large_json, &descriptor).unwrap_err(), "bytes");
    }
}

#[test]
fn malformed_values_fail_instead_of_becoming_defaults_or_overwriting_fields() {
    let descriptor = descriptor();
    for (_, encode, _) in codecs() {
        for invalid in [
            Json::Null,
            json!([]),
            json!("not an object"),
            json!({"unknown": 1}),
            json!({"child": false}),
            json!({"samples": [2147483648u64]}),
            json!({"small": 1e40}),
            json!({"small": 1e-50}),
            json!({"blob": "invalid!"}),
            json!({"numeric": {"1": "a", "01": "b"}}),
            json!({"first": "a", "second": "b"}),
        ] {
            assert!(encode(&invalid, &descriptor).is_err(), "accepted {invalid}");
        }
    }
    for value in [
        Value::F32(f32::NAN),
        Value::F32(f32::INFINITY),
        Value::F64(f64::NEG_INFINITY),
    ] {
        assert!(netget::server::grpc::proto_value_to_json(&value).is_err());
    }
    let conflicting = Value::Map(std::collections::HashMap::from([
        (MapKey::String("1".into()), Value::I32(1)),
        (MapKey::I32(1), Value::I32(2)),
    ]));
    assert!(netget::server::grpc::proto_value_to_json(&conflicting).is_err());
}

#[test]
fn request_conversion_errors_keep_resource_and_schema_statuses_distinct() {
    use netget::server::grpc::{grpc_status_for_value_failure, GrpcStatus};
    let descriptor = descriptor();
    let too_deep = nested_json(MAX_VALUE_DEPTH + 1, "child");
    let limited =
        netget::server::grpc::json_to_dynamic_message(&too_deep, &descriptor).unwrap_err();
    assert_eq!(
        grpc_status_for_value_failure(&limited),
        GrpcStatus::ResourceExhausted
    );
    let malformed =
        netget::server::grpc::json_to_dynamic_message(&json!([]), &descriptor).unwrap_err();
    assert_eq!(
        grpc_status_for_value_failure(&malformed),
        GrpcStatus::InvalidArgument
    );
}
