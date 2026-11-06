//! The gRPC server's unary request path: `decode_grpc_frame` (the 5-byte length-prefixed
//! message header), then `prost_reflect::DynamicMessage::decode` against the method's input
//! descriptor, then `value_codec::dynamic_message_to_json` — the bounded conversion that
//! produces what the model is shown — and the streaming path's `stream_codec::to_json`.
//!
//! The server's schema is whatever the operator loaded, so the target carries one written to
//! reach every branch of the conversion: a **recursive** message (`Node` holds a `Node`, a
//! `repeated Node`, a `map<string, Node>` and a oneof with a `Node` in it), every scalar class,
//! an enum, packed repeated integers and a bytes field.
//!
//! Two independent depth bounds stand between a deep message and the stack, and the corpus
//! carries a bomb for each:
//!
//! - prost's recursion limit (100), which `DynamicMessage::decode` inherits through
//!   `prost::encoding::message::merge` and which also bounds nested unknown-field *groups*.
//!   Cargo feature unification can delete it: any crate in the graph that enables prost's
//!   `no-recursion-limit` turns it off for every decoder in the process.
//! - `value_codec::MAX_VALUE_DEPTH` (32), which `message_to_json` checks as it recurses.
//!
//! `nested_child_bomb` (20 000 levels of `child`) and `unknown_group_bomb` (20 000 nested
//! groups in an unknown field) are refused by the first; `deep_inside_prost_limit` (90 levels)
//! decodes and is refused by the second.
//!
//! Asserted: nothing panics or overflows; a message that decodes re-encodes and decodes again;
//! JSON the converter produced converts back through `json_to_dynamic_message` without panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::grpc::{decode_grpc_frame, stream_codec, value_codec, MAX_REQUEST_BYTES};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, FileDescriptorSet, MessageOptions, OneofDescriptorProto,
};
use std::sync::LazyLock;

fn field(
    name: &str,
    number: i32,
    label: Label,
    ty: Type,
    type_name: Option<&str>,
) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.to_string()),
        number: Some(number),
        label: Some(label as i32),
        r#type: Some(ty as i32),
        type_name: type_name.map(str::to_string),
        json_name: Some(name.to_string()),
        ..Default::default()
    }
}

static NODE: LazyLock<MessageDescriptor> = LazyLock::new(|| {
    use Label::{Optional, Repeated};
    let mut text = field("text", 11, Optional, Type::String, None);
    text.oneof_index = Some(0);
    let mut nested = field("nested", 12, Optional, Type::Message, Some(".fuzz.Node"));
    nested.oneof_index = Some(0);
    let entry = DescriptorProto {
        name: Some("ByNameEntry".to_string()),
        field: vec![
            field("key", 1, Optional, Type::String, None),
            field("value", 2, Optional, Type::Message, Some(".fuzz.Node")),
        ],
        options: Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    let node = DescriptorProto {
        name: Some("Node".to_string()),
        field: vec![
            field("name", 1, Optional, Type::String, None),
            field("count", 2, Optional, Type::Int64, None),
            field("children", 3, Repeated, Type::Message, Some(".fuzz.Node")),
            field(
                "by_name",
                4,
                Repeated,
                Type::Message,
                Some(".fuzz.Node.ByNameEntry"),
            ),
            field("child", 5, Optional, Type::Message, Some(".fuzz.Node")),
            field("ratio", 6, Optional, Type::Double, None),
            field("flag", 7, Optional, Type::Bool, None),
            field("kind", 8, Optional, Type::Enum, Some(".fuzz.Kind")),
            field("packed", 9, Repeated, Type::Sint32, None),
            field("f64", 10, Optional, Type::Fixed64, None),
            text,
            nested,
            field("blob", 13, Optional, Type::Bytes, None),
            field("score", 14, Optional, Type::Float, None),
            field("u32", 15, Optional, Type::Uint32, None),
        ],
        nested_type: vec![entry],
        oneof_decl: vec![OneofDescriptorProto {
            name: Some("choice".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let kind = EnumDescriptorProto {
        name: Some("Kind".to_string()),
        value: ["KIND_UNSPECIFIED", "KIND_A", "KIND_B"]
            .iter()
            .enumerate()
            .map(|(i, n)| EnumValueDescriptorProto {
                name: Some(n.to_string()),
                number: Some(i as i32),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("fuzz.proto".to_string()),
        package: Some("fuzz".to_string()),
        message_type: vec![node],
        enum_type: vec![kind],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    DescriptorPool::from_file_descriptor_set(FileDescriptorSet { file: vec![file] })
        .expect("the fuzz schema is valid")
        .get_message_by_name("fuzz.Node")
        .expect("fuzz.Node is in the pool")
});

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_REQUEST_BYTES {
        return;
    }
    let Ok(payload) = decode_grpc_frame(data) else {
        return;
    };
    assert!(
        payload.len() + 5 <= data.len(),
        "frame returned bytes it was not given"
    );
    let Ok(message) = DynamicMessage::decode(NODE.clone(), payload.as_slice()) else {
        return;
    };

    let encoded = message.encode_to_vec();
    DynamicMessage::decode(NODE.clone(), encoded.as_slice())
        .expect("a message prost-reflect encoded did not decode back");

    if let Ok(json) = value_codec::dynamic_message_to_json(&message) {
        let _ = value_codec::json_to_dynamic_message(&json, &NODE);
    }
    let _ = stream_codec::to_json(&message);
});
