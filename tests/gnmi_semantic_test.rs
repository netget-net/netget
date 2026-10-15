use netget::server::gnmi::{
    proto::gnmi as pb,
    semantic,
    value::{self, Element, Path, Value},
};
use serde_json::json;
use std::collections::BTreeMap;
fn path(name: &str) -> Path {
    Path {
        elem: vec![Element {
            name: name.into(),
            key: BTreeMap::from([("name".into(), "eth0".into())]),
        }],
        ..Default::default()
    }
}
#[test]
fn lossless_signed_unsigned_decimal_and_leaflist_values() {
    for value in [
        Value::Int(i64::MIN.to_string()),
        Value::Uint(u64::MAX.to_string()),
        Value::String("text\0value".into()),
        Value::Ascii("ascii\0value".into()),
        Value::Decimal(value::Decimal {
            digits: i64::MIN.to_string(),
            precision: 18,
        }),
        Value::Leaflist(vec![
            Value::String("word".into()),
            Value::Bool(true),
            Value::Double(0.125),
        ]),
    ] {
        assert_eq!(
            Value::from_proto(value.clone().into_proto().unwrap()).unwrap(),
            value
        );
    }
    assert!(Value::Int("9223372036854775808".into())
        .into_proto()
        .is_err());
    assert!(Value::Uint("-1".into()).into_proto().is_err());
    assert!(Value::Double(f64::INFINITY).into_proto().is_err());
    assert!(Value::Ascii("é".into()).into_proto().is_err());
    assert!(Value::Decimal(value::Decimal {
        digits: "1".into(),
        precision: 19
    })
    .into_proto()
    .is_err());
    assert!(Value::Leaflist(vec![Value::Leaflist(vec![])])
        .into_proto()
        .is_err());
    assert!(Value::Leaflist(vec![Value::Json(json!(1))])
        .into_proto()
        .is_err());
    Value::Leaflist(vec![Value::Bool(true); 64])
        .into_proto()
        .unwrap();
    assert_eq!(
        Value::Leaflist(vec![Value::Bool(true); 65])
            .into_proto()
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
}
#[test]
fn path_qualifiers_keys_and_empty_root_are_preserved() {
    let qualified = Path {
        origin: "openconfig".into(),
        target: "device".into(),
        ..path("interfaces")
    };
    assert_eq!(
        Path::from_proto(Some(qualified.clone().into_proto().unwrap())).unwrap(),
        qualified
    );
    assert_eq!(Path::from_proto(None).unwrap(), Path::default());
    assert!(Path::from_proto(Some(pb::Path {
        element: vec!["old".into()],
        ..Default::default()
    }))
    .is_err());
    assert!(path("").check().is_err());
}
#[test]
fn set_acknowledges_every_operation_in_required_transaction_order() {
    let request = pb::SetRequest {
        delete: vec![path("old").into_proto().unwrap()],
        replace: vec![pb::Update {
            path: Some(path("new").into_proto().unwrap()),
            val: Some(Value::String("value".into()).into_proto().unwrap()),
            ..Default::default()
        }],
        update: vec![pb::Update {
            path: None,
            val: Some(Value::Uint("1".into()).into_proto().unwrap()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let response = semantic::set_response(&request, "123456789").unwrap();
    assert_eq!(
        response.response.iter().map(|r| r.op).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(response.response[2].path, Some(pb::Path::default()));
    assert_eq!(response.timestamp, 123456789);
    assert_eq!(
        semantic::set_result(response).unwrap()["response"][0]["operation"],
        "DELETE"
    );
    let mut unsupported = request;
    unsupported.union_replace = unsupported.update.clone();
    assert_eq!(
        semantic::set_request(&unsupported).unwrap_err().code(),
        tonic::Code::Unimplemented
    );
}
#[test]
fn requested_encoding_and_subscription_options_are_enforced() {
    let notification = pb::Notification {
        update: vec![pb::Update {
            val: Some(Value::Json(json!({"counter":1})).into_proto().unwrap()),
            ..Default::default()
        }],
        ..Default::default()
    };
    value::notification_encoding(&notification, 0).unwrap();
    assert!(value::notification_encoding(&notification, 2).is_err());
    let mut list = pb::SubscriptionList {
        subscription: vec![pb::Subscription {
            path: Some(path("system").into_proto().unwrap()),
            ..Default::default()
        }],
        encoding: 2,
        ..Default::default()
    };
    for mode in 0..=2 {
        list.mode = mode;
        semantic::subscription(&list).unwrap();
    }
    list.subscription[0].mode = 2;
    assert!(semantic::subscription(&list).is_err());
    list.subscription[0].mode = 0;
    list.subscription[0].heartbeat_interval = 1;
    assert!(semantic::subscription(&list).is_err());
    list.subscription[0].heartbeat_interval = 0;
    list.qos = Some(pb::QosMarking { marking: 10 });
    assert!(semantic::subscription(&list).is_err());
}
#[test]
fn direct_model_values_have_independent_depth_nodes_and_retained_bounds() {
    let mut nested = json!(true);
    for _ in 0..33 {
        nested = json!([nested]);
    }
    assert_eq!(
        semantic::check_model(&nested).unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    assert!(semantic::check_model(&json!(vec![true; 10000])).is_err());
    assert!(semantic::check_model(&json!("x".repeat(65537))).is_err());
    assert!(semantic::check_model(&json!(vec!["x".repeat(65536); 17])).is_err());
    let bad = json!({"type":"gnmi_subscribe","call_id":1,"request":{"mode":"ONCE","subscription":[{"path":{}}],"encoding":"PROTO","sample_interval":1}});
    assert!(netget::client::gnmi::request::parse(&bad).is_err());
    assert!(netget::client::gnmi::request::parse(
        &json!({"type":"gnmi_capabilities","call_id":1,"metadata":{"x-any":"ignored"}})
    )
    .is_err());
}
#[test]
fn omitted_and_present_empty_set_ack_paths_have_the_same_root_semantics() {
    let request = pb::SetRequest {
        prefix: Some(pb::Path::default()),
        delete: vec![pb::Path::default()],
        ..Default::default()
    };
    let response = pb::SetResponse {
        response: vec![pb::UpdateResult {
            op: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    semantic::check_set_ack(&request, &response).unwrap();
    let mut wrong = response;
    wrong.response[0].op = 3;
    assert!(semantic::check_set_ack(&request, &wrong).is_err());
}
#[test]
fn recursive_protobuf_depth_is_checked_before_prost() {
    use prost::Message;
    let mut value = pb::TypedValue {
        value: Some(pb::typed_value::Value::BoolVal(true)),
    };
    for _ in 0..16 {
        value = pb::TypedValue {
            value: Some(pb::typed_value::Value::LeaflistVal(pb::ScalarArray {
                element: vec![value],
            })),
        };
    }
    netget::server::gnmi::codec::validate_wire("gnmi.TypedValue", &value.encode_to_vec()).unwrap();
    value = pb::TypedValue {
        value: Some(pb::typed_value::Value::LeaflistVal(pb::ScalarArray {
            element: vec![value],
        })),
    };
    assert_eq!(
        netget::server::gnmi::codec::validate_wire("gnmi.TypedValue", &value.encode_to_vec())
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
}
