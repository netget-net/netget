//! The OTLP codec on its own: what the model is told about an export in each encoding, what
//! NetGet refuses to decode, the gzip bound, and every response body.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- otlp::codec --test-threads=100


use super::common::{gzip, string_attribute, traces_json, traces_protobuf};
use netget::server::otlp::codec::{self, Encoding, Signal};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::metrics::v1::{
    metric::Data, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;

#[test]
fn a_protobuf_trace_export_is_summarised_not_forwarded() {
    let body = traces_protobuf("checkout", &["GET /cart", "SELECT items"]);
    let s = codec::summarize(Signal::Traces, Encoding::Protobuf, &body).unwrap();
    assert_eq!(s.resource_count, 1);
    assert_eq!(s.services, vec!["checkout"]);
    assert_eq!(s.item_count, 2);
    assert_eq!(s.names, vec!["GET /cart", "SELECT items"]);
    let event = s.to_event(Signal::Traces, Encoding::Protobuf, false, body.len());
    assert_eq!(event["service_name"], "checkout");
    assert_eq!(event["span_count"], 2);
    assert_eq!(event["resource_attributes"]["service.name"], "checkout");
    assert!(
        event.get("metric_names").is_none(),
        "only the signal's own fields"
    );
    let text = event.to_string();
    assert!(
        !text.contains("5b8efff7") && !text.contains("0101010101"),
        "no ids: {text}"
    );
}

#[test]
fn the_json_encoding_reads_the_same_in_either_key_style() {
    let camel = traces_json("checkout", &["GET /cart"]);
    let s = codec::summarize(Signal::Traces, Encoding::Json, &camel).unwrap();
    assert_eq!(
        (s.services.clone(), s.item_count),
        (vec!["checkout".to_string()], 1)
    );
    assert_eq!(s.names, vec!["GET /cart"]);

    let snake = serde_json::json!({"resource_spans": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"string_value": "api"}}]},
        "scope_spans": [{"spans": [{"name": "a", "status": {"code": "STATUS_CODE_ERROR"}},
                                    {"name": "b", "status": {"code": 2}}]}]
    }]});
    let s = codec::summarize(Signal::Traces, Encoding::Json, snake.to_string().as_bytes()).unwrap();
    assert_eq!(s.services, vec!["api"]);
    assert_eq!(
        (s.item_count, s.error_count),
        (2, 2),
        "ERROR as a name or a number"
    );
}

#[test]
fn metrics_count_data_points_across_every_kind() {
    let point = NumberDataPoint::default;
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![string_attribute("service.name", "billing")],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![
                    Metric {
                        name: "queue.depth".into(),
                        data: Some(Data::Gauge(Gauge {
                            data_points: vec![point(), point()],
                        })),
                        ..Default::default()
                    },
                    Metric {
                        name: "requests".into(),
                        data: Some(Data::Sum(Sum {
                            data_points: vec![point()],
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let s = codec::summarize(
        Signal::Metrics,
        Encoding::Protobuf,
        &request.encode_to_vec(),
    )
    .unwrap();
    assert_eq!((s.metric_count, s.item_count), (2, 3));
    assert_eq!(s.names, vec!["queue.depth", "requests"]);

    let json = serde_json::json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
        {"name": "m1", "gauge": {"dataPoints": [{"asDouble": 1.5}]}},
        {"name": "m2", "histogram": {"dataPoints": [{}, {}], "aggregationTemporality": 2}},
        {"name": "m3", "exponentialHistogram": {"dataPoints": [{}]}}
    ]}]}]});
    let s = codec::summarize(Signal::Metrics, Encoding::Json, json.to_string().as_bytes()).unwrap();
    assert_eq!((s.metric_count, s.item_count), (3, 4));
}

#[test]
fn log_bodies_are_text_and_bytes_are_described_not_shown() {
    let record = |body: any_value::Value, severity: i32| LogRecord {
        body: Some(AnyValue { value: Some(body) }),
        severity_number: severity,
        ..Default::default()
    };
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![
                    record(
                        any_value::Value::StringValue("disk full\non /var".into()),
                        17,
                    ),
                    record(any_value::Value::BytesValue(vec![0xde, 0xad, 0xbe]), 9),
                    record(any_value::Value::IntValue(42), 9),
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let s = codec::summarize(Signal::Logs, Encoding::Protobuf, &request.encode_to_vec()).unwrap();
    assert_eq!((s.item_count, s.error_count), (3, 1));
    assert_eq!(s.names, vec!["disk full on /var", "<3 bytes>", "42"]);

    let json = serde_json::json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"body": {"stringValue": "hello"}, "severityNumber": 21},
        {"body": {"kvlistValue": {"values": [{"key": "a"}]}}, "severityNumber": "9"}
    ]}]}]});
    let s = codec::summarize(Signal::Logs, Encoding::Json, json.to_string().as_bytes()).unwrap();
    assert_eq!((s.item_count, s.error_count), (2, 1));
    assert_eq!(s.names, vec!["hello", "<map of 1>"]);
}

#[test]
fn what_the_model_sees_is_bounded() {
    let names: Vec<String> = (0..50)
        .map(|i| format!("span-{i}-{}", "x".repeat(300)))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let s = codec::summarize(
        Signal::Traces,
        Encoding::Protobuf,
        &traces_protobuf("s", &refs),
    )
    .unwrap();
    assert_eq!(s.item_count, 50);
    assert_eq!(s.names.len(), codec::MAX_NAMES);
    assert!(s.names.iter().all(|n| n.len() < 150), "each name is cut");
}

#[test]
fn a_payload_that_does_not_decode_is_an_error() {
    for (encoding, body) in [
        (Encoding::Protobuf, b"\xff\xff\xff\xff".to_vec()),
        (Encoding::Json, b"not json".to_vec()),
        (Encoding::Json, b"[1, 2]".to_vec()),
        (
            Encoding::Json,
            br#"{"resourceSpans": {"not": "a list"}}"#.to_vec(),
        ),
        (
            Encoding::Json,
            br#"{"resourceSpans": [{"scopeSpans": [{"spans": [7]}]}]}"#.to_vec(),
        ),
    ] {
        assert!(
            codec::summarize(Signal::Traces, encoding, &body).is_err(),
            "{encoding:?} {:?}",
            String::from_utf8_lossy(&body)
        );
    }
    // Unknown fields are ignored, as the specification requires.
    let ok = br#"{"resourceSpans": [], "somethingNew": {"x": 1}}"#;
    assert!(codec::summarize(Signal::Traces, Encoding::Json, ok).is_ok());
    // An empty export is valid in both encodings.
    assert_eq!(
        codec::summarize(Signal::Logs, Encoding::Protobuf, b"")
            .unwrap()
            .item_count,
        0
    );
}

/// An attribute value nested 10,000 arrays deep: prost's recursion limit (100) and serde_json's
/// (128) must turn it into a decode error, not a stack overflow.
#[test]
fn a_depth_bomb_in_either_encoding_is_refused() {
    // Built as bytes, inside-out: a 10,000-deep AnyValue tree would itself overflow the stack
    // when dropped.
    let bomb = protobuf_depth_bomb(10_000);
    let err = codec::summarize(Signal::Traces, Encoding::Protobuf, &bomb).unwrap_err();
    assert!(err.contains("recursion limit"), "{err}");

    let mut json =
        String::from(r#"{"resourceSpans": [{"resource": {"attributes": [{"key": "b", "value": "#);
    json.push_str(&"[".repeat(10_000));
    json.push_str(&"]".repeat(10_000));
    json.push_str("}]}}]}");
    let err = codec::summarize(Signal::Traces, Encoding::Json, json.as_bytes()).unwrap_err();
    assert!(err.contains("recursion limit"), "{err}");
}

/// `ExportTraceServiceRequest { resource_spans: [{ resource: { attributes: [{ key: "b",
/// value: AnyValue{array_value: {values: [AnyValue{array_value: ...}]}} }] } }] }`, `depth`
/// arrays deep, written inside-out so nothing here recurses.
fn protobuf_depth_bomb(depth: usize) -> Vec<u8> {
    fn field(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        prost::encoding::encode_key(tag, prost::encoding::WireType::LengthDelimited, &mut out);
        prost::encoding::encode_varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }
    // AnyValue { string_value: "x" }
    let mut any = field(1, b"x");
    for _ in 0..depth {
        let array = field(1, &any); // ArrayValue.values
        any = field(5, &array); // AnyValue.array_value
    }
    let kv = [field(1, b"b"), field(2, &any)].concat(); // KeyValue
    let resource = field(1, &kv); // Resource.attributes
    let resource_spans = field(1, &resource); // ResourceSpans.resource
    field(1, &resource_spans) // ExportTraceServiceRequest.resource_spans
}

#[test]
fn gzip_is_held_to_the_cap_after_inflation() {
    let exact = vec![b'a'; 4096];
    assert_eq!(codec::gunzip_bounded(&gzip(&exact), 4096).unwrap(), exact);
    assert_eq!(
        codec::gunzip_bounded(&gzip(&vec![b'a'; 4097]), 4096),
        Err(codec::BodyError::TooLarge)
    );
    assert_eq!(
        codec::gunzip_bounded(b"not gzip", 4096),
        Err(codec::BodyError::BadGzip)
    );
    // A 4 MiB + 1 bomb is a few kilobytes on the wire.
    let bomb = gzip(&vec![0u8; codec::MAX_BODY_BYTES + 1]);
    assert!(bomb.len() < 16 * 1024, "{}", bomb.len());
    assert_eq!(
        codec::gunzip_bounded(&bomb, codec::MAX_BODY_BYTES),
        Err(codec::BodyError::TooLarge)
    );
}

#[test]
fn responses_decode_as_the_specification_defines_them() {
    let full = codec::export_response(Signal::Traces, Encoding::Protobuf, None);
    assert!(full.is_empty(), "a full success is the empty message");
    assert_eq!(
        ExportTraceServiceResponse::decode(&*full).unwrap(),
        ExportTraceServiceResponse::default()
    );
    let partial = codec::export_response(Signal::Metrics, Encoding::Protobuf, Some((3, "stale")));
    let partial = ExportMetricsServiceResponse::decode(&*partial)
        .unwrap()
        .partial_success
        .unwrap();
    assert_eq!(
        (partial.rejected_data_points, partial.error_message.as_str()),
        (3, "stale")
    );
    let logs = codec::export_response(Signal::Logs, Encoding::Protobuf, Some((1, "x")));
    assert_eq!(
        ExportLogsServiceResponse::decode(&*logs)
            .unwrap()
            .partial_success
            .unwrap()
            .rejected_log_records,
        1
    );

    let json: serde_json::Value = serde_json::from_slice(&codec::export_response(
        Signal::Traces,
        Encoding::Json,
        None,
    ))
    .unwrap();
    assert_eq!(json, serde_json::json!({}));
    let json: serde_json::Value = serde_json::from_slice(&codec::export_response(
        Signal::Logs,
        Encoding::Json,
        Some((2, "too old")),
    ))
    .unwrap();
    assert_eq!(
        json,
        serde_json::json!({"partialSuccess": {"rejectedLogRecords": "2", "errorMessage": "too old"}})
    );

    let status =
        codec::RpcStatus::decode(&*codec::status_body(Encoding::Protobuf, 429, "slow down"))
            .unwrap();
    assert_eq!((status.code, status.message.as_str()), (8, "slow down"));
    let status: serde_json::Value =
        serde_json::from_slice(&codec::status_body(Encoding::Json, 403, "no")).unwrap();
    assert_eq!(status, serde_json::json!({"code": 7, "message": "no"}));
    assert!(codec::retryable(503) && !codec::retryable(400));
}

#[test]
fn content_types_and_paths() {
    assert_eq!(
        Encoding::from_content_type("application/json; charset=utf-8"),
        Some(Encoding::Json)
    );
    assert_eq!(
        Encoding::from_content_type("Application/X-Protobuf"),
        Some(Encoding::Protobuf)
    );
    assert_eq!(Encoding::from_content_type("text/plain"), None);
    assert_eq!(Signal::from_path("/v1/logs"), Some(Signal::Logs));
    assert_eq!(Signal::from_path("/v1/traces/"), None);
}
