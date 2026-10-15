//! The OTLP receiver end to end with a mocked model, over raw HTTP.
//!
//! `real_client_test.rs` is the evidence that OpenTelemetry's own exporters accept what this
//! receiver writes. This file pins the exact responses in both encodings: a JSON trace export
//! the model accepts (`{}`), a gzip protobuf metrics export it partly accepts (a partial success
//! naming the rejected data points), a JSON logs export it refuses with 429 and Retry-After (a
//! `google.rpc.Status`). The refusals NetGet makes itself — another path, method, content type
//! or content encoding — cost no model call (`expect_calls`).
//!
//! LLM budget: 4 calls (open_server, one per signal).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- otlp::e2e --test-threads=100


use super::common::{gzip, post, request, traces_json, GZIP, JSON, PROTOBUF};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::metrics::v1::{
    metric::Data, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;

#[tokio::test]
async fn an_otlp_session_against_a_mocked_model() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via otlp. A receiver.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via otlp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "otlp",
                    "instruction": "A receiver"
                }]))
                .expect_calls(1)
                .and()
                // One rule branching on the signal; each answer depends on the summary being
                // exactly right, so a wrong summary shows up as a different response.
                .on_event("otlp_export")
                .respond_with_actions_from_event(|e| match e["signal"].as_str() {
                    Some("traces")
                        if e["service_name"] == "checkout"
                            && e["span_names"] == serde_json::json!(["GET /cart", "charge"])
                            && e["span_count"] == 2
                            && e["encoding"] == "json" =>
                    {
                        serde_json::json!([{"type": "accept_otlp"}])
                    }
                    Some("metrics")
                        if e["compressed"] == true
                            && e["metric_names"] == serde_json::json!(["cpu.load"])
                            && e["data_point_count"] == 3 =>
                    {
                        serde_json::json!([{"type": "accept_otlp_partially", "rejected": 2,
                                            "error_message": "points too old"}])
                    }
                    Some("logs") if e["log_bodies"] == serde_json::json!(["disk full"]) => {
                        serde_json::json!([{"type": "reject_otlp", "code": 429,
                                            "message": "log quota spent", "retry_after_secs": 30}])
                    }
                    _ => serde_json::json!([{"type": "reject_otlp", "code": 400,
                                             "message": "unexpected summary"}]),
                })
                .expect_calls(3)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    // Traces, JSON: a full success is `{}` in the request's content type.
    let reply = post(
        port,
        "/v1/traces",
        &[JSON],
        &traces_json("checkout", &["GET /cart", "charge"]),
    )
    .await;
    assert_eq!(
        reply.status,
        200,
        "{:?}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(reply.json(), serde_json::json!({}));

    // Metrics, gzip protobuf: a partial success naming 2 rejected data points.
    let point = NumberDataPoint::default;
    let metrics = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource::default()),
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![Metric {
                    name: "cpu.load".into(),
                    data: Some(Data::Gauge(Gauge {
                        data_points: vec![point(), point(), point()],
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec();
    let reply = post(port, "/v1/metrics", &[PROTOBUF, GZIP], &gzip(&metrics)).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/x-protobuf"));
    let partial = ExportMetricsServiceResponse::decode(&*reply.body)
        .unwrap()
        .partial_success
        .expect("a partial success");
    assert_eq!(
        (partial.rejected_data_points, partial.error_message.as_str()),
        (2, "points too old")
    );

    // Logs, JSON: refused 429 with Retry-After and a google.rpc.Status body.
    let logs = serde_json::json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"body": {"stringValue": "disk full"}, "severityNumber": 17}
    ]}]}]});
    let reply = post(port, "/v1/logs", &[JSON], logs.to_string().as_bytes()).await;
    assert_eq!(reply.status, 429);
    assert_eq!(reply.header("retry-after"), Some("30"));
    assert_eq!(
        reply.json(),
        serde_json::json!({"code": 8, "message": "log quota spent"})
    );

    // NetGet's own refusals: none of these reaches the model.
    assert_eq!(post(port, "/v1/spans", &[JSON], b"{}").await.status, 404);
    let reply = request(port, "GET", "/v1/traces", &[], b"").await;
    assert_eq!((reply.status, reply.header("allow")), (405, Some("POST")));
    assert_eq!(
        post(port, "/v1/traces", &[("Content-Type", "text/plain")], b"{}")
            .await
            .status,
        415
    );
    let reply = post(
        port,
        "/v1/traces",
        &[JSON, ("Content-Encoding", "br")],
        b"{}",
    )
    .await;
    assert_eq!(reply.status, 415);
    assert_eq!(
        reply.json()["code"],
        13,
        "a Status in the request's encoding"
    );
    let reply = post(port, "/v1/traces", &[JSON, GZIP], b"not gzip").await;
    assert_eq!(reply.status, 400);
    let reply = post(port, "/v1/logs", &[PROTOBUF], b"\xff\xff\xff").await;
    assert_eq!(reply.status, 400);
    let status = netget::server::otlp::codec::RpcStatus::decode(&*reply.body).unwrap();
    assert_eq!(status.code, 3, "INVALID_ARGUMENT");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
