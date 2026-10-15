//! The OTLP receiver against real, independent OpenTelemetry exporters.
//!
//! - **`otel-cli`** (equinix-labs, Go; Homebrew `otel-cli`, the release binary on Ubuntu) sends
//!   one span over `http/protobuf`, encoding it with the OpenTelemetry project's Go protobuf
//!   bindings and its own OTLP/HTTP client. With `--fail` it exits non-zero on any response but a
//!   success, so its exit status is a reading of our response.
//! - **`telemetrygen`** (the OpenTelemetry Collector project's load generator; `go install
//!   …/cmd/telemetrygen`) sends metrics and logs through the OpenTelemetry Go SDK's OTLP/HTTP
//!   exporters — a second, independent encoder and a second response reader.
//!
//! Neither is linked by NetGet, and NetGet's decoder is `opentelemetry-proto` (Rust), so the two
//! sides share only the `.proto` files. The first test is answered by a Python script handler,
//! so it is deterministic; the others put a mocked model behind the exporters and record every
//! event it was shown.
//!
//! **These tests FAIL, they do not skip, when a binary is absent.** A skip gate returns `Ok(())`
//! on a runner without them and the rating built on it rests on nothing;
//! `tests/server/memcached/real_client_test.rs` is the precedent. A generic HTTP client would not
//! do here: it proves an HTTP server answers, not that OTLP on top is right.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features otlp --test server -- otlp::real_client --test-threads=100

use super::common;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
fn require_tool(name: &str) -> String {
    let home_go = std::env::var("HOME")
        .map(|h| format!("{h}/go/bin"))
        .unwrap_or_default();
    for prefix in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        home_go.as_str(),
    ] {
        let candidate = std::path::Path::new(prefix).join(name);
        if !prefix.is_empty() && candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        if let Some(found) = path
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|candidate| candidate.exists())
        {
            return found.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin, ~/go/bin and \
         $PATH). These tests drive OpenTelemetry exporters - otel-cli and the Collector \
         project's telemetrygen - against NetGet's OTLP/HTTP receiver, and they are the only \
         independent check that the responses NetGet encodes are what an OTLP exporter reads. \
         Skipping would leave the OTLP evidence resting on nothing, so this is a failure and not \
         a skip. Install otel-cli with `brew install otel-cli` (macOS) or the release binary \
         from https://github.com/equinix-labs/otel-cli/releases (Debian/Ubuntu), and \
         telemetrygen with `go install \
         github.com/open-telemetry/opentelemetry-collector-contrib/cmd/telemetrygen@v0.161.0`."
    );
}

/// Run a tool; returns (exit code, stdout + stderr).
pub(super) async fn run(tool: &str, args: &[String]) -> (i32, String) {
    let bin = require_tool(tool);
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(&bin)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{tool} {args:?} did not exit within 120s"))
    .expect("run the client");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "--- {tool} {} (exit {:?}) ---\n{text}",
        args.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), text)
}

fn otel_cli_span(port: u16, service: &str, name: &str) -> Vec<String> {
    [
        "span",
        "--endpoint",
        &format!("http://127.0.0.1:{port}"),
        "--protocol",
        "http/protobuf",
        "--insecure",
        "--service",
        service,
        "--name",
        name,
        "--timeout",
        "30s",
        "--fail",
        "--verbose",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn telemetrygen(port: u16, signal: &str, extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = [
        signal,
        "--otlp-http",
        "--otlp-insecure",
        "--otlp-endpoint",
        &format!("127.0.0.1:{port}"),
        "--rate",
        "0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

/// Accept exactly one span named `charge card` from the service `checkout`; refuse anything
/// else with 403. So otel-cli exiting 0 is a reading of both fields.
const SPAN_SCRIPT: &str = r#"import json, sys
e = json.load(sys.stdin)['event']
if e.get('service_name') == 'checkout' and e.get('span_names') == ['charge card'] and e.get('span_count') == 1 and e.get('encoding') == 'protobuf':
    a = [{'type': 'accept_otlp'}]
else:
    a = [{'type': 'reject_otlp', 'code': 403, 'message': 'not the expected span'}]
print(json.dumps({'actions': a}))
"#;

#[tokio::test]
async fn otel_cli_sends_a_span_the_handler_reads_by_name_and_service() {
    let state = common::new_state().await;
    let handler = serde_json::json!({
        "event_pattern": "otlp_export",
        "handler": {"type": "script", "language": "python", "code": SPAN_SCRIPT}
    });
    let (_id, port, mut rx) = common::start(&state, vec![handler]).await;

    let (code, out) = run("otel-cli", &otel_cli_span(port, "checkout", "charge card")).await;
    assert_eq!(code, 0, "a full success: {out}");
    common::wait_for_log(&mut rx, "decision=model_answer items=1", 30).await;

    // The same exporter, refused: otel-cli --fail reports it and exits non-zero.
    let (code, out) = run("otel-cli", &otel_cli_span(port, "inventory", "charge card")).await;
    assert_ne!(code, 0, "a 403 is not a success: {out}");
    assert!(out.contains("403"), "otel-cli named the status: {out}");
    common::wait_for_log(&mut rx, "decision=model_reject status=403", 30).await;
}

type Seen = Arc<Mutex<Vec<serde_json::Value>>>;

fn recording_config(seen: Seen) -> NetGetConfig {
    NetGetConfig::new("listen on port {AVAILABLE_PORT} via otlp. A receiver.")
        .with_log_level("debug")
        .with_mock(move |mock| {
            mock.on_instruction_containing("via otlp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "otlp",
                    "instruction": "Accept metrics, refuse logs"
                }]))
                .expect_calls(1)
                .and()
                .on_event("otlp_export")
                .respond_with_actions_from_event(move |e| {
                    seen.lock().unwrap().push(e.clone());
                    match e["signal"].as_str() {
                        Some("logs") => serde_json::json!([{
                            "type": "reject_otlp", "code": 400, "message": "logs are not kept here"
                        }]),
                        _ => serde_json::json!([{"type": "accept_otlp"}]),
                    }
                })
                .expect_at_least(1)
                .and()
        })
}

fn total(seen: &[serde_json::Value], signal: &str, field: &str) -> u64 {
    seen.iter()
        .filter(|e| e["signal"] == signal)
        .map(|e| e[field].as_u64().unwrap_or(0))
        .sum()
}

/// The model path behind the Collector project's own generator: every metric data point and
/// log record telemetrygen sent reached the model in a summary, and the refusal of the logs is
/// what telemetrygen reports.
#[tokio::test]
async fn telemetrygen_metrics_and_logs_reach_the_model_as_summaries() -> E2EResult<()> {
    let _ = require_tool("telemetrygen");
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let server = start_netget_server(recording_config(seen.clone())).await?;

    let (code, out) = run(
        "telemetrygen",
        &telemetrygen(
            server.port,
            "metrics",
            &["--metrics", "3", "--service", "billing"],
        ),
    )
    .await;
    assert_eq!(code, 0, "{out}");
    let metrics = seen.lock().unwrap().clone();
    assert_eq!(
        total(&metrics, "metrics", "data_point_count"),
        3,
        "every data point reached the model once: {metrics:#?}"
    );
    assert!(metrics
        .iter()
        .filter(|e| e["signal"] == "metrics")
        .all(|e| e["service_name"] == "billing" && e["encoding"] == "protobuf"));

    let (_code, out) = run(
        "telemetrygen",
        &telemetrygen(
            server.port,
            "logs",
            &[
                "--logs",
                "2",
                "--body",
                "payment declined",
                "--service",
                "billing",
            ],
        ),
    )
    .await;
    let logs: Vec<serde_json::Value> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["signal"] == "logs")
        .cloned()
        .collect();
    assert!(!logs.is_empty(), "the logs reached the model");
    assert!(
        logs.iter().all(|e| e["log_bodies"]
            .as_array()
            .is_some_and(|b| b.iter().all(|x| x == "payment declined"))),
        "{logs:#?}"
    );
    assert!(
        out.contains("400") || out.contains("logs are not kept here"),
        "telemetrygen reported the refusal: {out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model path behind otel-cli: the model is shown the span's name and service.
#[tokio::test]
async fn otel_cli_span_reaches_the_model_by_name_and_service() -> E2EResult<()> {
    let _ = require_tool("otel-cli");
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via otlp. A receiver.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via otlp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "otlp",
                    "instruction": "Accept traces from checkout"
                }]))
                .expect_calls(1)
                .and()
                .on_event("otlp_export")
                .and_event_data_contains("service_name", "checkout")
                .and_event_data_contains("signal", "traces")
                .respond_with_actions_from_event(|e| {
                    if e["span_names"] == serde_json::json!(["refund order"]) {
                        serde_json::json!([{"type": "accept_otlp"}])
                    } else {
                        serde_json::json!([{"type": "reject_otlp", "code": 400,
                                            "message": "unexpected span"}])
                    }
                })
                .expect_calls(1)
                .and()
        });
    let server = start_netget_server(config).await?;
    let (code, out) = run(
        "otel-cli",
        &otel_cli_span(server.port, "checkout", "refund order"),
    )
    .await;
    assert_eq!(code, 0, "{out}");
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
