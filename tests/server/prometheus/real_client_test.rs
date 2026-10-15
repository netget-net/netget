//! The Prometheus exporter against the Prometheus project's own tools.
//!
//! Two independent readers of the exposition format, neither of which NetGet wrote or links:
//!
//! - **`promtool check metrics`** parses a body and lints it. Exit 0 with no output means the
//!   body parsed *and* broke none of the exposition guidelines (counter `_total`, help text,
//!   and so on). It is only evidence because the negative control shows it rejecting a body
//!   with one broken label — a checker that accepts everything would pass the positive half.
//! - **`prometheus`** itself, scraping NetGet on a one-second interval and answering its own
//!   query API: `up == 1` means the scrape succeeded end to end (HTTP, content type, parser),
//!   and a sample read back through PromQL — including a label value full of characters that
//!   need escaping — shows the numbers and labels survived the round trip exactly. It is run
//!   once per format, text 0.0.4 and OpenMetrics 1.0.0, pinned with `scrape_protocols`.
//!
//! The servers here are answered by a **static handler**, so no model is involved and the
//! bodies are deterministic; `e2e_test.rs` carries a mocked-model body through promtool as well.
//!
//! **These tests FAIL, they do not skip, when a binary is absent.** A skip-when-missing gate
//! returns `Ok(())` on a machine without the tools, which is a silent pass, and this protocol's
//! maturity rating would then rest on nothing. `tests/server/npm/e2e_test.rs` is the precedent.
//! Install with `brew install prometheus` (macOS; ships both binaries) or, on Debian/Ubuntu,
//! the upstream release tarball from https://github.com/prometheus/prometheus/releases (the
//! `prometheus` apt package's promtool is too old to lint OpenMetrics-era rules).


use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// A label value that exercises every escape the text format defines: backslash, double quote
/// and line feed.
const HOSTILE_LABEL: &str = "C:\\logs \"primary\"\nsecond line";

fn require_binary(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Some(found) = std::env::var("PATH").ok().and_then(|path| {
        path.split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|c| c.exists())
    }) {
        return found.to_string_lossy().into_owned();
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These tests drive the Prometheus project's own {name} against NetGet's exporter, and \
         that is the only independent check that the exposition NetGet renders is one a real \
         scraper accepts. Skipping would leave the Prometheus exporter's maturity rating resting \
         on nothing, so this is a failure and not a skip. Install with `brew install prometheus` \
         (macOS) or unpack the upstream release tarball onto PATH (Linux)."
    );
}

/// The families every test here serves: one of each type, labels that need escaping, a
/// histogram given out of order and without its `+Inf` bucket, a counter named without
/// `_total`, and a timestamped untyped sample.
fn fixture_metrics() -> Value {
    json!([
        {
            "name": "netget_requests",
            "type": "counter",
            "help": "Requests served, by path.\nSecond line of help with a \\ backslash.",
            "samples": [
                {"labels": {"path": "/"}, "value": 1027},
                {"labels": {"path": HOSTILE_LABEL}, "value": 3}
            ]
        },
        {
            "name": "netget_in_flight",
            "type": "gauge",
            "help": "Requests in flight.",
            "samples": [{"value": 4}]
        },
        {
            "name": "netget_latency_seconds",
            "type": "histogram",
            "help": "Request latency.",
            "samples": [
                {"suffix": "_bucket", "labels": {"le": "0.5"}, "value": 1010},
                {"suffix": "_bucket", "labels": {"le": 0.1}, "value": 900},
                {"suffix": "_sum", "value": 81.5},
                {"suffix": "_count", "value": 1030}
            ]
        },
        {
            "name": "netget_rpc_seconds",
            "type": "summary",
            "help": "RPC latency quantiles.",
            "samples": [
                {"labels": {"quantile": "0.99"}, "value": 0.25},
                {"labels": {"quantile": "0.5"}, "value": 0.05},
                {"suffix": "_sum", "value": 12.5},
                {"suffix": "_count", "value": 200}
            ]
        },
        {
            "name": "netget_build_info",
            "type": "untyped",
            "help": "Build information.",
            "samples": [{"labels": {"version": "1.2.3"}, "value": 1}]
        }
    ])
}

/// Start a Prometheus exporter in process whose only rule answers every scrape statically.
async fn start_static_exporter() -> (AppState, u16) {
    start_exporter(vec![json!({
        "event_pattern": "prometheus_scrape",
        "handler": {
            "type": "static",
            "actions": [{"type": "send_metrics", "metrics": fixture_metrics()}]
        }
    })])
    .await
}

/// Start a Prometheus exporter in process with the given routing table and a dead model.
async fn start_exporter(event_handlers: Vec<Value>) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "prometheus".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create prometheus server");
    for _ in 0..300 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                return (state, addr.port());
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("prometheus server never bound a port");
}

async fn scrape(port: u16, accept: &str) -> (u16, String, String) {
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{port}/metrics"))
        .header("Accept", accept)
        .send()
        .await
        .expect("scrape /metrics");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, content_type, response.text().await.unwrap())
}

/// Feed `body` to `promtool check metrics` and return (exit code, combined output).
async fn promtool_check(promtool: &str, body: &str) -> (i32, String) {
    let mut child = Command::new(promtool)
        .args(["check", "metrics"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn promtool");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(body.as_bytes()).await.unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("promtool did not finish within 30s")
        .expect("promtool output");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[tokio::test]
async fn promtool_accepts_what_a_scrape_returned_and_rejects_a_broken_exposition() -> TestResult {
    let promtool = require_binary("promtool");
    let (_state, port) = start_static_exporter().await;

    let (status, content_type, body) = scrape(port, "text/plain;version=0.0.4").await;
    println!("--- scrape (text 0.0.4) ---\n{content_type}\n{body}");
    assert_eq!(status, 200);
    assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");

    // What the renderer is responsible for, visible in the bytes.
    assert!(
        body.contains("# TYPE netget_requests_total counter\n"),
        "{body}"
    );
    assert!(
        body.contains(
            "netget_requests_total{path=\"C:\\\\logs \\\"primary\\\"\\nsecond line\"} 3\n"
        ),
        "the hostile label was not escaped as the text format requires:\n{body}"
    );
    assert!(
        body.contains("netget_latency_seconds_bucket{le=\"0.1\"} 900\nnetget_latency_seconds_bucket{le=\"0.5\"} 1010\nnetget_latency_seconds_bucket{le=\"+Inf\"} 1030\n"),
        "buckets were not sorted and completed with +Inf:\n{body}"
    );

    let (code, output) = promtool_check(&promtool, &body).await;
    println!("--- promtool check metrics: exit {code} ---\n{output}");
    assert_eq!(
        code, 0,
        "promtool rejected or linted the exposition NetGet served:\n{output}\n--- body ---\n{body}"
    );
    assert!(
        output.trim().is_empty(),
        "promtool printed lint findings for the served exposition:\n{output}"
    );

    // Negative control: the same body with one label value left unterminated. If promtool
    // accepted this too, the pass above would mean nothing.
    let broken = body.replacen("{path=\"/\"}", "{path=\"/}", 1);
    assert_ne!(broken, body, "the negative control did not change the body");
    let (code, output) = promtool_check(&promtool, &broken).await;
    println!("--- promtool on the broken control: exit {code} ---\n{output}");
    assert_ne!(
        code, 0,
        "promtool accepted a body with an unterminated label value, so its acceptance of \
         NetGet's body is not evidence of anything:\n{output}"
    );
    assert!(
        output.contains("parsing error"),
        "promtool rejected the control for an unexpected reason:\n{output}"
    );
    Ok(())
}

/// Pick a free loopback port for Prometheus' own web listener.
///
/// Bind-and-drop is racy in general; here a lost race makes Prometheus exit at startup, which
/// `run_prometheus` detects and retries on a fresh port rather than reporting a false failure.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct PrometheusRun {
    _child: tokio::process::Child,
    _dir: tempfile::TempDir,
    web_port: u16,
}

async fn run_prometheus(binary: &str, target_port: u16, scrape_protocol: &str) -> PrometheusRun {
    for _attempt in 0..3 {
        let dir = tempfile::TempDir::new().unwrap();
        let config = format!(
            "global:\n  scrape_interval: 1s\n  scrape_timeout: 1s\n\
             scrape_configs:\n  - job_name: netget\n    scrape_protocols: [{scrape_protocol}]\n\
             \x20   static_configs:\n      - targets: ['127.0.0.1:{target_port}']\n"
        );
        let config_path = dir.path().join("prometheus.yml");
        std::fs::write(&config_path, config).unwrap();
        let web_port = free_port();
        let mut child = Command::new(binary)
            .arg(format!("--config.file={}", config_path.display()))
            .arg(format!(
                "--storage.tsdb.path={}",
                dir.path().join("data").display()
            ))
            .arg(format!("--web.listen-address=127.0.0.1:{web_port}"))
            .arg("--log.level=warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn prometheus");
        // Ready when its own readiness endpoint says so; gone if it exited (port lost).
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for _ in 0..200 {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            if let Ok(r) = client
                .get(format!("http://127.0.0.1:{web_port}/-/ready"))
                .send()
                .await
            {
                if r.status().is_success() {
                    return PrometheusRun {
                        _child: child,
                        _dir: dir,
                        web_port,
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    panic!("prometheus did not become ready on any of three ports");
}

/// Run a PromQL instant query until it returns at least one series, returning the result.
async fn query_until(web_port: u16, promql: &str, secs: u64) -> Vec<Value> {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut last = Value::Null;
    while std::time::Instant::now() < deadline {
        if let Ok(r) = client
            .get(format!("http://127.0.0.1:{web_port}/api/v1/query"))
            .query(&[("query", promql)])
            .send()
            .await
        {
            if let Ok(v) = r.json::<Value>().await {
                if let Some(result) = v["data"]["result"].as_array() {
                    if !result.is_empty() {
                        return result.clone();
                    }
                }
                last = v;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("PromQL `{promql}` returned nothing within {secs}s; last answer: {last}");
}

#[tokio::test]
async fn a_real_prometheus_scrapes_netget_in_both_formats() -> TestResult {
    let prometheus = require_binary("prometheus");
    let (_state, port) = start_static_exporter().await;

    // Each mode with the exact Accept header Prometheus 3.15 sends in it (captured from a real
    // scrape against a bare listener), and the content type NetGet must answer that header
    // with. The direct scrape pins which format the run below is actually exercising — a
    // Prometheus pinned to OpenMetrics would still parse a text body it was sent, so `up == 1`
    // alone could not say which renderer it read.
    let modes = [
        (
            "PrometheusText0.0.4",
            "text/plain;version=0.0.4;q=0.7,*/*;q=0.6",
            "text/plain; version=0.0.4; charset=utf-8",
        ),
        (
            "OpenMetricsText1.0.0",
            "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.7,*/*;q=0.6",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        ),
    ];
    for (protocol, accept, content_type) in modes {
        let (status, served_as, _) = scrape(port, accept).await;
        assert_eq!(status, 200);
        assert_eq!(
            served_as, content_type,
            "[{protocol}] negotiated the wrong format"
        );

        let run = run_prometheus(&prometheus, port, protocol).await;

        // `up` is 1 only when the scrape, the content type and the parse all succeeded.
        let up = query_until(run.web_port, "up{job=\"netget\"} == 1", 30).await;
        println!("[{protocol}] up: {up:?}");

        // The hostile label value must come back exactly as the model gave it, which is only
        // possible if every escape was written the way this format's parser reads it.
        let series = query_until(run.web_port, "netget_requests_total", 30).await;
        println!("[{protocol}] netget_requests_total: {series:?}");
        let hostile = series
            .iter()
            .find(|s| s["metric"]["path"] == HOSTILE_LABEL)
            .unwrap_or_else(|| {
                panic!("[{protocol}] no series carried the escaped label back intact: {series:?}")
            });
        assert_eq!(hostile["value"][1], "3", "[{protocol}] {hostile}");
        assert!(
            series
                .iter()
                .any(|s| s["metric"]["path"] == "/" && s["value"][1] == "1027"),
            "[{protocol}] the / series lost its value: {series:?}"
        );

        // The +Inf bucket NetGet synthesised is what histogram_quantile needs to work at all.
        let inf = query_until(
            run.web_port,
            "netget_latency_seconds_bucket{le=\"+Inf\"}",
            30,
        )
        .await;
        assert_eq!(inf[0]["value"][1], "1030", "[{protocol}] {inf:?}");

        let quantile = query_until(run.web_port, "netget_rpc_seconds{quantile=\"0.99\"}", 30).await;
        assert_eq!(quantile[0]["value"][1], "0.25", "[{protocol}] {quantile:?}");
    }
    Ok(())
}

/// The protocol's own script-mode startup example is what a reader copies, so it has to produce
/// an exposition promtool accepts — run as shipped, through the real script executor.
#[tokio::test]
async fn the_documented_script_example_serves_a_lint_clean_exposition() -> TestResult {
    use netget::llm::actions::protocol_trait::Protocol;
    let promtool = require_binary("promtool");
    let example = netget::server::PrometheusProtocol::new()
        .get_startup_examples()
        .script_mode;
    let handlers = example["event_handlers"]
        .as_array()
        .expect("script_mode example has event_handlers")
        .clone();
    let (_state, port) = start_exporter(handlers).await;

    let (status, _, body) = scrape(port, "text/plain").await;
    println!("--- script-mode scrape ---\n{body}");
    assert_eq!(status, 200, "the script example did not answer: {body}");
    assert!(
        body.contains("app_scrapes_total{format=\"text\"} 1\n"),
        "{body}"
    );
    let (code, output) = promtool_check(&promtool, &body).await;
    assert_eq!(
        code, 0,
        "promtool rejected the script example's output:\n{output}"
    );
    assert!(
        output.trim().is_empty(),
        "promtool lint findings:\n{output}"
    );
    Ok(())
}
