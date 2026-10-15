//! The Prometheus exporter with a mocked model: one scrape answered, one refused on purpose,
//! one answered with an invalid family, and the paths that must never reach the model.
//!
//! The three scrapes are told apart by `User-Agent`, which the event carries — one rule branches
//! on it rather than three rules racing on the same event (see the root `CLAUDE.md`, "Rules are
//! first-match-wins").
//!
//! LLM calls: 4 — the startup instruction and three scrapes. `GET /`, `HEAD /metrics`,
//! `POST /metrics` and an unknown path are served without the model, and `expect_calls` on the
//! scrape rule is what proves it.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_prometheus_scrapes_answered_refused_and_invalid() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Open a Prometheus exporter on port {AVAILABLE_PORT} for a queue worker")
            .with_mock(|mock| {
                mock.on_instruction_containing("Prometheus exporter")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "prometheus",
                "instruction": "Exporter for a queue worker: jobs processed and queue depth."
            }]))
            .expect_calls(1)
            .and()
            .on_event("prometheus_scrape")
            .respond_with_actions_from_event(|event| {
                match event["user_agent"].as_str().unwrap_or("") {
                    "netget-test/refuse" => json!([{
                        "type": "send_scrape_error",
                        "status": 503,
                        "message": "worker is draining"
                    }]),
                    "netget-test/invalid" => json!([{
                        "type": "send_metrics",
                        "metrics": [{"name": "queue-depth", "type": "gauge",
                                     "samples": [{"value": 1}]}]
                    }]),
                    _ => json!([{
                        "type": "send_metrics",
                        "metrics": [
                            // Named without _total and with no +Inf bucket: NetGet completes both.
                            {"name": "jobs_processed", "type": "counter",
                             "help": "Jobs processed.",
                             "samples": [{"labels": {"queue": "default"}, "value": 42}]},
                            {"name": "queue_depth", "type": "gauge", "help": "Jobs waiting.",
                             "samples": [{"value": 7}]},
                            {"name": "job_seconds", "type": "histogram", "help": "Job time.",
                             "samples": [
                                 {"suffix": "_bucket", "labels": {"le": "1"}, "value": 30},
                                 {"suffix": "_sum", "value": 25.5},
                                 {"suffix": "_count", "value": 42}
                             ]}
                        ]
                    }]),
                }
            })
            .expect_calls(3)
            .and()
            });

    let server = helpers::start_netget_server(config).await?;
    let base = format!("http://127.0.0.1:{}", server.port);
    let http = client();

    // Served without the model.
    let index = http.get(format!("{base}/")).send().await?;
    assert_eq!(index.status(), 200);
    assert!(index.text().await?.contains("href=\"/metrics\""));
    let head = http.head(format!("{base}/metrics")).send().await?;
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let post = http
        .post(format!("{base}/metrics"))
        .body("x")
        .send()
        .await?;
    assert_eq!(post.status(), 405);
    assert_eq!(post.headers()["allow"], "GET, HEAD");
    let missing = http.get(format!("{base}/nothing-here")).send().await?;
    assert_eq!(missing.status(), 404);

    // A scrape the model answers.
    let ok = http
        .get(format!("{base}/metrics"))
        .header("User-Agent", "netget-test/ok")
        .send()
        .await?;
    assert_eq!(ok.status(), 200);
    let body = ok.text().await?;
    println!("--- model-answered scrape ---\n{body}");
    assert!(
        body.contains("# TYPE jobs_processed_total counter\n"),
        "{body}"
    );
    assert!(
        body.contains("jobs_processed_total{queue=\"default\"} 42\n"),
        "{body}"
    );
    assert!(
        body.contains("job_seconds_bucket{le=\"+Inf\"} 42\n"),
        "{body}"
    );

    // The same body through promtool: the mocked model's answer is lint-clean too. The binary
    // is required by real_client_test.rs as well, and absent means failure, not a skip.
    let promtool = [
        "/opt/homebrew/bin/promtool",
        "/usr/local/bin/promtool",
        "/usr/bin/promtool",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(str::to_string)
    .unwrap_or_else(|| "promtool".to_string());
    let mut child = tokio::process::Command::new(&promtool)
        .args(["check", "metrics"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            format!("promtool is required (brew install prometheus, or the release tarball): {e}")
        })?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .await?;
    let out = child.wait_with_output().await?;
    assert!(
        out.status.success() && out.stdout.is_empty() && out.stderr.is_empty(),
        "promtool did not accept the mocked model's exposition cleanly: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // A refusal the model chose: its status, its text, and a model_reject tag.
    let refused = http
        .get(format!("{base}/metrics"))
        .header("User-Agent", "netget-test/refuse")
        .send()
        .await?;
    assert_eq!(refused.status(), 503);
    assert_eq!(refused.text().await?.trim(), "worker is draining");

    // An answer the executor refuses: never a partial body, always a 500.
    let invalid = http
        .get(format!("{base}/metrics"))
        .header("User-Agent", "netget-test/invalid")
        .send()
        .await?;
    assert_eq!(invalid.status(), 500);
    let text = invalid.text().await?;
    assert!(!text.contains("queue-depth"), "{text}");

    server
        .wait_for_any(&["decision=fail_closed_invalid_exposition"], 30)
        .await;
    let lines = server.get_output().await;
    for tag in [
        "decision=model_answer",
        "decision=model_reject",
        "decision=fail_closed_invalid_exposition",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(tag)),
            "expected {tag} in the log. Output:\n{}",
            lines.join("\n")
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// OpenMetrics is served when the scraper prefers it, and the event says which format was
/// negotiated.
#[tokio::test]
async fn test_prometheus_negotiates_openmetrics() -> E2EResult<()> {
    let config = NetGetConfig::new("Open a Prometheus exporter on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("Prometheus exporter")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "prometheus",
                    "instruction": "Exporter"
                }]))
                .expect_calls(1)
                .and()
                .on_event("prometheus_scrape")
                .and_event_data_contains("format", "openmetrics")
                .respond_with_actions(json!([{
                    "type": "send_metrics",
                    "metrics": [{"name": "jobs", "type": "counter", "help": "Jobs.",
                                 "samples": [{"value": 5, "timestamp_ms": 1700000000500_i64}]}]
                }]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;

    let response = client()
        .get(format!("http://127.0.0.1:{}/metrics", server.port))
        .header(
            "Accept",
            "application/openmetrics-text;version=1.0.0;q=0.5,text/plain;version=0.0.4;q=0.2",
        )
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
    );
    let body = response.text().await?;
    assert_eq!(
        body,
        "# HELP jobs Jobs.\n# TYPE jobs counter\njobs_total 5 1700000000.500\n# EOF\n"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
