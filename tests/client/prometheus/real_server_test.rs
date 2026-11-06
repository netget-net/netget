use super::common::*;
use crate::helpers::real_server::{InstallHint, RealServer};
use serde_json::json;
async fn daemon() -> crate::helpers::E2EResult<RealServer> {
    RealServer::builder(
        "prometheus",
        InstallHint {
            brew: "prometheus",
            apt: "prometheus",
        },
    )
    .config_file(
        "prometheus.yml",
        "global:\n  scrape_interval: 1s\nscrape_configs: []\n",
    )
    .args([
        "--config.file={dir}/prometheus.yml",
        "--storage.tsdb.path={dir}/data",
        "--web.listen-address=127.0.0.1:{port}",
        "--log.level=debug",
    ])
    .start()
    .await
}
fn assert_process_metrics(event: &serde_json::Value) {
    assert!(event["sample_count"].as_u64().unwrap() > 50);
    let metrics = event["metrics"].as_array().unwrap();
    let goroutines = metrics
        .iter()
        .find(|f| f["name"] == "go_goroutines")
        .expect("real Go runtime family");
    assert_eq!(goroutines["type"], "gauge");
    assert!(goroutines["samples"][0]["value"].as_f64().unwrap() > 0.0);
    let info = metrics
        .iter()
        .flat_map(|f| f["samples"].as_array().unwrap())
        .find(|s| s["name"] == "prometheus_build_info")
        .expect("real independent build info");
    assert_eq!(info["value"], 1.0);
    assert!(info["labels"]["version"].as_str().unwrap().contains('.'));
}
#[tokio::test]
async fn independent_prometheus_exports_text_and_auto_falls_back_without_openmetrics(
) -> crate::helpers::E2EResult<()> {
    let server = daemon().await?;
    let state = state();
    let id = connected_client(&state, server.addr()).await;
    for format in ["text", "auto"] {
        let result = request(&state, id, json!({"format":format})).await;
        assert_eq!(result["format"], "text");
        assert_process_metrics(&result);
        let cpu = result["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "process_cpu_seconds_total")
            .unwrap();
        assert_eq!(cpu["type"], "counter");
        assert_eq!(cpu["samples"][0]["name"], "process_cpu_seconds_total");
    }
    // Prometheus' own /metrics uses promhttp.Handler() with OpenMetrics disabled.
    // https://github.com/prometheus/prometheus/blob/v3.15.0/web/web.go
    let after = latest(&state, id).await;
    send(&state, id, json!({"format":"openmetrics"})).await;
    let (_, error) = event(&state, id, "prometheus_scrape_error", after).await;
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("unrequested metrics format"));
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn independent_official_python_exporter_negotiates_openmetrics_with_created_and_exemplars(
) -> crate::helpers::E2EResult<()> {
    // The process uses the official exposition server/renderer; NetGet supplies only values.
    let script = r#"import sys, threading
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Summary, Info, Enum, start_http_server
r=CollectorRegistry()
c=Counter('peer_requests_seconds','Requests',['path'],registry=r)
c.labels('C:\\logs "one"\nnext').inc(3,exemplar={'trace_id':'abc'})
Gauge('peer_gauge','Gauge',registry=r).set(float('nan'))
h=Histogram('peer_latency_seconds','Latency',buckets=[0.5,1.0],registry=r)
h.observe(0.75,exemplar={'trace_id':'bucket'})
s=Summary('peer_summary_seconds','Summary',registry=r);s.observe(2.5)
Info('peer_build','Version',registry=r).info({'version':'1.2.3'})
e=Enum('peer_state','State',states=['ready','waiting'],registry=r);e.state('ready')
server,_=start_http_server(0,addr='127.0.0.1',registry=r)
print('EXPORTER_PORT='+str(server.server_port),flush=True)
threading.Event().wait()
"#;
    let server = RealServer::builder(
        "python3",
        InstallHint {
            brew: "python3; pip install prometheus-client==0.22.1",
            apt: "python3; pip install prometheus-client==0.22.1",
        },
    )
    .config_file("exporter.py", script)
    .args(["-u", "{dir}/exporter.py"])
    .port_from_log("EXPORTER_PORT=([0-9]+)")
    .start()
    .await?;
    let state = state();
    let id = connected_client(&state, server.addr()).await;
    for format in ["text", "openmetrics", "auto"] {
        let result = request(&state, id, json!({"format":format})).await;
        assert_eq!(
            result["format"],
            if format == "text" {
                "text"
            } else {
                "openmetrics"
            }
        );
        let family = result["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| {
                f["name"]
                    == if format == "text" {
                        "peer_requests_seconds_total"
                    } else {
                        "peer_requests_seconds"
                    }
            })
            .unwrap();
        assert_eq!(family["type"], "counter");
        assert_eq!(family["samples"][0]["value"], 3.0);
        assert_eq!(
            family["samples"][0]["labels"]["path"],
            "C:\\logs \"one\"\nnext"
        );
        if format != "text" {
            assert_eq!(
                family["samples"][0]["exemplar"]["labels"]["trace_id"],
                "abc"
            );
            assert_eq!(family["samples"][1]["suffix"], "_created");
            assert!(result["metrics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["type"] == "info"));
            assert!(result["metrics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["type"] == "stateset"));
        }
    }
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn advertised_static_and_script_examples_scrape_the_independent_exporter(
) -> crate::helpers::E2EResult<()> {
    use netget::llm::actions::protocol_trait::Protocol;
    let examples =
        netget::client::prometheus::PrometheusClientProtocol::new().get_startup_examples();
    examples.validate("Prometheus")?;
    let server = daemon().await?;
    let state = state();
    for example in [examples.static_mode, examples.script_mode] {
        let id = client(
            &state,
            server.addr(),
            json!({}),
            serde_json::from_value(example["event_handlers"].clone())?,
        )
        .await;
        let (_, result) = event(&state, id, "prometheus_metrics", 0).await;
        assert_process_metrics(&result);
        assert_eq!(result["request"]["format"], "auto");
        state.remove_client(id).await;
    }
    Ok(())
}
#[tokio::test]
async fn mocked_model_chooses_scrape_and_shared_memory_reaches_metrics_followup(
) -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let server = daemon().await?;
    let config=MockLlmBuilder::new().on_event("prometheus_connected").respond_with_actions(json!([
        {"type":"set_memory","value":"model chose real exporter scrape"},{"type":"scrape_metrics","format":"text"}
    ])).expect_calls(1).and().on_event("prometheus_metrics").and_prompt_containing("model chose real exporter scrape")
        .respond_with_actions(json!([])).expect_calls(1).and().build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "prometheus".into(),
        remote_addr: Some(server.addr()),
        instruction: Some("Scrape once and retain shared memory".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    let (_, result) = event(&state, id, "prometheus_metrics", 0).await;
    assert_process_metrics(&result);
    mock.wait_for_expectations(30).await;
    // Condition 4 from Prometheus's side: its own handler counts the scrapes it has served, and
    // the client connects without one, so the single 200 it reports is the scrape the model
    // chose. The counter is incremented after a response is written, so this read is not in it.
    let own = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new("curl")
            .args(["-fsS", &format!("http://{}/metrics", server.addr())])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("curl deadline")?;
    assert!(
        own.status.success(),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
    let own = String::from_utf8(own.stdout)?;
    assert!(
        own.lines()
            .any(|l| l == "promhttp_metric_handler_requests_total{code=\"200\"} 1"),
        "Prometheus did not count exactly one scrape served: {}",
        own.lines()
            .filter(|l| l.starts_with("promhttp_metric_handler_requests_total"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        state.get_memory_for_client(id).await.as_deref(),
        Some("model chose real exporter scrape")
    );
    assert_eq!(mock.call_count().await, 2);
    mock.verify_calls().await?;
    state.remove_client(id).await;
    Ok(())
}
#[tokio::test]
async fn https_exporter_with_an_untrusted_certificate_is_refused() -> crate::helpers::E2EResult<()>
{
    let script = r#"import subprocess, threading
from prometheus_client import CollectorRegistry, Gauge, start_http_server
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout','key.pem','-out','cert.pem'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
r=CollectorRegistry();Gauge('peer_secure','Secure peer',registry=r).set(1)
server,_=start_http_server(0,addr='127.0.0.1',registry=r,certfile='cert.pem',keyfile='key.pem')
print('TLS_EXPORTER_PORT='+str(server.server_port),flush=True)
threading.Event().wait()
"#;
    let server = RealServer::builder(
        "python3",
        InstallHint {
            brew: "python3 openssl; pip install prometheus-client==0.22.1",
            apt: "python3 openssl; pip install prometheus-client==0.22.1",
        },
    )
    .config_file("exporter.py", script)
    .args(["-u", "{dir}/exporter.py"])
    .port_from_log("TLS_EXPORTER_PORT=([0-9]+)")
    .start()
    .await?;
    let state = state();
    let id = connected_client(&state, format!("https://{}", server.addr())).await;
    send(&state, id, json!({})).await;
    let (_, result) = event(&state, id, "prometheus_scrape_error", 0).await;
    let error = result["error"].as_str().unwrap().to_ascii_lowercase();
    assert!(
        error.contains("certificate") || error.contains("cert"),
        "{error}"
    );
    assert!(result.get("metrics").is_none());
    state.remove_client(id).await;
    Ok(())
}
