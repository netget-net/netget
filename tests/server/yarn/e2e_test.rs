//! End-to-end tests for the Hadoop YARN ResourceManager REST server.
//!
//! Drives the endpoints with `reqwest` (a real, independent HTTP client) and asserts the
//! decoded JSON matches the documented YARN RM envelopes
//! (https://hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html).
//! A real `yarn` CLI is not available on the CI/dev hosts, so this is shape-conformance against
//! the documented response bodies, not validation against a real Hadoop client.


use crate::helpers::retry;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use reqwest::Client;
use serde_json::json;

/// `GET /ws/v1/cluster/info` is answered statically (no LLM), and `/metrics` is LLM-driven.
#[tokio::test]
async fn test_yarn_cluster_info_static_and_metrics() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a Hadoop YARN ResourceManager on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("YARN ResourceManager")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "yarn",
                    "instruction": "YARN ResourceManager reporting a small cluster"
                }]))
                .expect_calls(1)
                .and()
                .on_event("yarn_request")
                .and_event_data_contains("operation", "metrics")
                .respond_with_actions(json!([{
                    "type": "send_yarn_metrics",
                    "metrics": {
                        "appsRunning": 1, "appsSubmitted": 4, "appsCompleted": 3,
                        "totalMB": 32768, "availableMB": 24576, "allocatedMB": 8192,
                        "totalNodes": 2, "activeNodes": 2, "containersAllocated": 4
                    }
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    assert!(server.stack.to_uppercase().contains("YARN"));
    let client = Client::new();

    // Static info banner — no LLM round-trip.
    let info_url = format!("http://127.0.0.1:{}/ws/v1/cluster/info", server.port);
    let info = retry(|| async { client.get(&info_url).send().await }).await?;
    assert!(info.status().is_success());
    let info_json: serde_json::Value = serde_json::from_str(&info.text().await?)?;
    assert_eq!(info_json["clusterInfo"]["state"], "STARTED");
    assert!(info_json["clusterInfo"]["resourceManagerVersion"].is_string());

    // LLM-driven metrics.
    let metrics_url = format!("http://127.0.0.1:{}/ws/v1/cluster/metrics", server.port);
    let metrics = client.get(&metrics_url).send().await?;
    assert!(metrics.status().is_success());
    let m: serde_json::Value = serde_json::from_str(&metrics.text().await?)?;
    assert_eq!(m["clusterMetrics"]["totalNodes"], 2);
    assert_eq!(m["clusterMetrics"]["appsRunning"], 1);
    // A field the model omitted must still be present (defaulted to 0) so clients parse it.
    assert_eq!(m["clusterMetrics"]["lostNodes"], 0);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `GET /ws/v1/cluster/apps` → `{"apps":{"app":[...]}}`; app-by-id → `{"app":{...}}`.
#[tokio::test]
async fn test_yarn_apps_list_and_by_id() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a Hadoop YARN ResourceManager on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("YARN ResourceManager")
                .respond_with_actions(json!([{
                    "type": "open_server", "port": 0, "base_stack": "yarn",
                    "instruction": "YARN RM"
                }]))
                .expect_calls(1)
                .and()
                .on_event("yarn_request")
                .and_event_data_contains("operation", "apps")
                .respond_with_actions(json!([{
                    "type": "send_yarn_apps",
                    "apps": [{
                        "id": "application_1476912658570_0002", "user": "dr.who",
                        "name": "word count", "queue": "default", "state": "RUNNING",
                        "finalStatus": "UNDEFINED", "progress": 62.5,
                        "applicationType": "MAPREDUCE"
                    }]
                }]))
                .expect_calls(1)
                .and()
                .on_event("yarn_request")
                .and_event_data_contains("operation", "app")
                .respond_with_actions(json!([{
                    "type": "send_yarn_app",
                    "app": {
                        "id": "application_1476912658570_0002", "state": "FINISHED",
                        "finalStatus": "SUCCEEDED", "progress": 100.0
                    }
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let client = Client::new();

    let apps_url = format!("http://127.0.0.1:{}/ws/v1/cluster/apps", server.port);
    let apps = retry(|| async { client.get(&apps_url).send().await }).await?;
    assert!(apps.status().is_success());
    let a: serde_json::Value = serde_json::from_str(&apps.text().await?)?;
    assert_eq!(a["apps"]["app"][0]["id"], "application_1476912658570_0002");
    assert_eq!(a["apps"]["app"][0]["state"], "RUNNING");

    let app_url = format!(
        "http://127.0.0.1:{}/ws/v1/cluster/apps/application_1476912658570_0002",
        server.port
    );
    let app = client.get(&app_url).send().await?;
    assert!(app.status().is_success());
    let single: serde_json::Value = serde_json::from_str(&app.text().await?)?;
    assert_eq!(single["app"]["finalStatus"], "SUCCEEDED");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `POST /ws/v1/cluster/apps` accepted → 202 Accepted with a `Location` header, empty body.
#[tokio::test]
async fn test_yarn_submit_application_accepted() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a Hadoop YARN ResourceManager on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("YARN ResourceManager")
                .respond_with_actions(json!([{
                    "type": "open_server", "port": 0, "base_stack": "yarn",
                    "instruction": "YARN RM"
                }]))
                .expect_calls(1)
                .and()
                .on_event("yarn_request")
                .and_event_data_contains("operation", "submit")
                .respond_with_actions(json!([{
                    "type": "send_yarn_submit_response",
                    "accepted": true,
                    "application_id": "application_1476912658570_0005"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let client = Client::new();

    let url = format!("http://127.0.0.1:{}/ws/v1/cluster/apps", server.port);
    let resp = retry(|| async {
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(r#"{"application-id":"application_1476912658570_0005","application-name":"job"}"#)
            .send()
            .await
    })
    .await?;

    assert_eq!(
        resp.status().as_u16(),
        202,
        "YARN submit acceptance is 202 Accepted"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.contains("application_1476912658570_0005"),
        "202 must carry a Location header pointing at the new app, got {location:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
