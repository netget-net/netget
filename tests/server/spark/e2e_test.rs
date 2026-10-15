//! End-to-end tests for the Apache Spark monitoring REST server.
//!
//! Drives the endpoints with `reqwest` (a real, independent HTTP client) and asserts the decoded
//! JSON matches the documented Spark monitoring REST shapes
//! (https://spark.apache.org/docs/latest/monitoring.html#rest-api) — crucially that success
//! responses are top-level JSON *arrays*. A real Spark client is not available on the CI/dev
//! hosts, so this is shape-conformance against the documented bodies, not real-client validation.


use crate::helpers::retry;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use reqwest::Client;
use serde_json::json;

/// `/api/v1/version` is static (no LLM); `/applications` is LLM-driven and returns a bare array.
#[tokio::test]
async fn test_spark_version_static_and_applications() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an Apache Spark REST API on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("Apache Spark REST API")
                .respond_with_actions(json!([{
                    "type": "open_server", "port": 0, "base_stack": "spark",
                    "instruction": "Spark driver monitoring API"
                }]))
                .expect_calls(1)
                .and()
                .on_event("spark_request")
                .and_event_data_contains("operation", "applications")
                .respond_with_actions(json!([{
                    "type": "send_spark_applications",
                    "applications": [{
                        "id": "app-20161116163331-0000", "name": "Spark shell",
                        "attempts": [{
                            "startTime": "2016-11-16T22:33:29.916GMT",
                            "completed": false, "sparkUser": "jose", "appSparkVersion": "3.5.1"
                        }]
                    }]
                }]))
                .expect_calls(1)
                .and()
                // After the list rule, so "applications" never reaches it.
                .on_event("spark_request")
                .and_event_data_contains("operation", "application")
                .respond_with_actions(json!([{
                    "type": "send_spark_applications",
                    "applications": [{
                        "id": "app-20161116163331-0000", "name": "Spark shell",
                        "attempts": [{"completed": false, "sparkUser": "jose"}]
                    }]
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    assert!(server.stack.to_uppercase().contains("SPARK"));
    let client = Client::new();

    // Static version banner — no LLM round-trip.
    let ver_url = format!("http://127.0.0.1:{}/api/v1/version", server.port);
    let ver = retry(|| async { client.get(&ver_url).send().await }).await?;
    assert!(ver.status().is_success());
    let vj: serde_json::Value = serde_json::from_str(&ver.text().await?)?;
    assert!(vj["spark"].is_string(), "version banner has a spark field");

    // LLM-driven applications — must be a top-level array.
    let apps_url = format!("http://127.0.0.1:{}/api/v1/applications", server.port);
    let apps = client.get(&apps_url).send().await?;
    assert!(apps.status().is_success());
    let a: serde_json::Value = serde_json::from_str(&apps.text().await?)?;
    assert!(
        a.is_array(),
        "Spark /applications must be a JSON array, got {a}"
    );
    assert_eq!(a[0]["id"], "app-20161116163331-0000");
    assert_eq!(a[0]["attempts"][0]["completed"], false);

    // One application is the API's one object: Spark answers `{...}`, not `[{...}]`.
    let one = client
        .get(format!("{apps_url}/app-20161116163331-0000"))
        .send()
        .await?;
    assert!(one.status().is_success());
    let o: serde_json::Value = serde_json::from_str(&one.text().await?)?;
    assert!(
        o.is_object(),
        "GET /applications/{{id}} must be an object, got {o}"
    );
    assert_eq!(o["id"], "app-20161116163331-0000");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `/applications/{id}/jobs`, `/stages`, `/executors` all return bare arrays.
#[tokio::test]
async fn test_spark_jobs_stages_executors() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an Apache Spark REST API on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("Apache Spark REST API")
                .respond_with_actions(json!([{
                    "type": "open_server", "port": 0, "base_stack": "spark",
                    "instruction": "Spark monitoring API"
                }]))
                .expect_calls(1)
                .and()
                .on_event("spark_request")
                .and_event_data_contains("operation", "jobs")
                .respond_with_actions(json!([{
                    "type": "send_spark_jobs",
                    "jobs": [{
                        "jobId": 0, "name": "count at <console>:15", "status": "SUCCEEDED",
                        "stageIds": [0], "numTasks": 8, "numCompletedTasks": 8
                    }]
                }]))
                .expect_calls(1)
                .and()
                .on_event("spark_request")
                .and_event_data_contains("operation", "stages")
                .respond_with_actions(json!([{
                    "type": "send_spark_stages",
                    "stages": [{
                        "status": "COMPLETE", "stageId": 0, "attemptId": 0, "numTasks": 8,
                        "name": "count at <console>:15"
                    }]
                }]))
                .expect_calls(1)
                .and()
                .on_event("spark_request")
                .and_event_data_contains("operation", "executors")
                .respond_with_actions(json!([{
                    "type": "send_spark_executors",
                    "executors": [{
                        "id": "driver", "hostPort": "10.0.0.1:57971", "isActive": true,
                        "totalCores": 8, "completedTasks": 16
                    }]
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let client = Client::new();
    let base = format!("http://127.0.0.1:{}/api/v1/applications/app-1", server.port);

    let jobs = retry(|| async { client.get(format!("{base}/jobs")).send().await }).await?;
    assert!(jobs.status().is_success());
    let j: serde_json::Value = serde_json::from_str(&jobs.text().await?)?;
    assert!(j.is_array());
    assert_eq!(j[0]["jobId"], 0);
    assert_eq!(j[0]["status"], "SUCCEEDED");

    let stages = client.get(format!("{base}/stages")).send().await?;
    let s: serde_json::Value = serde_json::from_str(&stages.text().await?)?;
    assert!(s.is_array());
    assert_eq!(s[0]["status"], "COMPLETE");

    let execs = client.get(format!("{base}/executors")).send().await?;
    let e: serde_json::Value = serde_json::from_str(&execs.text().await?)?;
    assert!(e.is_array());
    assert_eq!(e[0]["id"], "driver");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
