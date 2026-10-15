//! What a YARN client gets when the LLM backend fails: a RemoteException envelope with a 5xx.
//!
//! The failure that matters for a cluster control plane is answering `200 {"apps":null}` — a
//! valid "the cluster is idle" statement a client cannot distinguish from a backend that never
//! ran. This pins the LLM-failure path to a 5xx RemoteException instead, structurally distinct
//! from any real (empty) cluster response.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_yarn_answers_remote_exception_when_llm_fails() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("Open a YARN ResourceManager on port {AVAILABLE_PORT}")
            .with_mock(|mock| {
                mock.on_instruction_containing("YARN ResourceManager")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server", "port": 0, "base_stack": "yarn",
                        "instruction": "YARN RM"
                    }]))
                    .expect_calls(1)
                    .and()
                // No rule for the yarn_request event -> the mock 500s -> call_llm errors.
            });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        Duration::from_secs(25),
        client
            .get(format!(
                "http://127.0.0.1:{}/ws/v1/cluster/metrics",
                server.port
            ))
            .send(),
    )
    .await
    .map_err(|_| {
        "No YARN response within 25s - the server went silent on LLM failure, which is the exact \
         defect this test exists to catch"
    })??;

    let status = response.status().as_u16();
    let text = response.text().await?;
    println!("YARN -> {status} {text}");

    assert!(
        (500..600).contains(&status),
        "expected a 5xx rather than a success-shaped empty cluster: {status}"
    );
    let body: Value = serde_json::from_str(&text)?;
    assert!(
        body["clusterMetrics"].is_null(),
        "a failure must not carry a clusterMetrics object: {text}"
    );
    let exception = body["RemoteException"]["exception"]
        .as_str()
        .unwrap_or_default();
    assert!(
        exception == "ServiceUnavailableException" || exception == "WebApplicationException",
        "expected a server-side RemoteException, got {exception:?}"
    );
    assert!(
        body["RemoteException"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("netget"),
        "the message should name the source of the failure: {text}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
