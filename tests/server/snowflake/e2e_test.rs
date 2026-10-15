//! End-to-end Snowflake tests.
//!
//! Snowflake's real drivers are hard to point at localhost, so these tests drive
//! the exact REST/JSON endpoints a driver uses (`/session/v1/login-request`,
//! `/queries/v1/query-request`) with `reqwest` and assert the login/query/error
//! envelopes match the shapes a genuine Snowflake connector expects:
//!
//! - login success → `{"data": {"token", "masterToken", "sessionId", ...},
//!   "success": true, "code": null, "message": null}` (the Python/Go/JDBC
//!   connectors read `data.token` and send it back as
//!   `Authorization: Snowflake Token="..."`).
//! - query success → `{"data": {"rowtype": [...], "rowset": [[...]], "total", ...},
//!   "success": true}`.
//! - failure → `{"data": null, "code": "...", "message": "...", "success": false}`.
//!
//! This is envelope-shape evidence driven by `reqwest`, NOT a real Snowflake
//! driver on a live connection.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build reqwest client")
}

#[tokio::test]
async fn test_snowflake_login_and_query() -> E2EResult<()> {
    println!("\n=== E2E Test: Snowflake login + query ===");

    let prompt = "Start a Snowflake server on port {AVAILABLE_PORT}. On login issue a session \
        token. Answer SELECT queries with a small rowset.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Snowflake server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "snowflake",
                    "instruction": "Snowflake warehouse: log clients in and answer queries"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "snowflake_login_success",
                    "token": "SESSION_TOKEN_ABC",
                    "master_token": "MASTER_TOKEN_ABC",
                    "session_id": 4242
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "snowflake_query_response",
                    "rowtype": [{"name": "N", "type": "fixed"}],
                    "rowset": [["1"]]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Snowflake server on port {}", server.port);

    let http = client();
    let base = format!("http://127.0.0.1:{}", server.port);

    // 1) Login
    let login: serde_json::Value = http
        .post(format!("{base}/session/v1/login-request"))
        .json(&serde_json::json!({
            "data": {
                "LOGIN_NAME": "SNOWMAN",
                "PASSWORD": "hunter2",
                "ACCOUNT_NAME": "XY12345",
                "CLIENT_APP_ID": "PythonConnector",
                "CLIENT_APP_VERSION": "3.0.0"
            }
        }))
        .send()
        .await?
        .json()
        .await?;

    println!("login response: {login}");
    assert_eq!(
        login["success"],
        serde_json::json!(true),
        "login must succeed"
    );
    let token = login["data"]["token"]
        .as_str()
        .expect("login response must carry data.token");
    assert_eq!(token, "SESSION_TOKEN_ABC");
    assert_eq!(
        login["data"]["masterToken"],
        serde_json::json!("MASTER_TOKEN_ABC")
    );
    assert_eq!(login["data"]["sessionId"], serde_json::json!(4242));

    // 2) Query, presenting the token the way a driver does.
    let query: serde_json::Value = http
        .post(format!("{base}/queries/v1/query-request?requestId=abc-123"))
        .header("Authorization", format!("Snowflake Token=\"{token}\""))
        .json(&serde_json::json!({ "sqlText": "SELECT 1", "asyncExec": false }))
        .send()
        .await?
        .json()
        .await?;

    println!("query response: {query}");
    assert_eq!(
        query["success"],
        serde_json::json!(true),
        "query must succeed"
    );
    assert_eq!(query["data"]["rowset"], serde_json::json!([["1"]]));
    assert_eq!(query["data"]["returned"], serde_json::json!(1));
    assert_eq!(query["data"]["rowtype"][0]["name"], serde_json::json!("N"));
    assert_eq!(
        query["data"]["queryResultFormat"],
        serde_json::json!("json")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    println!("✓ Snowflake login + query passed\n");
    Ok(())
}

#[tokio::test]
async fn test_snowflake_login_refused() -> E2EResult<()> {
    println!("\n=== E2E Test: Snowflake login refused (fail-closed shape) ===");

    let prompt =
        "Start a Snowflake server on port {AVAILABLE_PORT}. Refuse all logins as unauthorized.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Snowflake server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "snowflake",
                    "instruction": "Snowflake warehouse that refuses logins"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "snowflake_error",
                    "code": "390100",
                    "message": "Incorrect username or password was specified."
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let http = client();
    let base = format!("http://127.0.0.1:{}", server.port);

    let login: serde_json::Value = http
        .post(format!("{base}/session/v1/login-request"))
        .json(&serde_json::json!({
            "data": { "LOGIN_NAME": "SNOWMAN", "PASSWORD": "wrong", "ACCOUNT_NAME": "XY12345" }
        }))
        .send()
        .await?
        .json()
        .await?;

    println!("refused login response: {login}");
    // Fail-closed shape: success:false, no token, an error code — never a
    // success-shaped empty result.
    assert_eq!(
        login["success"],
        serde_json::json!(false),
        "login must be refused"
    );
    assert_eq!(login["code"], serde_json::json!("390100"));
    assert!(
        login["data"].is_null(),
        "refused login must not carry a token"
    );

    // The refusal on the wire is byte-identical to the one a backend outage produces
    // (`success:false`, code 390100, no token), because that is the only refusal RADIUS-style
    // this protocol has. So the log is the only place "the model said no" stays distinct from
    // "we could not ask" — assert the model's denial is tagged as the model's.
    server.wait_for_any(&["decision=model_reject"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Snowflake login") && l.contains("decision=model_reject")),
        "a deliberate model denial must be logged as decision=model_reject, not as a \
         fail-closed. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed_")),
        "nothing failed closed here: the model answered. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    println!("✓ Snowflake login refusal passed\n");
    Ok(())
}
