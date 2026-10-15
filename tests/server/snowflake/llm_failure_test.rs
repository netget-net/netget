//! What a Snowflake driver gets when the LLM backend fails: a refusal, never a session.
//!
//! This is the security-critical path in this protocol and the one the existing suite did not
//! cover. `test_snowflake_login_refused` proves the server relays a *model's* denial; it says
//! nothing about what happens when netget cannot reach a model at all. Those two must not be
//! the same thing, and the dangerous direction is obvious: a login endpoint that fell open on
//! an outage would issue a session token to anyone who asked while the backend was down —
//! the OAuth2 defect the root `CLAUDE.md` calls the most dangerous pattern in this codebase.
//!
//! So this pins three properties of the failure path:
//!
//! 1. the envelope is `success: false` with `data: null` — no token, no `masterToken`;
//! 2. it is distinguishable in the log from a model denial (`decision`-style wording differs:
//!    the message says the backend was unavailable rather than that credentials were wrong);
//! 3. the message on the wire is a `crate::utils::WireFailure` category and nothing else — no
//!    backend URL, no model name, no `anyhow` chain. A driver prints this string to a user.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_snowflake_refuses_login_when_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Start a Snowflake server on port {AVAILABLE_PORT} and log clients in.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Snowflake server")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server", "port": 0, "base_stack": "snowflake",
                "instruction": "Snowflake warehouse"
            }]))
            .expect_calls(1)
            .and()
        // Deliberately no rule for snowflake_login: the mock answers 500, so `call_llm`
        // returns Err and the server takes its backend-outage path.
    });

    let server = start_netget_server(config).await?;

    // A request timeout on the client, so a server that goes *silent* on LLM failure — the
    // other half of the defect this test guards — fails the test instead of hanging it.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()?;
    let url = format!("http://127.0.0.1:{}/session/v1/login-request", server.port);
    let body = serde_json::json!({
        "data": {
            "LOGIN_NAME": "SNOWMAN",
            "PASSWORD": "hunter2",
            "ACCOUNT_NAME": "XY12345",
            "CLIENT_APP_ID": "PythonConnector",
            "CLIENT_APP_VERSION": "3.0.0"
        }
    });

    // Wait for the socket, not for a duration: `start_netget_server` returns when startup is
    // parsed, not when the listener is bound. A 5xx envelope is a *successful* HTTP exchange
    // here, so only a transport failure retries.
    let response = crate::helpers::retry(|| async { http.post(&url).json(&body).send().await })
        .await
        .map_err(|e| {
            format!(
                "no Snowflake response: the server went silent on LLM failure, which is the \
                 exact defect this test exists to catch ({e})"
            )
        })?;

    let text = response.text().await?;
    println!("Snowflake login on LLM failure -> {text}");
    let envelope: Value = serde_json::from_str(&text)?;

    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "an LLM outage must refuse the login, never issue a session: {text}"
    );
    assert!(
        envelope["data"].is_null(),
        "a refused login must carry no token at all: {text}"
    );

    // The peer gets a category; the error itself belongs in netget.log. A driver shows this
    // message to a human, so a leak here reaches an end user's terminal.
    let message = envelope["message"].as_str().unwrap_or_default();
    for leak in [
        "http://",
        "ollama",
        "Ollama",
        "model",
        "retries",
        "Caused by",
    ] {
        assert!(
            !message.contains(leak),
            "the wire message leaked internals ({leak:?}): {message}"
        );
    }

    // The envelope a driver sees is identical to the one `test_snowflake_login_refused`
    // produces from a deliberate `snowflake_error`, so the wire cannot carry the difference.
    // The `decision=` tag is where it lives, and `grep decision=fail_closed` is the diagnostic
    // the root CLAUDE.md teaches — assert it is actually there.
    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Snowflake login") && l.contains("decision=fail_closed_")),
        "a backend outage on the login endpoint must be logged with a fail_closed decision \
         tag; without it it is indistinguishable from the model denying the login. Output \
         was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_reject")),
        "the model never answered, so nothing here may be recorded as its decision. Output \
         was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
