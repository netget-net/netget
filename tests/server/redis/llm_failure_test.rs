//! What a Redis client gets when the LLM backend fails: a RESP error, decoded by `redis-rs`.
//!
//! Redis already answered `-ERR` here, so this test is mostly a regression guard - but it also
//! covers a real defect that was fixed alongside it. The message used to be
//! `format!("ERR LLM error: {}", e)` with the error text interpolated raw, and a RESP simple
//! error is CRLF-terminated with no length prefix: a newline anywhere in the text ends the
//! frame early and everything after it is parsed as the *next* reply. Backend error strings
//! are routinely multi-line, so that would have desynchronised the connection permanently.
//!
//! The assertion below reads the reply back through `redis-rs`, an independent implementation
//! of RESP, which is what makes "the client saw an error and not a value" evidence rather than
//! a restatement of our own encoder.


use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_redis_answers_resp_error_when_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Listen on port {AVAILABLE_PORT} via Redis. Answer GET for any key.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Redis")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Redis",
                    "instruction": "Answer GET for any key"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `redis_command`, so every command fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = redis::Client::open(format!("redis://127.0.0.1:{}/", server.port))?;
    let mut conn = tokio::time::timeout(
        Duration::from_secs(20),
        client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| "Redis did not complete a connection within 20s")??;

    let outcome: Result<Option<String>, redis::RedisError> = tokio::time::timeout(
        Duration::from_secs(20),
        redis::cmd("GET").arg("somekey").query_async(&mut conn),
    )
    .await
    .map_err(|_| {
        "No Redis reply within 20s - the server went silent on LLM failure, which is the exact \
         defect this test exists to catch"
    })?;

    let error = match outcome {
        Ok(value) => panic!(
            "Redis returned a value ({value:?}) while the backend was unavailable - a failure \
             must never be reported as a cache answer, because `nil` is a meaningful result"
        ),
        Err(e) => e,
    };
    println!("Redis error: {error:?}");

    let detail = error.detail().unwrap_or_default().to_string();
    assert!(
        detail.contains("netget"),
        "the error should name the source of the failure: {error:?}"
    );
    assert!(
        !detail.contains('\n') && !detail.contains('\r'),
        "a RESP simple error is CRLF-terminated, so an embedded newline would forge a second \
         reply and desynchronise the connection: {detail:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
