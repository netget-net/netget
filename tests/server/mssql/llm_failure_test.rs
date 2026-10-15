//! What a TDS client gets when the LLM backend fails: an ERROR token, read back by `tiberius`.
//!
//! MSSQL already sent one, so this is a regression guard on the shape plus the addition of a
//! transient error number. The reason it matters here more than in most protocols: an empty
//! result set is a meaningful SQL answer. A server that answered a bare DONE token on failure
//! would be telling the application the query ran and matched nothing.
//!
//! 49918 ("Cannot process request. Not enough resources") is on the transient-error list
//! SqlClient's own retry logic keys off, so capacity exhaustion is retried by the driver
//! rather than surfaced. 50000 is the generic number for everything else.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn test_mssql_answers_error_token_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open MSSQL on port {AVAILABLE_PORT}. Answer queries about a users table.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Answer queries about a users table"
                }
            ]))
            .and()
            // The login is a decision now; admit it so the test can reach the query path it
            // is actually about.
            .on_event("mssql_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_login_ack"
                }
            ]))
            .expect_at_least(1)
            .expect_calls(1)
            .and()
        // No rule for `mssql_query`: every statement fails.
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut config_tds = Config::new();
    config_tds.host("127.0.0.1");
    config_tds.port(server.port);
    config_tds.authentication(AuthMethod::sql_server("sa", "password"));
    config_tds.encryption(EncryptionLevel::NotSupported);
    config_tds.trust_cert();

    let tcp = TcpStream::connect(config_tds.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let outcome = tokio::time::timeout(Duration::from_secs(25), async {
        let mut client = Client::connect(config_tds, tcp.compat_write()).await?;
        let stream = client.query("SELECT id FROM users", &[]).await?;
        stream.into_results().await
    })
    .await
    .map_err(|_| {
        "MSSQL neither answered nor failed within 25s - the server went silent on LLM failure, \
         which is the exact defect this test exists to catch"
    })?;

    let error = match outcome {
        Ok(rows) => panic!(
            "MSSQL reported success ({} result set(s)) despite the backend being unavailable - \
             an empty result set is a meaningful SQL answer and must not be produced by a \
             failure",
            rows.len()
        ),
        Err(e) => e,
    };
    println!("MSSQL error: {error:?}");

    match error {
        tiberius::error::Error::Server(token) => {
            assert!(
                token.code() == 50000 || token.code() == 49918,
                "expected error 50000 (generic) or 49918 (not enough resources), got {}: {token:?}",
                token.code()
            );
            assert!(
                token.message().contains("netget"),
                "the message should name the source of the failure: {token:?}"
            );
        }
        other => panic!(
            "expected a TDS ERROR token, got {other:?}. Anything else means the failure never \
             reached the client as a protocol-level error."
        ),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model answering with *no* actions must not be reported to the client as success.
///
/// A bare DONE token means "the statement ran and matched nothing" — a meaningful, successful
/// SQL answer. Producing one for a query nobody answered is a fail-open: the application sees
/// an empty table rather than a failure. The server sends an ERROR token instead.
#[tokio::test]
async fn test_mssql_fails_closed_when_no_response_action_is_produced() -> E2EResult<()> {
    let prompt = "Open MSSQL on port {AVAILABLE_PORT}. Answer queries about a users table.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Answer queries about a users table"
                }
            ]))
            .and()
            // The login is a decision now; admit it so the test can reach the query path it
            // is actually about.
            .on_event("mssql_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_login_ack"
                }
            ]))
            .expect_at_least(1)
            .expect_calls(1)
            .and()
            // The call succeeds and the model answers with nothing usable.
            .on_event("mssql_query")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut config_tds = Config::new();
    config_tds.host("127.0.0.1");
    config_tds.port(server.port);
    config_tds.authentication(AuthMethod::sql_server("sa", "password"));
    config_tds.encryption(EncryptionLevel::NotSupported);
    config_tds.trust_cert();

    let tcp = TcpStream::connect(config_tds.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let outcome = tokio::time::timeout(Duration::from_secs(25), async {
        let mut client = Client::connect(config_tds, tcp.compat_write()).await?;
        let stream = client.query("SELECT id FROM users", &[]).await?;
        stream.into_results().await
    })
    .await
    .map_err(|_| {
        "MSSQL neither answered nor failed within 25s after an empty answer from the model"
    })?;

    match outcome {
        Ok(rows) => panic!(
            "MSSQL reported success ({} result set(s)) although no action answered the query - \
             an empty result set is a meaningful SQL answer and must not stand in for silence",
            rows.len()
        ),
        Err(tiberius::error::Error::Server(token)) => {
            assert_eq!(
                token.code(),
                50000,
                "an unanswered query is the generic user-defined error, not the transient one: \
                 {token:?}"
            );
            assert!(
                token.message().contains("netget"),
                "the message should name the source of the failure: {token:?}"
            );
            // The category, never a diagnosis: nothing internal may reach the client.
            for leaked in ["LLM", "ollama", "Ollama", "http://", "retries"] {
                assert!(
                    !token.message().contains(leaked),
                    "error message leaked {leaked:?}: {token:?}"
                );
            }
        }
        Err(other) => panic!(
            "expected a TDS ERROR token, got {other:?}. Anything else means the failure never \
             reached the client as a protocol-level error."
        ),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
