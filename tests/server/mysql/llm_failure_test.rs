//! What a MySQL client gets when the LLM backend fails: an ERR packet with a SQLSTATE.
//!
//! MySQL's ERR packet carries an error number *and* the SQLSTATE that goes with it, which is
//! what lets a driver classify a failure instead of guessing from the message text. The
//! assertion below is on both, read back through `mysql_async` - an independent client
//! implementation of the wire protocol, so decoding it is evidence rather than a tautology.
//!
//! The alternative this replaced was an empty OK packet, which the client cannot distinguish
//! from a statement that succeeded and affected no rows.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// ER_UNKNOWN_ERROR. Its SQLSTATE is HY000 ("general error").
const ER_UNKNOWN_ERROR: u16 = 1105;

#[tokio::test]
async fn test_mysql_answers_error_packet_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open MySQL on port {AVAILABLE_PORT}. Answer queries about a users table.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Answer queries about a users table"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `mysql_query`: the mock answers 500 for every statement, including the
        // `SELECT @@...` the client sends while setting the connection up.
    });

    let server = start_netget_server(server_config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let url = format!("mysql://root@127.0.0.1:{}/test", server.port);
    let pool = mysql_async::Pool::new(url.as_str());

    // The first statement to reach the handler fails. Whether that is the driver's own setup
    // query or our SELECT does not matter: what matters is that the failure arrives as an ERR
    // packet and not as silence or as a success.
    let outcome = tokio::time::timeout(Duration::from_secs(25), async {
        use mysql_async::prelude::Queryable;
        let mut conn = pool.get_conn().await?;
        let rows: Vec<(i64,)> = conn.query("SELECT id FROM users").await?;
        Ok::<_, mysql_async::Error>(rows)
    })
    .await
    .map_err(|_| {
        "MySQL neither answered nor failed within 25s - the server went silent on LLM failure, \
         which is the exact defect this test exists to catch"
    })?;

    let error = match outcome {
        Ok(rows) => panic!(
            "MySQL reported success ({} rows) despite the backend being unavailable",
            rows.len()
        ),
        Err(e) => e,
    };
    println!("MySQL error: {error:?}");

    match error {
        mysql_async::Error::Server(server_error) => {
            assert_eq!(
                server_error.code, ER_UNKNOWN_ERROR,
                "expected error 1105 (ER_UNKNOWN_ERROR): {server_error:?}"
            );
            assert_eq!(
                server_error.state, "HY000",
                "the ERR packet must carry the SQLSTATE for 1105: {server_error:?}"
            );
            assert!(
                server_error.message.contains("netget"),
                "the message should name the source of the failure: {server_error:?}"
            );
        }
        other => panic!(
            "expected a MySQL server ERR packet, got {other:?}. Anything else means the failure \
             never reached the client as a protocol-level error."
        ),
    }

    let _ = pool.disconnect().await;
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
