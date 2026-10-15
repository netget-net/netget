//! The TLS client must keep talking after `wait_for_more`, and must not lose the
//! bytes it was asked to accumulate.
//!
//! Two defects this pins, both silent - the client stayed connected and simply
//! stopped answering:
//!
//! 1. **`wait_for_more` was terminal.** The read loop set the connection state to
//!    `Accumulating` and nothing ever moved it back, so every later read was appended
//!    to a queue that no code path read. One `wait_for_more` deafened the client for
//!    the rest of the session.
//! 2. **Data that arrived during a model call was cleared unread.** The branch that
//!    was supposed to process the queue did `queued_data.clear()`.
//!
//! The exchange below distinguishes both from a working client without any timing
//! assumption: the client answers `wait_for_more` *and* sends a nudge in the same
//! turn, so the server's next message is guaranteed to arrive while the client is
//! accumulating. A client with either defect never raises a third
//! `tls_client_data_received`, so the server never sees `DONE` and both mocks fail.
//!
//! The merged payload is asserted too - the third event must carry `PONG1PONG2`,
//! not `PONG2` - which is what proves the accumulated bytes survived rather than
//! being silently dropped.

mod tls_client_multi_turn {
    use crate::helpers::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wait_for_more_keeps_the_client_listening_and_keeps_the_bytes() -> E2EResult<()> {
        // Server: answers PING1 with PONG1, PING2 with PONG2, and logs DONE.
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via TLS. Answer each request with a pong.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("TLS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "TLS",
                        "instruction": "Answer PING1 with PONG1 and PING2 with PONG2"
                    }
                ]))
                .expect_calls(1)
                .and()
                // One rule, branching on the request: two rules on the same event id
                // would be first-match-wins and the second would never fire.
                .on_event("tls_data_received")
                .respond_with_actions_from_event(|event| {
                    let data = event.get("data").and_then(|d| d.as_str()).unwrap_or("");
                    match data {
                        "PING1" => serde_json::json!([
                            {"type": "send_tls_data", "data": "PONG1"}
                        ]),
                        "PING2" => serde_json::json!([
                            {"type": "send_tls_data", "data": "PONG2"}
                        ]),
                        // "DONE" - the run is over; say nothing back.
                        _ => serde_json::json!([{"type": "wait_for_more"}]),
                    }
                })
                // PING1, PING2, DONE. The third is only reached if the client
                // answered after its own wait_for_more.
                .expect_calls(3)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        server
            .wait_for_pattern(
                "TLS server (action-based) listening on",
                Duration::from_secs(5),
            )
            .await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TLS (accept invalid certificates) and run the ping exchange.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("TLS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TLS",
                        "instruction": "Run the ping exchange",
                        "startup_params": {"accept_invalid_certs": true}
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("tls_client_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_tls_data", "data": "PING1"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("tls_client_data_received")
                .respond_with_actions_from_event(|event| {
                    let data = event.get("data").and_then(|d| d.as_str()).unwrap_or("");
                    if data == "PONG1" {
                        // "I need more" AND a nudge that makes more arrive. The nudge is
                        // what turns a deaf client into a failing test rather than a
                        // hanging one.
                        serde_json::json!([
                            {"type": "send_tls_data", "data": "PING2"},
                            {"type": "wait_for_more"}
                        ])
                    } else if data == "PONG1PONG2" {
                        // The accumulated bytes were carried into this turn.
                        serde_json::json!([{"type": "send_tls_data", "data": "DONE"}])
                    } else {
                        // Anything else means the merge lost or reordered data. Send a
                        // marker the server does not expect so the failure is visible in
                        // the server's call history rather than as a bare timeout.
                        serde_json::json!([
                            {"type": "send_tls_data", "data": format!("UNEXPECTED:{data}")}
                        ])
                    }
                })
                .expect_calls(2)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // The server logs every decrypted payload it receives; DONE is the last one and
        // only exists if the client took a second turn after its wait_for_more.
        server
            .wait_for_pattern("DONE", Duration::from_secs(20))
            .await?;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}
