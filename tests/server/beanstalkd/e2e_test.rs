//! Beanstalkd end to end with a mocked model, over a raw socket.
//!
//! `real_client_test.rs` is the evidence that a real client accepts what this server writes.
//! This file pins the exact bytes, covers what greenstalk never sends — a malformed command, an
//! unknown one, upper case, a body without its CRLF, a pipelined burst — and asserts the one
//! property a client cannot see: the commands NetGet answers itself cost no model call. The
//! mock's `expect_calls` counts pin that.
//!
//! LLM budget: 6 calls (open_server, put, reserve, delete, stats, list-tubes).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::e2e --test-threads=100

use super::common::Peer;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

fn ok_block(yaml: &str) -> String {
    format!("OK {}\r\n{yaml}\r\n", yaml.len())
}

#[tokio::test]
async fn a_whole_beanstalkd_session_against_a_mocked_model() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via beanstalkd. A tiny work queue.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("via beanstalkd")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "beanstalkd",
                        "instruction": "A tiny work queue"
                    }]))
                    .expect_calls(1)
                    .and()
                    // The body contains a CRLF and a command line; the filter proves it reached
                    // the model whole, as body.
                    .on_event("beanstalkd_put")
                    .and_event_data_contains("body", "put 0 0 0 1")
                    .respond_with_actions_from_event(|e| {
                        // An id built from the event's fields, so the reply proves the model
                        // was shown them.
                        let id = e["priority"].as_u64().unwrap_or(0) * 100_000
                            + e["ttr"].as_u64().unwrap_or(0) * 1_000
                            + e["body_bytes"].as_u64().unwrap_or(0);
                        serde_json::json!([{"type": "insert_beanstalkd_job", "job_id": id}])
                    })
                    .expect_calls(1)
                    .and()
                    .on_event("beanstalkd_reserve")
                    // Matches only when the event says where the job's body comes from.
                    .and_event_data_contains("answer_with", "word for word")
                    .respond_with_actions(serde_json::json!([{
                        "type": "reserve_beanstalkd_job",
                        "job_id": 12,
                        "body": "résumé"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("beanstalkd_job_command")
                    .and_event_data_contains("command", "delete")
                    .respond_with_actions(serde_json::json!([
                        {"type": "send_beanstalkd_status", "status": "DELETED"}
                    ]))
                    .expect_calls(1)
                    .and()
                    // One rule for beanstalkd_stats that branches on scope: two rules on the
                    // same event cannot be told apart, and the first would answer both.
                    .on_event("beanstalkd_stats")
                    // Every scope's hint names its answer: send_beanstalkd_stats for stats,
                    // send_beanstalkd_tubes for list-tubes.
                    .and_event_data_contains("answer_with", "send_beanstalkd_")
                    .respond_with_actions_from_event(|e| match e["scope"].as_str() {
                        Some("tubes") => serde_json::json!([{
                            "type": "send_beanstalkd_tubes",
                            "tubes": ["default", "images"]
                        }]),
                        _ => serde_json::json!([{
                            "type": "send_beanstalkd_stats",
                            "stats": {"current-jobs-ready": 1, "total-jobs": 12}
                        }]),
                    })
                    .expect_calls(2)
                    .and()
            });

    let server = start_netget_server(config).await?;
    let mut peer = Peer::connect(server.port).await;

    // Connection state, answered by NetGet.
    peer.send("use images").await;
    assert_eq!(peer.line(10).await, "USING images\r\n");
    peer.send("watch images").await;
    assert_eq!(peer.line(10).await, "WATCHING 2\r\n");
    peer.send("watch images").await;
    assert_eq!(
        peer.line(10).await,
        "WATCHING 2\r\n",
        "watching a tube twice is one entry"
    );

    // put: 21 body bytes, among them a CRLF and something shaped like a command.
    peer.send_raw(b"put 5 0 30 21\r\nresize 7\r\nput 0 0 0 1\r\n")
        .await;
    assert_eq!(peer.line(30).await, "INSERTED 530021\r\n");

    // reserve: "résumé" is 8 bytes, not 6 characters.
    peer.send("reserve").await;
    assert_eq!(peer.line(30).await, "RESERVED 12 8\r\n");
    assert_eq!(peer.bytes(10, 10).await, "résumé\r\n".as_bytes());

    peer.send("delete 12").await;
    assert_eq!(peer.line(30).await, "DELETED\r\n");

    peer.send("stats").await;
    let expected = ok_block("---\ncurrent-jobs-ready: 1\ntotal-jobs: 12\n");
    let (line, payload) = peer.reply(30).await;
    assert_eq!(
        format!("{line}{}\r\n", String::from_utf8_lossy(&payload.unwrap())),
        expected
    );

    peer.send("list-tubes").await;
    let (line, payload) = peer.reply(30).await;
    assert_eq!(
        format!("{line}{}\r\n", String::from_utf8_lossy(&payload.unwrap())),
        ok_block("---\n- default\n- images\n")
    );

    // Everything below is NetGet's own answer; the mock would count a model call.
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING images\r\n");
    peer.send("list-tubes-watched").await;
    let (line, payload) = peer.reply(10).await;
    assert_eq!(
        format!("{line}{}\r\n", String::from_utf8_lossy(&payload.unwrap())),
        ok_block("---\n- default\n- images\n")
    );
    peer.send("ignore default").await;
    assert_eq!(peer.line(10).await, "WATCHING 1\r\n");
    peer.send("ignore images").await;
    assert_eq!(
        peer.line(10).await,
        "NOT_IGNORED\r\n",
        "the last watched tube cannot be ignored"
    );
    peer.send("PUT 1 0 60 3").await;
    assert_eq!(
        peer.line(10).await,
        "UNKNOWN_COMMAND\r\n",
        "commands are case-sensitive, as upstream's are"
    );
    peer.send("").await;
    assert_eq!(peer.line(10).await, "UNKNOWN_COMMAND\r\n");
    for bad in [
        "delete",
        "delete x",
        "delete -1",
        "use -bad",
        "use a b",
        "reserve now",
    ] {
        peer.send(bad).await;
        assert_eq!(peer.line(10).await, "BAD_FORMAT\r\n", "{bad:?}");
    }
    peer.send(&format!("use {}", "t".repeat(201))).await;
    assert_eq!(
        peer.line(10).await,
        "BAD_FORMAT\r\n",
        "tube names are at most 200 bytes"
    );

    // A body without its CRLF, then the connection is still in step.
    peer.send_raw(b"put 1 0 60 3\r\nabcXY").await;
    assert_eq!(peer.line(10).await, "EXPECTED_CRLF\r\n");
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING images\r\n");

    // Over max-job-size, with the body sent anyway: refused, skipped, still in step.
    let mut big = b"put 1 0 60 70000\r\n".to_vec();
    big.extend(std::iter::repeat_n(b'z', 70_000));
    big.extend_from_slice(b"\r\nlist-tube-used\r\n");
    peer.send_raw(&big).await;
    assert_eq!(peer.line(10).await, "JOB_TOO_BIG\r\n");
    assert_eq!(peer.line(10).await, "USING images\r\n");

    // Pipelined: three commands in one write, answered in order.
    peer.send_raw(b"list-tube-used\r\nwatch a\r\nquit\r\n")
        .await;
    assert_eq!(peer.line(10).await, "USING images\r\n");
    assert_eq!(peer.line(10).await, "WATCHING 2\r\n");
    assert_eq!(peer.line(10).await, "", "quit must close the connection");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
