//! Gearman end to end with a mocked model, over a raw socket.
//!
//! `real_client_test.rs` is the evidence that libgearman accepts what this server writes. This
//! file pins the exact packets, covers what the `gearman` CLI never sends — `OPTION_REQ
//! exceptions`, `GET_STATUS` for a finished job, malformed arguments, unsupported types, the
//! admin commands this server refuses — and asserts that the ones NetGet answers itself cost no
//! model call (`expect_calls`). Both answer shapes are exercised: an action naming the job
//! handle (rendered by the executor) and one that does not (rendered by the loop).
//!
//! LLM budget: 3 calls (open_server, two jobs).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::e2e --test-threads=100

use super::common::{req, Peer};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::gearman::wire;

#[tokio::test]
async fn a_gearman_session_against_a_mocked_model() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gearman. A job server.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via gearman")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gearman",
                    "instruction": "A job server"
                }]))
                .expect_calls(1)
                .and()
                // One rule that branches on the function: two rules on the same event cannot
                // be told apart, and the first would answer both.
                .on_event("gearman_job_submitted")
                .respond_with_actions_from_event(|e| match e["function"].as_str() {
                    Some("count") => {
                        // Byte count and words, so the reply proves the workload reached the
                        // model whole: the NUL inside it is neither a separator nor whitespace.
                        let words = format!(
                            "{}:{}",
                            e["workload_bytes"].as_u64().unwrap_or(0),
                            e["workload"]
                                .as_str()
                                .unwrap_or("")
                                .split_whitespace()
                                .count()
                        );
                        serde_json::json!([
                            // Names its handle: the executor renders the whole packet.
                            {"type": "send_gearman_status", "numerator": 3, "denominator": 4,
                             "job_handle": e["job_handle"]},
                            {"type": "complete_gearman_job", "result": words.to_string()}
                        ])
                    }
                    _ => serde_json::json!([
                        {"type": "send_gearman_exception", "text": "cannot parse the image"}
                    ]),
                })
                .expect_calls(2)
                .and()
        });

    let server = start_netget_server(config).await?;
    let mut peer = Peer::connect(server.port).await;

    // A job at high priority with a unique id and a workload containing a NUL: the last
    // argument keeps its NULs.
    peer.send(&req(
        wire::SUBMIT_JOB_HIGH,
        &[b"count", b"job-7", b"one two\0three four"],
    ))
    .await;
    let (t, args, raw) = peer.packet(30).await;
    assert_eq!(t, wire::JOB_CREATED);
    let handle = args[0].clone();
    assert_eq!(handle, b"H:netget:1", "NetGet numbers its handles");
    assert_eq!(&raw[..4], b"\0RES");
    let (t, args, _) = peer.packet(30).await;
    assert_eq!(
        (t, args),
        (
            wire::WORK_STATUS,
            vec![handle.clone(), b"3".to_vec(), b"4".to_vec()]
        )
    );
    let (t, args, _) = peer.packet(30).await;
    assert_eq!(t, wire::WORK_COMPLETE);
    assert_eq!(
        args,
        vec![handle.clone(), b"18:3".to_vec()],
        "18 bytes, and the NUL-joined middle is one word"
    );

    // The job is finished: GET_STATUS says unknown.
    peer.send(&req(wire::GET_STATUS, &[&handle])).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!(t, wire::STATUS_RES);
    assert_eq!(
        args[1..],
        [b"0".to_vec(), b"0".to_vec(), b"0".to_vec(), b"0".to_vec()]
    );

    // With exceptions enabled, WORK_EXCEPTION reaches the client as such.
    peer.send(&req(wire::OPTION_REQ, &[b"exceptions"])).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!((t, args), (wire::OPTION_RES, vec![b"exceptions".to_vec()]));
    peer.send(&req(wire::SUBMIT_JOB, &[b"thumbnail", b"", b"img"]))
        .await;
    let (t, args, _) = peer.packet(30).await;
    assert_eq!(t, wire::JOB_CREATED);
    let handle = args[0].clone();
    assert_eq!(handle, b"H:netget:2");
    let (t, args, _) = peer.packet(30).await;
    assert_eq!(t, wire::WORK_EXCEPTION);
    assert_eq!(args, vec![handle, b"cannot parse the image".to_vec()]);

    // Everything below is NetGet's own answer; the mock would count a model call.
    peer.send(&req(wire::ECHO_REQ, &[b"ping\0with a nul"]))
        .await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!(
        (t, args),
        (wire::ECHO_RES, vec![b"ping\0with a nul".to_vec()])
    );

    peer.send(&req(wire::OPTION_REQ, &[b"turbo"])).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!((t, &args[0]), (wire::ERROR, &b"unknown_option".to_vec()));

    peer.send(&req(wire::SET_CLIENT_ID, &[b"e2e"])).await;
    // SET_CLIENT_ID has no reply; the next request's reply comes next.
    peer.send(&req(wire::SUBMIT_JOB, &[b"only-two-args"])).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!((t, &args[0]), (wire::ERROR, &b"invalid_arguments".to_vec()));

    peer.send(&req(35, &[b"f", b"", b"0", b"0", b"0", b"0", b"0", b"w"]))
        .await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!(
        (t, &args[0]),
        (wire::ERROR, &b"not_supported".to_vec()),
        "SUBMIT_JOB_SCHED is refused"
    );

    // Admin lines on the same connection.
    peer.send(b"status\r\n").await;
    assert_eq!(peer.line(10).await, ".\n", "no jobs in flight");
    peer.send(b"workers\n").await;
    assert_eq!(peer.line(10).await, ".\n");
    peer.send(b"version\n").await;
    assert!(peer.line(10).await.starts_with("OK netget-"));
    peer.send(b"maxqueue reverse 10\n").await;
    assert_eq!(
        peer.line(10).await,
        "ERR NOT_SUPPORTED This+server+does+not+change+its+state\n"
    );
    peer.send(b"shutdown graceful\n").await;
    assert!(peer.line(10).await.starts_with("ERR NOT_SUPPORTED "));
    peer.send(b"getpid\n").await;
    assert_eq!(
        peer.line(10).await,
        "ERR UNKNOWN_COMMAND Unknown+server+command\n"
    );

    // A worker packet: refused, and the connection closes.
    peer.send(&req(wire::CAN_DO, &[b"reverse"])).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!((t, &args[0]), (wire::ERROR, &b"not_supported".to_vec()));
    assert!(
        peer.rest(10).await.is_empty(),
        "the worker connection must close"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
