//! NetGet's NVMe/TCP host against NetGet's own target (a regression of the shapes, not
//! evidence: the independent target is in `real_server_test.rs`): a whole session driven by
//! the model's actions, digests, a refused connect, the handler-chain bound, an injected
//! action, keep-alive, a target that goes away, and a model that never answers. No LLM:
//! python handlers play both models.
use super::server_support::{self as target, policy, DISK0, POLICY};
use super::support::*;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn the_host_runs_the_models_session_against_netgets_target() {
    let srv = target::start(policy(POLICY), None).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"host_nqn": "nqn.2026-10.net.netget:test-host",
               "host_id": "0f9b2c64-3a51-4bb4-9d1e-3b8e0a51c2d7"}),
        chain(SESSION_POLICY),
    )
    .await
    .unwrap();
    let log = wait_event(&state, id, "nvme_tcp_discovery_log", 0).await;
    assert_eq!(log["entries"][0]["subsystem_nqn"], DISK0, "{log}");
    assert_eq!(log["entries"][0]["transport"], "tcp");
    assert_eq!(log["entries"][0]["address"], "127.0.0.1");
    assert_eq!(log["entries"][0]["port"], srv.port.to_string());
    assert_eq!(log["entries"][1]["address"], "192.0.2.7");
    assert_eq!(log["controller"]["controller_type"], "discovery");
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], true, "{connected}");
    assert_eq!(connected["namespaces"], json!([1, 2]));
    assert_eq!(connected["controller"]["model"], "NETGET-BOOT");
    assert_eq!(connected["controller"]["serial"], "SER0001");
    assert_eq!(connected["controller"]["mdts_bytes"], 1048576);
    assert_eq!(connected["controller"]["in_capsule_data"], 8192);
    let r = results(&state, id, 6).await;
    assert_eq!(r[0]["namespace"]["blocks"], 2048, "{}", r[0]);
    assert_eq!(r[0]["namespace"]["block_size"], 512);
    assert_eq!(r[0]["namespace"]["write_protected"], false);
    assert_eq!(r[0]["namespace"]["descriptors"][0]["type"], "eui64");
    assert_eq!(r[1]["data"], "hello from netget", "{}", r[1]);
    assert_eq!(r[1]["encoding"], "utf8");
    assert_eq!(r[1]["trailing_zero_bytes"], 512 - 17);
    assert_eq!(r[2]["status"], "SUCCESS", "{}", r[2]);
    assert_eq!(r[3]["data"], WRITE_TEXT, "read back: {}", r[3]);
    assert_eq!(r[4]["log"]["host_write_commands"], "1", "{}", r[4]);
    assert_eq!(r[4]["log"]["temperature_celsius"], 40);
    assert_eq!(r[5]["operation"], "flush");
    assert_eq!(r[5]["status"], "SUCCESS");
    let out = wait_event(&state, id, "nvme_tcp_disconnected", 0).await;
    assert_eq!(out["reason"], "shut down by this host");
    // The target saw exactly the discovery and the connect the model asked for.
    let connects = target::events(&srv.state, srv.id, "nvme_tcp_connect").await;
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0]["host_nqn"], "nqn.2026-10.net.netget:test-host");
    assert_eq!(
        connects[0]["host_id"],
        "0f9b2c64-3a51-4bb4-9d1e-3b8e0a51c2d7"
    );
    assert_eq!(connects[0]["keep_alive_ms"], 30000);
    assert_eq!(
        target::events(&srv.state, srv.id, "nvme_tcp_discovery")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn statuses_hex_and_digests_reach_the_model() {
    let srv = target::start(policy(POLICY), None).await;
    // Each step is injected by the operator (send_to_client), so the order is the test's.
    let login_only = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"subsystem_nqn": DISK0, "digests": "crc32c"}),
        chain(login_only),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], true, "{connected}");
    assert_eq!(connected["controller"]["digests"], true);
    let send = |action: serde_json::Value| {
        let state = state.clone();
        async move {
            match state
                .send_to_client(id, action, Duration::from_secs(20))
                .await
                .unwrap()
            {
                ClientSendOutcome::Executed { detail } => {
                    serde_json::from_str::<serde_json::Value>(&detail).unwrap()
                }
                other => panic!("{other:?}"),
            }
        }
    };
    let r = send(json!({"type": "nvme_tcp_read", "nsid": 2, "lba": 0, "encoding": "hex"})).await;
    assert_eq!(r["encoding"], "hex");
    let hex = r["data"].as_str().unwrap();
    assert!(hex.starts_with("deadbeef") && hex.len() == 8192, "{r}");
    let r = send(json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 1024})).await;
    assert_eq!(r["status"], "UNRECOVERED READ ERROR", "{r}");
    let r = send(
        json!({"type": "nvme_tcp_write", "nsid": 2, "lba": 0, "data": "00ff", "encoding": "hex"}),
    )
    .await;
    assert_eq!(r["status"], "NAMESPACE IS WRITE PROTECTED", "{r}");
    let r = send(json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 5000})).await;
    assert_eq!(r["status"], "LBA OUT OF RANGE", "{r}");
    let r = send(json!({"type": "nvme_tcp_identify_controller"})).await;
    assert_eq!(r["controller"]["controller_type"], "io", "{r}");
    assert_eq!(r["controller"]["namespaces"], 2);
    let r = send(json!({"type": "nvme_tcp_list_namespaces"})).await;
    assert_eq!(r["namespaces"], json!([1, 2]));
    // The largest write an action takes (8 KiB), and the read that brings it back.
    let r = send(json!({"type": "nvme_tcp_write", "nsid": 1, "lba": 40, "data": "aa".repeat(8192), "encoding": "hex"})).await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    assert_eq!(r["bytes"], 8192);
    let r = send(
        json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 40, "blocks": 16, "encoding": "hex"}),
    )
    .await;
    assert_eq!(r["data"], "aa".repeat(8192), "{r}");
    let r = send(json!({"type": "nvme_tcp_write_zeroes", "nsid": 1, "lba": 40, "blocks": 1})).await;
    assert_eq!(r["status"], "SUCCESS");
    let r = send(
        json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 40, "blocks": 2, "encoding": "hex"}),
    )
    .await;
    assert_eq!(
        r["data"],
        format!("{}{}", "00".repeat(512), "aa".repeat(512))
    );
    let r = send(json!({"type": "nvme_tcp_identify_namespace", "nsid": 7})).await;
    assert_eq!(r["namespace"]["active"], false, "{r}");
    let r = send(json!({"type": "nvme_tcp_get_log_page", "page": "firmware_slot"})).await;
    assert_eq!(r["log"]["slot1"], "1.0", "{r}");
    // A malformed action is refused before anything reaches the wire.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "nvme_tcp_write", "nsid": 1, "lba": 0, "data": "zz", "encoding": "hex"}),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_refused_connect_injected_actions_and_the_chain_bound() {
    let srv = target::start(policy(POLICY), None).await;
    // Every result asks for another Flush: the chain must stop.
    let forever = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
if t=='nvme_tcp_connected':
  a=[{'type':'nvme_tcp_connect','subsystem_nqn':'nqn.2026-10.net.netget:nothing'}]
elif t=='nvme_tcp_connect_result' and not i['event']['connected']:
  a=[{'type':'nvme_tcp_connect','subsystem_nqn':'nqn.2026-10.net.netget:disk0'}]
else:
  a=[{'type':'nvme_tcp_flush','nsid':1}]
print(json.dumps({'actions':a}))"#;
    let (state, id) = client(format!("127.0.0.1:{}", srv.port), json!({}), chain(forever))
        .await
        .unwrap();
    let refused = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(refused["connected"], false);
    assert_eq!(
        refused["status"], "CONNECT INVALID PARAMETERS (SUBNQN)",
        "{refused}"
    );
    wait_event(&state, id, "nvme_tcp_connect_result", 1).await;
    // Depth: connected 0 → connect 1 → connect 2 → flush 3..=MAX; the next one is not run.
    let bound = netget::client::nvme_tcp::MAX_FOLLOWUP_DEPTH;
    let r = results(&state, id, bound - 2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r2 = client_events(&state, id, "nvme_tcp_command_result").await;
    assert_eq!(
        r2.len(),
        r.len(),
        "the chain stopped at the follow-up bound"
    );
    assert_eq!(r.len(), bound - 2, "{}", r.len());

    // An operator's injected action runs on the controller.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 0}),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
    match outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(detail.contains("hello from netget"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn keep_alive_holds_an_idle_association_and_a_vanished_target_is_reported() {
    let srv = target::start(policy(POLICY), None).await;
    let login_only = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"subsystem_nqn": DISK0, "keep_alive_ms": 1000}),
        chain(login_only),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], true, "{connected}");
    // Idle past KATO plus the target's grace: Keep Alive keeps the controller.
    tokio::time::sleep(Duration::from_millis(4500)).await;
    assert!(client_events(&state, id, "nvme_tcp_disconnected")
        .await
        .is_empty());
    match state
        .send_to_client(
            id,
            json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 0}),
            Duration::from_secs(20),
        )
        .await
        .unwrap()
    {
        ClientSendOutcome::Executed { detail } => {
            assert!(detail.contains("hello from netget"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    // The target goes away: the host says so.
    srv.state.remove_server(srv.id).await;
    let out = wait_event(&state, id, "nvme_tcp_disconnected", 0).await;
    assert!(
        out["reason"].as_str().unwrap().contains("closed")
            || out["reason"].as_str().unwrap().contains("failed"),
        "{out}"
    );
}

#[tokio::test]
async fn a_model_that_cannot_answer_sends_nothing() {
    let srv = target::start(policy(POLICY), None).await;
    // No handlers: the connected event goes to the unreachable model, and nothing follows.
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"subsystem_nqn": DISK0}),
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(client_events(&state, id, "nvme_tcp_connect_result")
        .await
        .is_empty());
    assert!(target::events(&srv.state, srv.id, "nvme_tcp_connect")
        .await
        .is_empty());
}
