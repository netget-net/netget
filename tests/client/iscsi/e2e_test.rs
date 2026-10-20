//! NetGet's iSCSI initiator against NetGet's own target (a regression of the shapes, not
//! evidence: the independent targets are in `real_server_test.rs`): a whole session driven by
//! the model's actions, CHAP and mutual CHAP, a refused login, the handler-chain bound, an
//! injected action, and a model that never answers. No LLM: python handlers play both models.
use super::server_support::{self as target, policy, DISK0, POLICY};
use super::support::*;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn the_initiator_runs_the_models_session_against_netgets_target() {
    let srv = target::start(policy(POLICY), None).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"initiator_name": "iqn.2026-10.net.netget:test-initiator"}),
        chain(SESSION_POLICY),
    )
    .await
    .unwrap();
    let targets = wait_event(&state, id, "iscsi_targets", 0).await;
    assert_eq!(targets["targets"][0]["name"], DISK0, "{targets}");
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(login["logged_in"], true, "{login}");
    assert_eq!(login["alias"], "netget disk");
    let r = results(&state, id, 6).await;
    assert_eq!(r[0]["luns"], json!([0, 1]), "{}", r[0]);
    assert_eq!(r[1]["inquiry"]["product"], "BOOT-DISK", "{}", r[1]);
    assert_eq!(
        r[2]["capacity"],
        json!({"blocks": 2048, "block_size": 512, "size_bytes": 1048576})
    );
    assert_eq!(r[3]["data"], "hello from netget", "{}", r[3]);
    assert_eq!(r[3]["encoding"], "utf8");
    assert_eq!(r[3]["trailing_zero_bytes"], 512 - 17);
    assert_eq!(r[4]["status"], "GOOD", "{}", r[4]);
    assert_eq!(
        r[5]["data"], WRITE_TEXT,
        "the target's session overlay read back: {}",
        r[5]
    );
    let out = wait_event(&state, id, "iscsi_logged_out", 0).await;
    assert_eq!(out["reason"], "logged out");
    // The target saw exactly the login the model asked for.
    let logins = target::events(&srv.state, srv.id, "iscsi_login").await;
    assert_eq!(logins.len(), 1);
    assert_eq!(
        logins[0]["initiator_name"],
        "iqn.2026-10.net.netget:test-initiator"
    );
}

const READ_HEX_AND_ERRORS: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='iscsi_connected':
  a=[{'type':'iscsi_login'}]
elif t=='iscsi_login_result' and e['logged_in']:
  a=[{'type':'iscsi_read','lun':1,'lba':0,'blocks':1,'encoding':'hex'}]
elif t=='iscsi_command_result' and e.get('lun')==1:
  a=[{'type':'iscsi_read','lun':0,'lba':1024,'blocks':1}]
elif t=='iscsi_command_result' and e.get('lba')==1024:
  a=[{'type':'iscsi_write','lun':0,'lba':5000,'data':'00ff','encoding':'hex'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn hex_reads_and_sense_reach_the_model() {
    let srv = target::start(policy(POLICY), None).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"target_name": DISK0, "digests": "crc32c"}),
        chain(READ_HEX_AND_ERRORS),
    )
    .await
    .unwrap();
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(login["negotiated"]["header_digest"], "CRC32C", "{login}");
    let r = results(&state, id, 3).await;
    assert_eq!(r[0]["encoding"], "hex");
    let hex = r[0]["data"].as_str().unwrap();
    assert!(
        hex.starts_with("deadbeef") && hex.len() == 8192,
        "4096 bytes as hex"
    );
    assert_eq!(r[1]["status"], "CHECK CONDITION");
    assert_eq!(
        r[1]["sense"], "MEDIUM ERROR: UNRECOVERED READ ERROR",
        "{}",
        r[1]
    );
    assert_eq!(
        r[2]["sense"], "ILLEGAL REQUEST: LOGICAL BLOCK ADDRESS OUT OF RANGE",
        "{}",
        r[2]
    );
}

#[tokio::test]
async fn chap_and_mutual_chap_with_secrets_the_model_never_sees() {
    let srv = target::start(
        policy(POLICY),
        Some(json!({
            "chap_accounts": [{"name": "alice", "secret": "wonderland12"}],
            "target_chap_name": "netget-target",
            "target_chap_secret": "targetsecret1",
        })),
    )
    .await;
    let login_only = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'iscsi_login'}] if i['event_type_id']=='iscsi_connected' else []}))"#;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"target_name": DISK0, "chap_name": "alice", "chap_secret": "wonderland12",
               "target_chap_name": "netget-target", "target_chap_secret": "targetsecret1"}),
        chain(login_only),
    )
    .await
    .unwrap();
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(login["logged_in"], true, "{login}");
    let all = format!("{:?}", state.list_access_logs_for(None, None).await);
    assert!(!all.contains("wonderland12") && !all.contains("targetsecret1"));

    // The target proving the wrong secret fails mutual CHAP on the initiator's side.
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"target_name": DISK0, "chap_name": "alice", "chap_secret": "wonderland12",
               "target_chap_name": "netget-target", "target_chap_secret": "not-the-target1"}),
        chain(login_only),
    )
    .await
    .unwrap();
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(login["logged_in"], false);
    assert!(
        login["error"].as_str().unwrap().contains("mutual CHAP"),
        "{login}"
    );

    // A wrong secret: the target refuses with authentication failure.
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"target_name": DISK0, "chap_name": "alice", "chap_secret": "the-wrong-one"}),
        chain(login_only),
    )
    .await
    .unwrap();
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(
        (login["logged_in"].clone(), login["status"].clone()),
        (json!(false), json!("0x0201")),
        "{login}"
    );
}

#[tokio::test]
async fn a_refused_login_injected_actions_and_the_chain_bound() {
    let srv = target::start(policy(POLICY), None).await;
    // Every result asks for another TEST UNIT READY: the chain must stop.
    let forever = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
if t=='iscsi_connected':
  a=[{'type':'iscsi_login','target_name':'iqn.2026-10.net.netget:nothing'}]
elif t=='iscsi_login_result' and not i['event']['logged_in']:
  a=[{'type':'iscsi_login','target_name':'iqn.2026-10.net.netget:disk0'}]
else:
  a=[{'type':'iscsi_test_unit_ready','lun':0}]
print(json.dumps({'actions':a}))"#;
    let (state, id) = client(format!("127.0.0.1:{}", srv.port), json!({}), chain(forever))
        .await
        .unwrap();
    let refused = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(refused["logged_in"], false);
    assert_eq!(refused["status"], "0x0203", "{refused}");
    assert_eq!(refused["status_meaning"], "target not found");
    wait_event(&state, id, "iscsi_login_result", 1).await;
    // Depth: connected 0 → login 1 → login 2 → TUR 3..=MAX; the next one is not run.
    let bound = netget::client::iscsi::MAX_FOLLOWUP_DEPTH;
    let r = results(&state, id, bound - 2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r2 = netget_count(&state, id).await;
    assert_eq!(r2, r.len(), "the chain stopped at the follow-up bound");
    assert_eq!(r.len(), bound - 2, "{}", r.len());

    // An operator's injected action runs on the session.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "iscsi_read", "lun": 0, "lba": 0}),
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

async fn netget_count(
    state: &netget::state::app_state::AppState,
    id: netget::state::ClientId,
) -> usize {
    client_events(state, id, "iscsi_command_result").await.len()
}

#[tokio::test]
async fn a_model_that_cannot_answer_sends_nothing() {
    let srv = target::start(policy(POLICY), None).await;
    // No handlers: the connected event goes to the unreachable model, and nothing follows.
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"target_name": DISK0}),
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(client_events(&state, id, "iscsi_login_result")
        .await
        .is_empty());
    assert!(target::events(&srv.state, srv.id, "iscsi_login")
        .await
        .is_empty());
}
