//! NetGet's NVMe/TCP host against NetGet's own target for DH-HMAC-CHAP and the Compare,
//! Verify, Copy and reservation actions — a regression of the shapes, not evidence (the
//! independent target is nvmet, in `real_server_test.rs`). No LLM: python handlers play both
//! models, and the operator's injected actions (`send_to_client`) order the steps.
use super::server_support::{self as target, dhhc1, policy};
use super::support::*;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::{json, Value};
use std::time::Duration;

const SECURE: &str = "nqn.2026-10.net.netget:secure";
const OPEN: &str = "nqn.2026-10.net.netget:open";
const HOST_KEY: [u8; 48] = [0x31; 48];
const CTRL_KEY: [u8; 32] = [0x7A; 32];

const TARGET_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
ns=[{'nsid':1,'size':1048576,'writable':True,
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}],
     'errors':[{'offset':524288,'length':4096,'error':'medium_error'}]}]
if t=='nvme_tcp_connect':
  a=[{'type':'nvme_tcp_accept_connect','require_authentication':e['subsystem_nqn'].endswith(':secure'),'namespaces':ns}]
elif t=='nvme_tcp_reservation':
  a=[{'type':'nvme_tcp_allow_reservation'}]
else:
  a=[]
print(json.dumps({'actions':a}))"#;

const CONNECT_ONLY: &str = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;

async fn send(
    state: &netget::state::app_state::AppState,
    id: netget::state::ClientId,
    action: Value,
) -> Value {
    match state
        .send_to_client(id, action, Duration::from_secs(30))
        .await
        .unwrap()
    {
        ClientSendOutcome::Executed { detail } => serde_json::from_str(&detail).unwrap(),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_authenticates_both_ways_and_runs_the_new_commands() {
    let srv = target::start(
        policy(TARGET_POLICY),
        Some(json!({
            "dhchap_secret": dhhc1(&HOST_KEY, 2),
            "dhchap_ctrl_secret": dhhc1(&CTRL_KEY, 0),
            "dhchap_hashes": "sha512",
            "dhchap_dhgroups": "ffdhe3072",
        })),
    )
    .await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"subsystem_nqn": SECURE,
               "dhchap_secret": dhhc1(&HOST_KEY, 2),
               "dhchap_ctrl_secret": dhhc1(&CTRL_KEY, 0)}),
        chain(CONNECT_ONLY),
    )
    .await
    .unwrap();
    let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(c["connected"], true, "{c}");
    assert_eq!(
        c["authentication"],
        json!({"protocol": "DH-HMAC-CHAP", "hash": "sha512", "dh_group": "ffdhe3072", "bidirectional": true})
    );
    assert!(
        srv.logs()
            .iter()
            .any(|l| l.contains("authenticated both ways")),
        "{:#?}",
        srv.logs()
    );
    assert!(
        !c.to_string().contains("DHHC-1"),
        "no secret in what the model sees: {c}"
    );

    // Compare, Verify, Copy.
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_compare", "nsid": 1, "lba": 0, "data": "hello from netget"}),
    )
    .await;
    assert_eq!(
        (r["status"].as_str(), r["matches"].as_bool()),
        (Some("SUCCESS"), Some(true)),
        "{r}"
    );
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_compare", "nsid": 1, "lba": 0, "data": "hello from NetGet"}),
    )
    .await;
    assert_eq!(
        (r["status"].as_str(), r["matches"].as_bool()),
        (Some("COMPARE FAILURE"), Some(false)),
        "{r}"
    );
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_verify", "nsid": 1, "lba": 0, "blocks": 64}),
    )
    .await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_verify", "nsid": 1, "lba": 1020, "blocks": 8}),
    )
    .await;
    assert_eq!(r["status"], "UNRECOVERED READ ERROR", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 300,
        "ranges": [{"lba": 0, "blocks": 1}, {"lba": 8}]}),
    )
    .await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 300, "blocks": 2, "encoding": "hex"}),
    )
    .await;
    let hex = r["data"].as_str().unwrap();
    assert!(hex.starts_with(&hex::encode("hello from netget")), "{r}");
    assert!(
        hex[1024..].chars().all(|c| c == 'a' || c == 'b'),
        "the fill block follows"
    );
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 0,
        "ranges": [{"lba": 0, "blocks": 9000}]}),
    )
    .await;
    assert_eq!(r["status"], "COMMAND SIZE LIMIT EXCEEDED", "{r}");

    // Reservations.
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_register", "nsid": 1, "new_key": 161}),
    )
    .await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1,
        "reservation_type": "exclusive_access", "current_key": 161}),
    )
    .await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_report", "nsid": 1}),
    )
    .await;
    assert_eq!(r["reservation"]["type"], "exclusive_access", "{r}");
    assert_eq!(r["reservation"]["registrants"], 1);
    assert_eq!(r["reservation"]["entries"][0]["key"], 161);
    assert_eq!(r["reservation"]["entries"][0]["holds_reservation"], true);
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1,
        "reservation_type": "write_exclusive", "current_key": 161}),
    )
    .await;
    assert_eq!(r["status"], "RESERVATION CONFLICT", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_release", "nsid": 1,
        "action": "clear", "current_key": 161}),
    )
    .await;
    assert_eq!(r["status"], "SUCCESS", "{r}");
    let r = send(
        &state,
        id,
        json!({"type": "nvme_tcp_reservation_report", "nsid": 1}),
    )
    .await;
    assert_eq!(r["reservation"]["registrants"], 0, "{r}");
    assert_eq!(
        target::events(&srv.state, srv.id, "nvme_tcp_reservation")
            .await
            .len(),
        3,
        "register, acquire and clear reached the target's model"
    );
    // A malformed action is refused before the wire.
    let refused = state
        .send_to_client(
            id,
            json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1, "current_key": 1}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(refused, ClientSendOutcome::Rejected { .. }),
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_secret_or_a_controller_that_cannot_prove_itself_is_refused() {
    let srv = target::start(
        policy(TARGET_POLICY),
        Some(json!({
            "dhchap_secret": dhhc1(&HOST_KEY, 1),
            "dhchap_ctrl_secret": dhhc1(&CTRL_KEY, 0),
            "dhchap_dhgroups": "ffdhe2048",
        })),
    )
    .await;
    for (params, expect) in [
        (
            json!({"dhchap_secret": dhhc1(&[0x32; 48], 1)}),
            "refused this host's response",
        ),
        (
            json!({"dhchap_secret": dhhc1(&HOST_KEY, 1), "dhchap_ctrl_secret": dhhc1(&[0x7B; 32], 0)}),
            "controller authentication failed",
        ),
        (json!({}), "no dhchap_secret"),
    ] {
        let mut p = params.clone();
        p["subsystem_nqn"] = json!(SECURE);
        let (state, id) = client(format!("127.0.0.1:{}", srv.port), p, chain(CONNECT_ONLY))
            .await
            .unwrap();
        let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(c["connected"], false, "{c}");
        let status = c["status"].as_str().unwrap_or_default();
        assert!(
            status.starts_with("AUTHENTICATION FAILED") && status.contains(expect),
            "{params}: {c}"
        );
        assert!(!c.to_string().contains("DHHC-1"), "{c}");
    }
    assert!(
        srv.logs().iter().any(|l| l.contains("AUTH_Failure2")),
        "the target saw the host refuse it: {:#?}",
        srv.logs()
    );
    // An open subsystem asks nothing, so a host with secrets connects without using them.
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"subsystem_nqn": OPEN, "dhchap_secret": dhhc1(&HOST_KEY, 1)}),
        chain(CONNECT_ONLY),
    )
    .await
    .unwrap();
    let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(c["connected"], true, "{c}");
    assert!(c["authentication"].is_null(), "{c}");
    // Secrets that do not parse refuse to start the client.
    for p in [
        json!({"dhchap_secret": "DHHC-1:09:AAAA:"}),
        json!({"dhchap_ctrl_secret": dhhc1(&CTRL_KEY, 0)}),
    ] {
        let r = client(
            format!("127.0.0.1:{}", srv.port),
            p.clone(),
            chain(CONNECT_ONLY),
        )
        .await;
        let failed = match r {
            Err(_) => true,
            Ok((state, id)) => {
                let mut failed = false;
                for _ in 0..200 {
                    if let Some(c) = state.get_client(id).await {
                        if matches!(c.status, netget::state::ClientStatus::Error(_)) {
                            failed = true;
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                failed
            }
        };
        assert!(failed, "{p} is refused");
    }
}
