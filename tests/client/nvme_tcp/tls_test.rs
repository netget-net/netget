//! NetGet's NVMe/TCP host over a secure channel, against NetGet's own target (a regression of
//! the shapes, not evidence: the Linux target through tlshd and SPDK's nvmf_tgt are the
//! independent targets, in the `nvme-tcp` pair job). Every queue — the discovery controller's
//! and the session's admin and I/O queues — opens its own TLS session, under an identity naming
//! the subsystem it then connects to.
#![cfg(unix)]

use super::server_support::{self as target, policy, DISK0, POLICY};
use super::support::*;
use netget::server::nvme_tcp::auth::Hash;
use netget::server::nvme_tcp::tls_psk::ConfiguredKey;
use serde_json::json;
use std::time::Duration;

const KEY: &str = "NVMeTLSkey-1:01:3rMPGkRFakyIYjFLJ7LZQNiFQ3Lyua16Zm97sG5VS8yDf7yj:";
const HOST_NQN: &str = "nqn.2026-10.net.netget:tls-host";

async fn logged(srv: &target::Started, needle: &str) -> bool {
    for _ in 0..200 {
        if srv.logs().iter().any(|l| l.contains(needle)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn the_host_runs_the_models_session_inside_secure_channels() {
    let srv = target::start(policy(POLICY), Some(json!({"tls_key": KEY}))).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"host_nqn": HOST_NQN, "tls_key": KEY}),
        chain(SESSION_POLICY),
    )
    .await
    .unwrap();
    let log = wait_event(&state, id, "nvme_tcp_discovery_log", 0).await;
    assert_eq!(log["entries"][0]["subsystem_nqn"], DISK0, "{log}");
    assert_eq!(log["entries"][0]["secure_channel"], "required");
    assert_eq!(log["entries"][0]["security"], "tls1.3");
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], true, "{connected}");
    let r = results(&state, id, 6).await;
    assert_eq!(r[3]["data"], WRITE_TEXT, "read back inside TLS: {}", r[3]);
    wait_event(&state, id, "nvme_tcp_disconnected", 0).await;

    // The discovery queue named the discovery NQN, the session's queues the subsystem.
    for sub in ["nqn.2014-08.org.nvmexpress.discovery", DISK0] {
        assert!(
            logged(&srv, &format!("PSK identity NVMe1R01 {HOST_NQN} {sub} ")).await,
            "a channel for {sub}: {:?}",
            srv.logs()
        );
    }
    assert!(!srv.logs().iter().any(|l| l.contains("fail_closed_tls")));
}

#[tokio::test]
async fn a_version_0_identity_and_a_sha384_key_work_too() {
    let key = ConfiguredKey::text(&[0x5au8; 48], Some(Hash::Sha384));
    let srv = target::start(policy(POLICY), Some(json!({"tls_key": key}))).await;
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"host_nqn": HOST_NQN, "tls_key": key, "tls_identity_version": 0}),
        chain(SESSION_POLICY),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], true, "{connected}");
    assert!(logged(&srv, &format!("PSK identity NVMe0R02 {HOST_NQN} {DISK0}")).await);
}

#[tokio::test]
async fn a_host_holding_another_key_is_told_why_it_could_not_connect() {
    let srv = target::start(policy(POLICY), Some(json!({"tls_key": KEY}))).await;
    let stranger = ConfiguredKey::text(&[3u8; 32], Some(Hash::Sha256));
    let (state, id) = client(
        format!("127.0.0.1:{}", srv.port),
        json!({"host_nqn": HOST_NQN, "subsystem_nqn": DISK0, "tls_key": stranger}),
        chain(&connect_first_policy()),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
    assert_eq!(connected["connected"], false, "{connected}");
    assert!(
        connected["error"]
            .as_str()
            .unwrap_or_default()
            .contains("TLS handshake"),
        "the model is told the secure channel failed: {connected}"
    );
    assert!(logged(&srv, "the PSK digest does not match").await);
    assert!(target::events(&srv.state, srv.id, "nvme_tcp_connect")
        .await
        .is_empty());
}
