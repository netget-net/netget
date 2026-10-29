//! The target's secure channel, driven by raw PDUs inside a TLS session.
//!
//! The TLS host here is NetGet's own (`netget::server::nvme_tcp::tls::connect`), so these are a
//! regression of the target's shapes, not interoperability evidence: the Linux host through
//! tlshd and SPDK are the independent peers, in the `nvme-tcp` pair job. What is asserted is what
//! the target does with what it is sent — PDUs travel inside the session, the discovery log
//! says TLS is required, a Connect is held to the identity the host proved, and a host without
//! the key never gets as far as an ICResp.
#![cfg(unix)]

use super::support::*;
use netget::server::nvme_tcp::auth::Hash;
use netget::server::nvme_tcp::tls;
use netget::server::nvme_tcp::tls_psk::ConfiguredKey;
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpStream;

/// libnvme's key from `tls_psk_test.rs`, so a derivation regression shows there first.
const KEY: &str = "NVMeTLSkey-1:01:3rMPGkRFakyIYjFLJ7LZQNiFQ3Lyua16Zm97sG5VS8yDf7yj:";

async fn tls_raw(
    port: u16,
    key: &str,
    hostnqn: &str,
    subnqn: &str,
    version: u8,
) -> anyhow::Result<Raw> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    tcp.set_nodelay(true)?;
    let key = ConfiguredKey::parse(key).map_err(anyhow::Error::msg)?;
    let (s, _) = tls::connect(tcp, &key, hostnqn, subnqn, version).await?;
    Ok(Raw::over(s))
}

async fn logged(srv: &Started, needle: &str) -> bool {
    for _ in 0..200 {
        if srv.logs().iter().any(|l| l.contains(needle)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdus_travel_inside_the_secure_channel_and_connect_is_held_to_the_identity() {
    let srv = start(policy(POLICY), Some(json!({"tls_key": KEY}))).await;

    // A whole admin session inside TLS, under a version 1 identity.
    let mut raw = tls_raw(srv.port, KEY, HOST, DISK0, 1).await.expect("TLS");
    raw.admin_session(DISK0, HOST, 0).await;
    let (id, c) = raw.identify(1, 0).await;
    assert!(c.ok(), "Identify inside TLS: {c:?}");
    assert_eq!(ascii(&id[24..64]).trim(), "NETGET-BOOT");
    assert!(
        logged(&srv, &format!("operation=tls decision=protocol_accept TLS 1.3 secure channel, PSK identity NVMe1R01 {HOST} {DISK0} ")).await,
        "the accepted identity is logged: {:?}",
        srv.logs()
    );

    // The discovery log says TLS 1.3 is required: TREQ's low bits 01b, TSAS SECTYPE 2.
    let mut d = tls_raw(srv.port, KEY, HOST, DISCOVERY, 1).await.expect("TLS");
    d.admin_session(DISCOVERY, HOST, 0).await;
    let (log, c) = d.get_log(0x70, 0, 2048).await;
    assert!(c.ok(), "discovery log: {c:?}");
    let entry = &log[1024..2048];
    assert_eq!(ascii(&entry[256..512]).trim_end_matches('\0'), DISK0);
    assert_eq!(entry[3] & 0x03, 0x01, "TREQ: secure channel required");
    assert_eq!(entry[768], 2, "TSAS SECTYPE: TLS 1.3");

    // A Connect as another host on a channel this host's identity opened.
    let mut other_host = tls_raw(srv.port, KEY, HOST, DISK0, 1).await.expect("TLS");
    other_host.icreq(0, 0).await;
    let c = other_host
        .connect_queue(
            0,
            31,
            0,
            0,
            &connect_data(&HOSTID, 0xFFFF, DISK0, "nqn.2026-10.org.example:other-host"),
        )
        .await;
    assert_eq!(c.sc(), (1, 0x84), "Connect Invalid Host: {c:?}");

    // And to a subsystem the identity does not name.
    let mut other_sub = tls_raw(srv.port, KEY, HOST, DISK0, 1).await.expect("TLS");
    other_sub.icreq(0, 0).await;
    let c = other_sub
        .connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, BACKUP, HOST))
        .await;
    assert_eq!(c.sc(), (1, 0x82), "Connect Invalid Parameters: {c:?}");
    assert!(
        logged(&srv, "on a secure channel established for").await,
        "both refusals are logged: {:?}",
        srv.logs()
    );
    // Neither reached the model: only the one accepted Connect did.
    assert_eq!(events(&srv.state, srv.id, "nvme_tcp_connect").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_without_the_key_never_reaches_nvme_tcp() {
    let srv = start(policy(POLICY), Some(json!({"tls_key": KEY}))).await;

    // Plain NVMe/TCP: the ICReq is not a ClientHello, and no ICResp comes back.
    let mut plain = Raw::connect(srv.port).await;
    let mut psh = vec![0u8; 120];
    psh[4] = 0;
    plain.send(0x00, 0, &psh, &[]).await;
    assert!(plain.recv_within(Duration::from_secs(5)).await.is_none());
    assert!(plain.closed().await, "the target closes a plain connection");
    assert!(
        logged(&srv, "operation=tls decision=fail_closed_tls").await,
        "{:?}",
        srv.logs()
    );

    // Another key: the digest in its identity is not the one this target's key gives.
    let stranger = ConfiguredKey::text(&[9u8; 32], Some(Hash::Sha256));
    assert!(tls_raw(srv.port, &stranger, HOST, DISK0, 1).await.is_err());
    assert!(
        logged(&srv, "the PSK digest does not match").await,
        "{:?}",
        srv.logs()
    );

    // A version 0 identity carries no digest, so another key fails at the handshake itself.
    assert!(tls_raw(srv.port, &stranger, HOST, DISK0, 0).await.is_err());

    // Silence: the handshake is bounded.
    let mut silent = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    let started = std::time::Instant::now();
    let mut b = [0u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::io::AsyncReadExt::read(&mut silent, &mut b),
    )
    .await
    .expect("closed within the bound");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(started.elapsed() >= Duration::from_secs(9), "{:?}", started.elapsed());
    assert!(
        logged(&srv, "no TLS handshake within 10 s").await,
        "{:?}",
        srv.logs()
    );
    assert!(events(&srv.state, srv.id, "nvme_tcp_connect").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sha384_keys_and_version_0_identities_are_served() {
    // SHA-384 is TLS_AES_256_GCM_SHA384, which OpenSSL's legacy PSK callbacks cannot carry.
    let key = ConfiguredKey::text(&[0x42u8; 48], Some(Hash::Sha384));
    let srv = start(policy(POLICY), Some(json!({"tls_key": key}))).await;
    for version in [1, 0] {
        let mut raw = tls_raw(srv.port, &key, HOST, DISK0, version)
            .await
            .unwrap_or_else(|e| panic!("version {version}: {e:#}"));
        raw.admin_session(DISK0, HOST, 0).await;
        let (_, c) = raw.identify(1, 0).await;
        assert!(c.ok(), "version {version}: {c:?}");
    }
    assert!(
        logged(&srv, &format!("PSK identity NVMe0R02 {HOST} {DISK0}")).await,
        "{:?}",
        srv.logs()
    );
}

#[tokio::test]
async fn a_malformed_tls_key_is_refused_at_startup() {
    let state = netget::state::app_state::AppState::new_with_options(
        false,
        "http://127.0.0.1:1".to_string(),
    );
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let err = netget::cli::management::ServerForm {
        protocol: "nvme_tcp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        startup_params: Some(json!({"tls_key": "NVMeTLSkey-1:01:AAAA:"})),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect_err("refused");
    assert!(format!("{err:#}").contains("tls_key"), "{err:#}");
}
