//! A protocol without `default_binding()` listens where the caller asked.
//!
//! Most servers still take `server_startup`'s legacy binding path, which used to build its
//! address from `127.0.0.1` whatever `host` said: `host: "0.0.0.0"` meant to expose a server
//! on the network quietly bound loopback, and the instance reported the host it had been
//! given. These start the TCP server, which takes that path, on IPv6 loopback — the one
//! non-default address every test host can bind — and read back where it listens.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test legacy_host_binding_test


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::cli::server_startup::legacy_bind_ip;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::sync::mpsc;

async fn bound_addr(state: &AppState, id: ServerId) -> SocketAddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return addr;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server #{} never reported a bound address",
            id.as_u32()
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

async fn start_tcp(host: Option<&str>) -> anyhow::Result<(AppState, SocketAddr)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tcp".to_string(),
        host: host.map(str::to_string),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await?;
    let addr = bound_addr(&state, id).await;
    Ok((state, addr))
}

#[test]
fn the_bind_address_is_loopback_unless_a_host_is_named() {
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!(legacy_bind_ip(None).unwrap(), v4);
    assert_eq!(legacy_bind_ip(Some("")).unwrap(), v4);
    assert_eq!(legacy_bind_ip(Some("localhost")).unwrap(), v4);
    assert_eq!(
        legacy_bind_ip(Some("0.0.0.0")).unwrap(),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    );
    assert_eq!(
        legacy_bind_ip(Some("[::1]")).unwrap(),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
    assert_eq!(
        legacy_bind_ip(Some("::")).unwrap(),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    );
    // A name this path cannot bind is an error, never a silent fallback to loopback.
    assert!(legacy_bind_ip(Some("example.com")).is_err());
}

#[tokio::test]
async fn an_explicit_host_is_where_the_server_listens() {
    let (_state, addr) = start_tcp(Some("::1")).await.expect("start tcp on ::1");
    assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST), "bound {addr}");
    // And a peer reaches it there.
    tokio::net::TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect to {addr}: {e}"));
}

#[tokio::test]
async fn no_host_still_means_ipv4_loopback() {
    let (_state, addr) = start_tcp(None).await.expect("start tcp");
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST), "bound {addr}");
}

#[tokio::test]
async fn a_host_that_is_not_an_address_is_refused() {
    let err = match start_tcp(Some("not-an-address.invalid")).await {
        Ok((_, addr)) => panic!("an unbindable host must be refused, not bound as {addr}"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("not an IP address"),
        "unexpected error: {err:#}"
    );
}
