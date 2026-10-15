//! The startup privilege gate asks what *this* start needs, not what the protocol declares for
//! its real transport.
//!
//! LLDP, STP, CDP, EAPOL, NDP, VRRP and raw IP declare raw-socket or packet-capture privilege,
//! honestly, for the transport an operator uses. Each also has a UDP test transport that sends
//! the same frames over an ordinary socket and needs nothing. The gate used to read the declared
//! requirement before the startup parameters, so `transport: "udp"` was refused on any
//! unprivileged host and every suite had to call `Server::spawn` directly to get past it.
//! `Protocol::startup_privilege_requirement` now carries the per-start answer.

use netget::protocol::metadata::PrivilegeRequirement;
use serde_json::json;

const UDP_CAPABLE: &[&str] = &["lldp", "stp", "cdp", "eapol", "ndp", "vrrp", "rawip"];

fn key(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

#[test]
fn only_the_udp_test_transports_relax_the_requirement() {
    let udp = json!({"transport": "udp"});
    let raw = json!({"transport": "raw"});
    for (name, protocol) in netget::protocol::server_registry::registry().all_protocols() {
        let declared = protocol.metadata().privilege_requirement;
        assert_eq!(
            protocol.startup_privilege_requirement(None),
            declared,
            "{name}: no parameters must mean the declared requirement"
        );
        assert_eq!(
            protocol.startup_privilege_requirement(Some(&raw)),
            declared,
            "{name}: the raw transport must keep the declared requirement"
        );
        let over_udp = protocol.startup_privilege_requirement(Some(&udp));
        if UDP_CAPABLE.contains(&key(&name).as_str()) {
            assert_ne!(
                declared,
                PrivilegeRequirement::None,
                "{name} declares a privilege"
            );
            assert_eq!(
                over_udp,
                PrivilegeRequirement::None,
                "{name} over UDP needs none"
            );
        } else {
            assert_eq!(over_udp, declared, "{name} has no unprivileged transport");
        }
    }
}

/// Through the real startup path, not `Server::spawn`: the gate must let the UDP transport in.
/// VRRP needs raw sockets for real, which no unprivileged process has, so this fails on any
/// unprivileged host if the gate reads the declared requirement.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn vrrp_over_udp_starts_through_the_gate_without_privilege() {
    use netget::{cli::management::ServerForm, state::app_state::AppState};
    use std::time::Duration;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = ServerForm {
        protocol: "vrrp".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(json!({"transport": "udp"})),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("VRRP over UDP must not be refused for privilege");
    let addr = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("VRRP over UDP never came up");
    assert_ne!(addr.port(), 0);
    state.remove_server(id).await;
}
