//! The port a server starts on when the caller names none — `netget::protocol::default_port`.
//!
//! Four properties, each the one a caller would be hurt by if it broke:
//!
//! 1. A well-known port at or above 1024 is taken whatever this process's privilege.
//! 2. A well-known port below 1024 falls back to an OS-assigned port, **with the reason**, when
//!    this process cannot bind privileged ports.
//! 3. A well-known port something already holds falls back to an OS-assigned port with the
//!    reason, rather than failing the start — and the probe asks the transport the port is
//!    registered for, so a UDP listener does not make a TCP port look taken.
//! 4. An explicit port is never replaced, `0` included — through the real startup path.
//!
//! Every port here is either one the kernel just handed out or one this test holds itself, so
//! nothing depends on what else the machine happens to be running.

use netget::privilege::SystemCapabilities;
use netget::protocol::default_port::{
    port_is_in_use, resolve_default_port, DefaultPort, PortFallback,
};
use netget::protocol::metadata::PortTransport;

fn caps(can_bind_privileged_ports: bool) -> SystemCapabilities {
    SystemCapabilities {
        can_bind_privileged_ports,
        has_raw_socket_access: false,
        has_packet_capture_access: false,
        has_bluetooth_access: false,
        has_usb_access: false,
        has_nfc_access: false,
        is_root: false,
    }
}

/// A TCP port the kernel just said was free, released again.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
fn a_well_known_port_at_or_above_1024_is_taken_without_privilege() {
    let port = free_tcp_port();
    assert!(
        port >= 1024,
        "the kernel hands out unprivileged ephemeral ports"
    );
    let resolved = resolve_default_port(Some(port), PortTransport::Tcp, "127.0.0.1", &caps(false));
    assert_eq!(resolved.well_known, Some(port));
    assert_ne!(
        resolved.fallback,
        Some(PortFallback::NeedsPrivilege),
        "privilege is never the reason at or above 1024"
    );
    assert_released_port_is_the_default(port, &resolved);
    if resolved.fallback.is_none() {
        assert_eq!(resolved.describe(), format!("well-known port {port}"));
    }
}

#[test]
fn a_privileged_well_known_port_falls_back_with_the_reason_when_privilege_is_missing() {
    let resolved = resolve_default_port(Some(53), PortTransport::Udp, "127.0.0.1", &caps(false));
    assert_eq!(
        resolved.port, 0,
        "an OS-assigned port, not a start that fails"
    );
    assert_eq!(resolved.well_known, Some(53));
    assert_eq!(resolved.fallback, Some(PortFallback::NeedsPrivilege));
    assert_eq!(
        resolved.describe(),
        "well-known port 53 needs root; starting on an OS-assigned port"
    );
}

#[test]
fn a_privileged_well_known_port_is_not_refused_when_privilege_is_present() {
    // Whether 53 is free on this machine is not ours to know, so the assertion is the one
    // that holds either way: privilege is never the reason given.
    let resolved = resolve_default_port(Some(53), PortTransport::Udp, "127.0.0.1", &caps(true));
    assert_ne!(resolved.fallback, Some(PortFallback::NeedsPrivilege));
    match resolved.fallback {
        None => assert_eq!(resolved.port, 53),
        Some(PortFallback::InUse) => assert_eq!(resolved.port, 0),
        Some(PortFallback::NeedsPrivilege) => unreachable!(),
    }
}

#[test]
fn a_well_known_port_in_use_falls_back_with_the_reason() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().unwrap().port();

    assert!(port_is_in_use("127.0.0.1", port, PortTransport::Tcp));
    let resolved = resolve_default_port(Some(port), PortTransport::Tcp, "127.0.0.1", &caps(true));
    assert_eq!(resolved.port, 0);
    assert_eq!(resolved.fallback, Some(PortFallback::InUse));
    assert_eq!(
        resolved.describe(),
        format!("well-known port {port} is in use; starting on an OS-assigned port")
    );

    drop(held);
    let resolved = resolve_default_port(Some(port), PortTransport::Tcp, "127.0.0.1", &caps(true));
    assert_released_port_is_the_default(port, &resolved);
}

/// Released, the same port is the default again — the probe reads the present.
///
/// An ephemeral port nobody holds is the kernel's to hand to the next `bind(0)`, and in a
/// whole-suite run some other test in some other process is always asking. So a fallback is
/// accepted only when the port really is held by someone else right now; a fallback on a free
/// port is the defect this assertion exists for.
fn assert_released_port_is_the_default(port: u16, resolved: &DefaultPort) {
    if resolved.port == port {
        assert_eq!(resolved.fallback, None);
        return;
    }
    assert_eq!(resolved.fallback, Some(PortFallback::InUse));
    assert!(
        port_is_in_use("127.0.0.1", port, PortTransport::Tcp),
        "fell back from {port}, but nothing holds it"
    );
}

#[test]
fn the_in_use_probe_asks_the_ports_own_transport() {
    let held = std::net::UdpSocket::bind("127.0.0.1:0").expect("hold a UDP port");
    let port = held.local_addr().unwrap().port();

    assert!(port_is_in_use("127.0.0.1", port, PortTransport::Udp));
    let udp = resolve_default_port(Some(port), PortTransport::Udp, "127.0.0.1", &caps(true));
    assert_eq!(udp.fallback, Some(PortFallback::InUse));

    // A TCP bind on the same number is a different socket. If the probe asked TCP about a UDP
    // port it would call a free port taken, or — the direction that matters — a taken one free.
    if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
        assert!(!port_is_in_use("127.0.0.1", port, PortTransport::Tcp));
    }
}

#[test]
fn no_well_known_port_means_an_os_assigned_one() {
    let resolved = resolve_default_port(None, PortTransport::Tcp, "127.0.0.1", &caps(true));
    assert_eq!(resolved.port, 0);
    assert_eq!(resolved.well_known, None);
    assert_eq!(
        resolved.describe(),
        "no well-known port; starting on an OS-assigned port"
    );
}

/// Through the real startup path: `ServerForm::create` → `start_server_from_action`.
mod through_startup {
    use std::time::Duration;

    use netget::cli::management::ServerForm;
    use netget::state::app_state::AppState;
    use netget::state::ServerId;

    const REDIS_WELL_KNOWN: u16 = 6379;

    async fn new_state() -> AppState {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
        state
            .set_llm_client(netget::llm::OllamaClient::new(
                "http://127.0.0.1:1".to_string(),
            ))
            .await;
        state
    }

    async fn bound_port(state: &AppState, id: ServerId) -> u16 {
        for _ in 0..200 {
            if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
                return addr.port();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("server #{} never reported a bound address", id.as_u32());
    }

    fn form(port: Option<u16>) -> ServerForm {
        ServerForm {
            protocol: "redis".to_string(),
            port,
            // Model-free: nothing here should reach an LLM.
            instruction: Some(String::new()),
            ..Default::default()
        }
    }

    async fn start(state: &AppState, port: Option<u16>) -> (ServerId, Vec<String>) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let id = form(port)
            .create(state, tx)
            .await
            .expect("redis server starts");
        let mut lines = Vec::new();
        while let Ok(line) = rx.try_recv() {
            lines.push(line);
        }
        (id, lines)
    }

    #[tokio::test]
    async fn an_explicit_zero_is_never_replaced_by_the_well_known_port() {
        let state = new_state().await;
        let (id, lines) = start(&state, Some(0)).await;
        let port = bound_port(&state, id).await;
        assert_ne!(port, 0);
        assert_ne!(
            port, REDIS_WELL_KNOWN,
            "port 0 asks for an OS-assigned port; the well-known port is only for no port at all"
        );
        assert!(
            !lines.iter().any(|l| l.contains("no port given")),
            "an explicit port must not be treated as an omitted one: {lines:?}"
        );
        state.remove_server(id).await;
    }

    #[tokio::test]
    async fn an_explicit_port_is_never_replaced() {
        let state = new_state().await;
        let wanted = super::free_tcp_port();
        let (id, _) = start(&state, Some(wanted)).await;
        assert_eq!(bound_port(&state, id).await, wanted);
        state.remove_server(id).await;
    }

    /// With the well-known port held, an omitted port starts on an OS-assigned one and the
    /// status stream says why, instead of the start failing on "address in use".
    ///
    /// The test holds 6379 itself when it can; when it cannot, something else already does,
    /// which is the same condition. Either way the port is taken for the whole test.
    #[tokio::test]
    async fn an_omitted_port_falls_back_when_the_well_known_port_is_taken() {
        let _held = std::net::TcpListener::bind(("127.0.0.1", REDIS_WELL_KNOWN)).ok();
        assert!(
            netget::protocol::default_port::port_is_in_use(
                "127.0.0.1",
                REDIS_WELL_KNOWN,
                netget::protocol::metadata::PortTransport::Tcp
            ),
            "6379 must be held for this test to mean anything"
        );

        let state = new_state().await;
        let (id, lines) = start(&state, None).await;
        let port = bound_port(&state, id).await;
        assert_ne!(port, REDIS_WELL_KNOWN);
        assert_ne!(port, 0);
        assert!(
            lines
                .iter()
                .any(|l| l
                    .contains("well-known port 6379 is in use; starting on an OS-assigned port")),
            "the fallback must be explained, not silent: {lines:?}"
        );
        state.remove_server(id).await;
    }
}
