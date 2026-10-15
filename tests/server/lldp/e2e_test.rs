//! LLDP end to end: a neighbour advertises, the model authors an identity, a frame goes out —
//! or, when it must not, nothing does.
//!
//! # Why this is in-process and over UDP
//!
//! LLDP's real transport is raw Ethernet, which needs `CAP_NET_RAW` / `/dev/bpf*`. Nothing in
//! this repository has that, and `server_startup` refuses to spawn a protocol whose declared
//! privilege is unmet — correctly — so the usual child-process harness cannot start an LLDP
//! server at all on an unprivileged host. This suite therefore builds a real `SpawnContext` and
//! calls `Server::spawn` directly, the way `tests/server/bluetooth_ble_beacon/e2e_test.rs` does,
//! and asks the protocol for its declared `transport: "udp"` test transport, which carries
//! complete Ethernet frames as datagram payloads.
//!
//! What that buys is the whole path: a frame arrives, the codec decodes it, the event is raised,
//! the handler or the model answers, the action is executed, a frame is built and transmitted,
//! and the test decodes it again with the same codec the neighbour would. What it does not buy
//! is any evidence about pcap — see this directory's `CLAUDE.md`.
//!
//! # LLM budget
//!
//! **One call**, in `an_identity_the_model_authors_reaches_the_wire`. Every other test here
//! either uses a static handler (no call by construction) or points at `127.0.0.1:1` to prove a
//! call *cannot* have succeeded.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features lldp \
//!       --test server lldp -- --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use netget::llm::actions::protocol_trait::{Protocol, Server};
use netget::llm::OllamaClient;
use netget::protocol::{SpawnContext, StartupParams};
use netget::server::lldp::actions::LldpProtocol;
use netget::server::lldp::codec::{self, Lldpdu, LLDP_MULTICAST_MAC};
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;

/// An endpoint nothing listens on. Any test using it proves the outcome happened *without* a
/// successful model call — the same trick `bluetooth_ble_beacon` uses.
const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";

/// A running LLDP server plus everything needed to observe it.
struct Running {
    /// Where the server's UDP test transport is bound.
    addr: SocketAddr,
    status_rx: UnboundedReceiver<String>,
    /// Held so the mock outlives the test; `None` when no model call is expected.
    mock: Option<MockOllamaServer>,
    /// Held so the server's tasks are not dropped mid-test.
    _state: Arc<AppState>,
}

impl Running {
    /// Wait up to `secs` for a status line containing `needle`, returning it.
    ///
    /// Polls rather than sleeping: the whole point of these assertions is *which* decision was
    /// taken, and a fixed sleep long enough to be reliable under `--test-threads=100` would make
    /// every test in the file slow.
    async fn wait_for_status(&mut self, needle: &str, secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        let mut seen = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(250), self.status_rx.recv()).await {
                Ok(Some(line)) => {
                    if line.contains(needle) {
                        return Some(line);
                    }
                    seen.push(line);
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        println!("status lines seen while waiting for '{needle}': {seen:#?}");
        None
    }
}

/// Start an LLDP server on the UDP test transport, in-process.
async fn start(
    instruction: &str,
    handlers: Option<Vec<Value>>,
    mut startup_params: Value,
    llm_url: &str,
    mock: Option<MockOllamaServer>,
) -> E2EResult<Running> {
    let state = Arc::new(AppState::new());
    // Without this, `ensure_model_selected` tries to auto-select against localhost:11434.
    state.set_ollama_model(Some("mock-model".to_string())).await;

    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "LLDP".to_string(),
            instruction.to_string(),
        ))
        .await;

    if let Some(handlers) = handlers {
        let config = netget::events::handler::EventHandler::parse_event_handlers(handlers)?;
        state
            .with_server_mut(server_id, |s| s.event_handler_config = Some(config))
            .await;
    }

    let protocol = LldpProtocol::new();
    if let Some(obj) = startup_params.as_object_mut() {
        obj.entry("transport").or_insert_with(|| json!("udp"));
    }
    let params = StartupParams::new(startup_params, protocol.get_startup_parameters())?;

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: Some("127.0.0.1".to_string()),
        port: Some(0),
        llm_client: OllamaClient::new(llm_url),
        state: state.clone(),
        status_tx,
        server_id,
        startup_params: Some(params),
    };

    let addr = protocol.spawn(ctx).await?;

    Ok(Running {
        addr,
        status_rx,
        mock,
        _state: state,
    })
}

/// The neighbour: an Ethernet frame carrying a perfectly ordinary advertisement.
fn neighbour_frame() -> Vec<u8> {
    let pdu = Lldpdu {
        system_name: Some("neighbour-sw".to_string()),
        system_description: Some("Vendor OS 9.9".to_string()),
        capabilities: Some((0x0014, 0x0014)),
        ..Lldpdu::minimal(4, "aa:bb:cc:dd:ee:ff", 5, "GigabitEthernet0/24", 120)
    };
    codec::encode_frame(
        LLDP_MULTICAST_MAC,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        &pdu,
    )
    .expect("the neighbour's own advertisement encodes")
}

/// A static handler that answers with one fixed identity.
fn static_identity_handler(pattern: &str) -> Vec<Value> {
    vec![json!({
        "event_pattern": pattern,
        "handler": {
            "type": "static",
            "actions": [{
                "type": "send_lldp_advertisement",
                "chassis_id": "02:00:00:00:00:01",
                "chassis_id_subtype": "mac_address",
                "port_id": "1/1",
                "port_id_subtype": "interface_name",
                "ttl": 120,
                "system_name": "netget-lab",
                "system_description": "NetGet LLDP agent",
                "capabilities": ["bridge", "router"]
            }]
        }
    })]
}

// =============================================================================================
// The happy path
// =============================================================================================

/// The whole point of the protocol: **the model authors the identity NetGet claims to be.**
///
/// A neighbour advertises; the model is asked; it answers with a chassis ID, a system
/// description and a capability set of its own choosing; and those become a real LLDP frame
/// which the test decodes with the same codec any neighbour would.
#[tokio::test]
async fn an_identity_the_model_authors_reaches_the_wire() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("lldp_neighbor_advertisement")
        .respond_with_actions(json!([{
            "type": "send_lldp_advertisement",
            "chassis_id": "00:1b:21:3c:4d:5e",
            "chassis_id_subtype": "mac_address",
            "port_id": "GigabitEthernet0/1",
            "port_id_subtype": "interface_name",
            "ttl": 120,
            "port_description": "Uplink to core",
            "system_name": "edge-sw-01",
            "system_description": "Cisco IOS Software, C2960 Software, Version 15.0(2)SE11",
            "capabilities": ["bridge", "router"],
            "capabilities_enabled": ["bridge"],
            "management_address": "192.0.2.10"
        }]))
        .expect_calls(1)
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "You are an LLDP agent impersonating a Cisco Catalyst switch.",
        None,
        json!({"source_mac": "02:00:00:00:00:07"}),
        &url,
        Some(mock),
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buf))
        .await
        .map_err(|_| "no advertisement came back within 30s")??;

    // The pcap oracle. `codec::decode_frame` below is the counterpart of the encoder
    // that produced these bytes, so it agrees with them by construction — the class of
    // defect Programme 2 found in this family (a transposed `05 75`/`75 05` pad, a
    // big-endian field that should be little-endian) survives a round trip through its
    // own codec untouched. Wireshark's `lldp` dissector shares nothing with it: it
    // walks the TLV list by type-and-length, requires the mandatory Chassis ID / Port
    // ID / TTL in order, and reports a TLV whose length runs past the frame as a
    // malformed packet.
    crate::helpers::pcap_oracle::PcapOracle::ethernet("lldp")
        .frame(&buf[..n])
        .assert_clean();

    let frame = codec::decode_frame(&buf[..n]).expect("what came back is a real LLDP frame");

    assert_eq!(
        frame.destination_mac, LLDP_MULTICAST_MAC,
        "an advertisement goes to the nearest-bridge group address"
    );
    assert_eq!(
        codec::format_mac(&frame.source_mac),
        "02:00:00:00:00:07",
        "the source address comes from the server's configuration, not from the model"
    );

    let pdu = frame.lldpdu;
    assert_eq!(pdu.chassis_id, "00:1b:21:3c:4d:5e");
    assert_eq!(
        pdu.chassis_id_subtype, 4,
        "mac_address, on the chassis table"
    );
    assert_eq!(pdu.port_id, "GigabitEthernet0/1");
    assert_eq!(pdu.port_id_subtype, 5, "interface_name, on the port table");
    assert_eq!(pdu.ttl, 120);
    assert_eq!(pdu.port_description.as_deref(), Some("Uplink to core"));
    assert_eq!(pdu.system_name.as_deref(), Some("edge-sw-01"));
    assert_eq!(
        pdu.system_description.as_deref(),
        Some("Cisco IOS Software, C2960 Software, Version 15.0(2)SE11"),
        "the reconnaissance-visible field is exactly what the model wrote"
    );
    assert_eq!(
        pdu.capabilities,
        Some((0x0014, 0x0004)),
        "supported bridge|router, enabled bridge only"
    );
    let mgmt = pdu.management_address.expect("a management address");
    assert_eq!(mgmt.address, "192.0.2.10");

    let mock = server.mock.take().expect("the mock was started");
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    Ok(())
}

/// A static handler answers without the model, which is the shape the dashboard and the
/// documentation recommend for a deterministic identity.
///
/// The unreachable LLM endpoint is what gives this teeth: a frame arriving proves no model call
/// was needed, rather than merely that one was not counted.
#[tokio::test]
async fn a_static_handler_advertises_with_no_llm_call() -> E2EResult<()> {
    let mut server = start(
        "",
        Some(static_identity_handler("lldp_neighbor_advertisement")),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), client.recv_from(&mut buf))
        .await
        .map_err(|_| "the static handler produced no frame within 20s")??;

    let pdu = codec::decode_frame(&buf[..n])
        .expect("a real LLDP frame")
        .lldpdu;
    assert_eq!(pdu.system_name.as_deref(), Some("netget-lab"));
    assert_eq!(pdu.chassis_id, "02:00:00:00:00:01");

    // Nothing should be waiting in the status stream about an LLM failure.
    assert!(
        server.wait_for_status("fail_closed", 1).await.is_none(),
        "a static handler must not reach the LLM at all"
    );
    Ok(())
}

/// The advertise timer is what makes this an LLDP *agent* rather than an echo: it announces
/// itself unprompted. It is also the emit site for `lldp_advertise_due`, and an event that is
/// declared and never raised is a defect this repository has shipped in bulk before.
#[tokio::test]
async fn the_advertise_timer_announces_us_unprompted() -> E2EResult<()> {
    // The timer has no peer to answer, so it needs one configured — which is exactly why
    // `udp_peer` exists.
    let listener = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = listener.local_addr()?;

    let _server = start(
        "",
        Some(static_identity_handler("lldp_advertise_due")),
        json!({"advertise_interval_secs": 1, "udp_peer": peer.to_string()}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), listener.recv_from(&mut buf))
        .await
        .map_err(|_| "the advertise timer produced no frame within 20s")??;

    let pdu = codec::decode_frame(&buf[..n])
        .expect("a real LLDP frame")
        .lldpdu;
    assert_eq!(pdu.system_name.as_deref(), Some("netget-lab"));
    Ok(())
}

// =============================================================================================
// Silence, and the three ways of arriving at it
// =============================================================================================

/// **An LLM failure must put nothing on the wire.**
///
/// This is the test the whole protocol's failure design exists for. Every LLDP frame asserts
/// that a device with a given identity is on this link, and a neighbour writes it into its
/// topology table; there is no error frame, so a fabricated advertisement would be strictly
/// worse than silence. The failure is visible only in the log, tagged `decision=`.
#[tokio::test]
async fn an_llm_failure_advertises_nothing() -> E2EResult<()> {
    let mut server = start(
        "You are an LLDP agent impersonating a switch.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;

    let line = server
        .wait_for_status("decision=", 60)
        .await
        .ok_or("the failure was never reported to the operator")?;
    assert!(
        line.contains("decision=fail_closed_llm_error")
            || line.contains("decision=fail_closed_overloaded"),
        "an unreachable backend must be tagged fail_closed, got: {line}"
    );
    assert!(
        line.contains("nothing advertised"),
        "the consequence must be stated, not inferred: {line}"
    );

    // And nothing came back. Checked after the decision is known, so this is not a race with a
    // frame still in flight.
    let mut buf = vec![0u8; 4096];
    match client.try_recv_from(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((n, _)) => panic!(
            "a frame was transmitted after an LLM failure: {:02x?}",
            &buf[..n]
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// No error text ever reaches the wire either — not even in a field a model might have filled.
///
/// This is the second half of the `WireFailure` rule: ~25 protocols were fixed for answering a
/// peer with netget's own retry machinery interpolated into the reply. LLDP cannot do that
/// because it sends nothing at all, and this asserts the stronger property directly.
#[tokio::test]
async fn no_backend_error_text_can_reach_a_neighbour() -> E2EResult<()> {
    let mut server = start(
        "You are an LLDP agent.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;
    server
        .wait_for_status("decision=", 60)
        .await
        .ok_or("the failure was never reported")?;

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            client.try_recv_from(&mut buf),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "silence is the only correct answer, so there is nothing for an error to hide in"
    );
    Ok(())
}

/// With no instruction and no handler there is no policy, so there is nothing honest to
/// advertise — and, just as importantly, no LLM round-trip per captured frame.
#[tokio::test]
async fn no_policy_means_no_frame_and_no_llm_call() -> E2EResult<()> {
    let mut server = start("", None, json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;

    let line = server
        .wait_for_status("decision=no_policy", 20)
        .await
        .ok_or("a passively observed advertisement must still be reported")?;
    assert!(line.contains("listening only"), "{line}");

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            client.try_recv_from(&mut buf),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "with no configured identity there is nothing to claim"
    );
    Ok(())
}

/// `no_advertisement` is a real answer and must be distinguishable, in the log, from the model
/// having produced nothing. On the wire the two are identical.
#[tokio::test]
async fn a_deliberate_refusal_is_logged_as_a_decision() -> E2EResult<()> {
    let handlers = vec![json!({
        "event_pattern": "lldp_neighbor_advertisement",
        "handler": {
            "type": "static",
            "actions": [{"type": "no_advertisement", "reason": "listening only on this link"}]
        }
    })];

    let mut server = start("", Some(handlers), json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&neighbour_frame(), server.addr).await?;

    let line = server
        .wait_for_status("decision=model_reject", 20)
        .await
        .ok_or("a deliberate refusal must be tagged distinctly")?;
    assert!(line.contains("nothing advertised"), "{line}");

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            client.try_recv_from(&mut buf),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "no_advertisement means no frame"
    );
    Ok(())
}

// =============================================================================================
// Startup contract
// =============================================================================================

/// A parameter that cannot be honoured fails the start, rather than being accepted and ignored.
///
/// An advertised knob that silently does nothing is the defect `startup_param_drift_test`
/// exists for; a knob that is *rejected* when it would do nothing is the same principle applied
/// to a combination the protocol cannot honour.
#[tokio::test]
async fn unusable_startup_parameters_are_refused() -> E2EResult<()> {
    let protocol = LldpProtocol::new();

    for (params, needle) in [
        (json!({"transport": "carrier-pigeon"}), "transport must be"),
        (
            json!({"transport": "raw", "udp_peer": "127.0.0.1:9"}),
            "would do nothing",
        ),
        (
            json!({"transport": "udp", "udp_peer": "nonsense"}),
            "HOST:PORT",
        ),
        (
            json!({"transport": "udp", "advertise_interval_secs": -1}),
            "advertise_interval_secs",
        ),
        (
            json!({"transport": "udp", "source_mac": "zz"}),
            "MAC address",
        ),
    ] {
        let state = Arc::new(AppState::new());
        let server_id = state
            .add_server(ServerInstance::new(
                ServerId::new(0),
                0,
                "LLDP".to_string(),
                String::new(),
            ))
            .await;
        let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
        let startup_params = StartupParams::new(params.clone(), protocol.get_startup_parameters())?;

        #[allow(deprecated)]
        let ctx = SpawnContext {
            listen_addr: "127.0.0.1:0".parse()?,
            mac_address: None,
            interface: None,
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
            llm_client: OllamaClient::new(UNREACHABLE_LLM),
            state,
            status_tx,
            server_id,
            startup_params: Some(startup_params),
        };

        let err = protocol
            .spawn(ctx)
            .await
            .expect_err(&format!("{params} must be refused"));
        assert!(
            format!("{err:#}").contains(needle),
            "the refusal for {params} should mention '{needle}': {err:#}"
        );
    }
    Ok(())
}

/// An undeclared parameter is rejected before anything is bound, naming the ones that exist.
#[tokio::test]
async fn an_undeclared_parameter_names_the_declared_ones() {
    let protocol = LldpProtocol::new();
    let err = StartupParams::new(
        json!({"chassis_id": "00:11:22:33:44:55"}),
        protocol.get_startup_parameters(),
    )
    .expect_err("chassis_id is an action field, not a startup parameter");

    let message = err.to_string();
    assert!(message.contains("chassis_id"), "{message}");
    for declared in [
        "transport",
        "udp_peer",
        "advertise_interval_secs",
        "source_mac",
    ] {
        assert!(
            message.contains(declared),
            "the error should list '{declared}': {message}"
        );
    }
}

/// The raw transport refuses on loopback with an explanation, rather than sitting in `Running`
/// having captured nothing.
///
/// This is the ARP/DataLink/ICMP/IS-IS defect, which was fixed four separate times. On an
/// unprivileged host the capture open fails first; on a privileged one the BPF filter does,
/// because `ether proto` is Ethernet-only and loopback has no Ethernet header. Either way
/// `spawn` must return `Err`.
#[tokio::test]
async fn the_raw_transport_refuses_rather_than_pretending() -> E2EResult<()> {
    let protocol = LldpProtocol::new();
    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "LLDP".to_string(),
            String::new(),
        ))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: Some("netget-no-such-device0".to_string()),
        host: Some("127.0.0.1".to_string()),
        port: Some(0),
        llm_client: OllamaClient::new(UNREACHABLE_LLM),
        state,
        status_tx,
        server_id,
        startup_params: Some(StartupParams::new(
            json!({"transport": "raw"}),
            protocol.get_startup_parameters(),
        )?),
    };

    let err = protocol
        .spawn(ctx)
        .await
        .expect_err("a device that does not exist cannot produce a running capture");
    assert!(
        format!("{err:#}").contains("netget-no-such-device0"),
        "the refusal must name the device: {err:#}"
    );
    Ok(())
}
