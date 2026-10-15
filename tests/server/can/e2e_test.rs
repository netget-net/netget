//! CAN end to end: a frame arrives, the model is the ECU, a frame goes back — or, when it must
//! not, nothing does.
//!
//! # Why this is in-process and over UDP
//!
//! `AF_CAN` is a Linux kernel address family. This suite runs on macOS, where it does not exist
//! at all, so nothing here can open a CAN socket and nothing here says anything about SocketCAN.
//! What it does exercise is everything else: the codec, the events, handler and script dispatch,
//! the model call, the action executor and the frame builder — over the protocol's own declared
//! `transport: "udp"` test transport, which carries the same `struct can_frame` /
//! `struct canfd_frame` octets an `AF_CAN` socket would. The suite builds a real `SpawnContext`
//! and calls `Server::spawn` directly, the way `tests/server/lldp/e2e_test.rs` and
//! `tests/server/bluetooth_ble_beacon/e2e_test.rs` do.
//!
//! The transport itself is covered by [`the_socketcan_transport_refuses_to_start_off_linux`] and
//! by nothing else. That refusal is a feature, not a gap: hiding the protocol would leave the
//! model never learning why, while refusing gives the operator `ServerStatus::Error` with the
//! reason. See this directory's `CLAUDE.md` for the concrete path to Beta on Linux.
//!
//! # LLM budget
//!
//! **Two calls.** `the_model_is_the_ecu` makes one and `a_can_fd_frame_survives_the_whole_path`
//! makes one. Every other test either uses a static handler (no call by construction) or points
//! at `127.0.0.1:1` to prove a call *cannot* have succeeded.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features can --test server can:: \
//!       -- --test-threads=100

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{Protocol, Server};
use netget::llm::OllamaClient;
use netget::protocol::{server_registry, SpawnContext, StartupParams};
use netget::server::can::actions::CanProtocol;
use netget::server::can::frame::{CanFrame, CAN_ERR_FLAG, CAN_MTU};
use netget::server::can::transport::{socketcan_supported, UNSUPPORTED_PLATFORM_MESSAGE};
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
/// successful model call, rather than merely that one was not counted.
const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";

/// A running CAN server plus everything needed to observe it.
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
    /// Polls rather than sleeping: a fixed sleep long enough to be reliable under
    /// `--test-threads=100` would make every test in the file slow, and the repo has been bitten
    /// by exactly that.
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

/// Build a spawn context for the CAN protocol with the given startup parameters.
fn spawn_context(
    state: &Arc<AppState>,
    server_id: ServerId,
    params: Value,
    llm_url: &str,
) -> E2EResult<(SpawnContext, UnboundedReceiver<String>)> {
    let protocol = CanProtocol::new();
    let startup_params = StartupParams::new(params, protocol.get_startup_parameters())?;
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
        startup_params: Some(startup_params),
    };
    Ok((ctx, status_rx))
}

/// Start a CAN server on the UDP test transport, in-process.
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
            "CAN".to_string(),
            instruction.to_string(),
        ))
        .await;

    if let Some(handlers) = handlers {
        let config = netget::events::handler::EventHandler::parse_event_handlers(handlers)?;
        state
            .with_server_mut(server_id, |s| s.event_handler_config = Some(config))
            .await;
    }

    if let Some(obj) = startup_params.as_object_mut() {
        obj.entry("transport").or_insert_with(|| json!("udp"));
    }

    let (ctx, status_rx) = spawn_context(&state, server_id, startup_params, llm_url)?;
    let addr = CanProtocol::new().spawn(ctx).await?;

    Ok(Running {
        addr,
        status_rx,
        mock,
        _state: state,
    })
}

/// An OBD-II mode 01 PID 05 request (engine coolant temperature) on the functional broadcast
/// identifier, as a real diagnostic tester would send it.
fn obd_request() -> Vec<u8> {
    CanFrame::classic(
        0x7DF,
        false,
        vec![0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
    )
    .expect("a well-formed OBD-II request")
    .to_wire_bytes()
    .expect("which encodes")
}

/// An error frame reporting the controller has gone error-passive.
///
/// `CAN_ERR_CRTL` (0x004) in the identifier, `CAN_ERR_CRTL_RX_PASSIVE` (0x10) in `data[1]` — the
/// layout the kernel uses, written out here rather than built by the code under test.
fn error_passive_frame() -> Vec<u8> {
    let mut bytes = vec![0u8; CAN_MTU];
    bytes[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x0000_0004).to_le_bytes());
    bytes[4] = 8;
    bytes[9] = 0x10;
    bytes
}

/// A static handler answering `pattern` with one fixed frame.
fn static_frame_handler(pattern: &str) -> Vec<Value> {
    vec![json!({
        "event_pattern": pattern,
        "handler": {
            "type": "static",
            "actions": [{
                "type": "send_can_frame",
                "id": "0x7E8",
                "extended": false,
                "data": "0341051e",
                "encoding": "hex"
            }]
        }
    })]
}

/// Receive one datagram from `client`, decoded as a CAN frame.
async fn recv_frame(client: &UdpSocket, secs: u64, what: &str) -> E2EResult<CanFrame> {
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(secs), client.recv_from(&mut buf))
        .await
        .map_err(|_| format!("no frame came back within {secs}s: {what}"))??;
    Ok(CanFrame::from_wire_bytes(&buf[..n])?)
}

// =================================================================================================
// The platform rule
// =================================================================================================

/// **The refusal, which on this host is the only reachable part of the SocketCAN path.**
///
/// `AF_CAN` exists only in the Linux kernel. A protocol that cannot run must say so rather than
/// disappearing: hidden, the model never learns why; refused, the operator gets
/// `ServerStatus::Error` carrying the reason. `spawn()` therefore returns `Err`, and the message
/// names the address family, the platform, the `vcan` route on Linux and the UDP test transport
/// here.
#[tokio::test]
async fn the_socketcan_transport_refuses_to_start_off_linux() -> E2EResult<()> {
    if socketcan_supported() {
        // On Linux this test would be asserting the opposite of the truth. It is skipped rather
        // than inverted, because a passing assertion about SocketCAN would be evidence this
        // suite is not entitled to produce.
        println!("SKIP: this host has AF_CAN; the refusal cannot be observed here");
        return Ok(());
    }

    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "CAN".to_string(),
            "You are an ECU.".to_string(),
        ))
        .await;

    // The default transport is socketcan, so an empty parameter set is the case that matters.
    let (ctx, _status_rx) = spawn_context(&state, server_id, json!({}), UNREACHABLE_LLM)?;
    let err = CanProtocol::new()
        .spawn(ctx)
        .await
        .expect_err("SocketCAN cannot start without AF_CAN")
        .to_string();

    assert!(
        err.contains("AF_CAN"),
        "the refusal must name the address family that is missing: {err}"
    );
    assert!(err.contains("Linux"), "and the platform that has it: {err}");
    assert!(
        err.contains("vcan0"),
        "and the no-hardware route on that platform: {err}"
    );
    assert!(
        err.contains("\"transport\": \"udp\""),
        "and what can be run here instead: {err}"
    );
    assert_eq!(
        err, UNSUPPORTED_PLATFORM_MESSAGE,
        "one const is the single source of this text, so the docs and the error cannot drift"
    );

    // And the UDP transport is genuinely reachable on the same host, which is what makes the
    // refusal a routing decision rather than a dead end.
    let running = start("", None, json!({"transport": "udp"}), UNREACHABLE_LLM, None).await?;
    assert_ne!(running.addr.port(), 0, "the test transport really bound");
    Ok(())
}

/// The protocol must be reachable through the registry the TUI, MCP and CLI all go through, and
/// must declare what the rest of the system relies on.
#[test]
fn can_is_registered_and_declares_what_it_must() {
    let registry = server_registry::registry();
    let protocol = registry
        .get("CAN")
        .expect("can must be registered when its feature is enabled");

    let metadata = protocol.metadata();
    assert!(
        metadata.is_available_to_llm(),
        "the model must be able to select it and learn why it cannot start, rather than finding \
         it absent"
    );
    assert!(
        metadata.connectionless,
        "a CAN bus has no connections; the 10-second idle sweep must reap the bookkeeping entries"
    );

    let actions: Vec<String> = protocol
        .get_sync_actions()
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert_eq!(
        actions,
        vec!["send_can_frame".to_string(), "no_response".to_string()],
        "the whole vocabulary, and nothing that could emit an error frame"
    );

    // Every event carries the actions, or the model cannot answer it at all.
    for event in protocol.get_event_types() {
        assert!(
            !event.actions.is_empty(),
            "event {} offers the model no actions",
            event.id
        );
    }
}

/// **Nothing in the vocabulary can emit a CAN error frame, and that is a safety property.**
///
/// An error frame is six dominant bits transmitted on top of a frame in flight: it destroys that
/// frame for every node, and repeated ones drive controllers error-passive and then bus-off.
/// There must be no way for a model — or a confused operator's handler — to produce one.
#[test]
fn no_action_can_emit_an_error_frame() {
    let protocol = CanProtocol::new();
    for action in protocol.get_sync_actions() {
        assert!(
            !action.parameters.iter().any(|p| p.name == "error"),
            "action {} exposes an 'error' parameter",
            action.name
        );
    }

    // Even asked directly, an `error` field is not a way in: it is not read, so the frame that
    // is built is an ordinary data frame.
    let result = protocol
        .execute_action(json!({
            "type": "send_can_frame", "id": "0x100", "error": true, "data": "00"
        }))
        .expect("the action is still valid; the error flag is simply not a thing it can set");
    let bytes = match result {
        netget::llm::actions::protocol_trait::ActionResult::Output(bytes) => bytes,
        other => panic!("send_can_frame must produce wire bytes, got {other:?}"),
    };
    let frame = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert!(
        !frame.error,
        "no path through the executor sets the ERR flag"
    );
}

// =================================================================================================
// The happy path
// =================================================================================================

/// The whole point of the protocol: **the model is the ECU.**
///
/// A diagnostic tester broadcasts an OBD-II request; the model decides that this is an identifier
/// the engine controller it is simulating owns, and answers on 0x7E8 with a coolant temperature.
/// The reply is decoded by the same codec any node on the bus would use.
#[tokio::test]
async fn the_model_is_the_ecu() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("can_frame_received")
        .respond_with_actions(json!([{
            "type": "send_can_frame",
            "id": "0x7E8",
            "extended": false,
            "data": "0341057b",
            "encoding": "hex"
        }]))
        .expect_calls(1)
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "You are an engine control unit. Answer OBD-II requests on 0x7DF from 0x7E8.",
        None,
        json!({"interface": "vcan0"}),
        &url,
        Some(mock),
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

    let frame = recv_frame(&client, 30, "the ECU's OBD-II response").await?;
    assert_eq!(frame.id, 0x7E8, "ECU 0 answers on 0x7E8");
    assert!(!frame.extended, "OBD-II on 11-bit identifiers");
    assert!(!frame.rtr);
    assert!(!frame.error, "and it is a data frame, not an error frame");
    assert_eq!(
        frame.data,
        vec![0x03, 0x41, 0x05, 0x7B],
        "the payload is the decoded hex the model wrote, not its ASCII"
    );
    assert_eq!(frame.dlc(), 4);

    let mock = server.mock.take().expect("the mock was started");
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    Ok(())
}

/// A CAN FD frame with a bit-rate switch survives the whole path, DLC encoding included.
///
/// 16 bytes is DLC 10 — a number the model never sees and never has to compute, which is the
/// point of doing the encoding in the codec.
#[tokio::test]
async fn a_can_fd_frame_survives_the_whole_path() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("can_frame_received")
        .respond_with_actions(json!([{
            "type": "send_can_frame",
            "id": "0x18DAF110",
            "extended": true,
            "fd": true,
            "brs": true,
            "data": "000102030405060708090a0b0c0d0e0f",
            "encoding": "hex"
        }]))
        .expect_calls(1)
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "You are a CAN FD gateway.",
        None,
        json!({}),
        &url,
        Some(mock),
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

    let frame = recv_frame(&client, 30, "the CAN FD reply").await?;
    assert!(frame.fd, "an FD frame came back");
    assert!(frame.brs, "with the bit-rate switch the model asked for");
    assert!(frame.extended);
    assert_eq!(frame.id, 0x18DA_F110);
    assert_eq!(frame.data, (0u8..16).collect::<Vec<u8>>());
    assert_eq!(
        frame.dlc(),
        10,
        "16 bytes is DLC 10 — a length CODE, not a byte count"
    );

    let mock = server.mock.take().expect("the mock was started");
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    Ok(())
}

/// A static handler answers with no model call at all, which is what a deterministic ECU
/// simulator should use — a real bus carries thousands of frames a second.
///
/// The unreachable LLM endpoint is what gives this teeth: a frame arriving proves no model call
/// was needed, rather than merely that one was not counted.
#[tokio::test]
async fn a_static_handler_answers_with_no_llm_call() -> E2EResult<()> {
    let mut server = start(
        "",
        Some(static_frame_handler("can_frame_received")),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

    let frame = recv_frame(&client, 20, "the static handler's frame").await?;
    assert_eq!(frame.id, 0x7E8);
    assert_eq!(frame.data, vec![0x03, 0x41, 0x05, 0x1E]);

    assert!(
        server.wait_for_status("fail_closed", 1).await.is_none(),
        "a static handler must not reach the LLM at all"
    );
    Ok(())
}

// =================================================================================================
// The other two events, and that they really fire
// =================================================================================================

/// `can_error_frame` has a real emit site: an error frame off the bus raises it.
///
/// A declared event that never fires is a defect this repository has shipped in bulk, and a
/// static declaration check cannot see it. The handler here answers with a frame, so its arrival
/// is proof the event was dispatched.
#[tokio::test]
async fn an_error_frame_raises_can_error_frame() -> E2EResult<()> {
    let server = start(
        "",
        Some(static_frame_handler("can_error_frame")),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&error_passive_frame(), server.addr).await?;

    let frame = recv_frame(&client, 20, "the answer to can_error_frame").await?;
    assert_eq!(frame.id, 0x7E8);
    assert!(
        !frame.error,
        "and what NetGet transmits in reply is never itself an error frame"
    );
    Ok(())
}

/// `can_bus_state_changed` has a real emit site: crossing a confinement boundary raises it.
///
/// The first error-passive report is a transition from error-active and must fire. A second
/// identical one is not a transition and must not — otherwise a degrading bus floods the model
/// with events that say nothing new.
#[tokio::test]
async fn crossing_a_confinement_boundary_raises_can_bus_state_changed_once() -> E2EResult<()> {
    let mut server = start(
        "",
        Some(static_frame_handler("can_bus_state_changed")),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&error_passive_frame(), server.addr).await?;

    let frame = recv_frame(&client, 20, "the answer to can_bus_state_changed").await?;
    assert_eq!(frame.id, 0x7E8);

    // The operator is told, in the state the ladder actually names.
    //
    // Asserted unconditionally. This used to substitute an empty string when the status
    // never arrived and then guard the real assertion behind `if !line.is_empty()`, so a
    // server that reported nothing at all passed silently - which is the one outcome the
    // check exists to catch.
    let line = server
        .wait_for_status("bus state", 20)
        .await
        .expect("the server must report the bus-state transition on its status stream");
    assert!(
        line.contains("error_active -> error_passive"),
        "the transition must name both ends: {line}"
    );

    // Same condition again: not a transition, so no second frame.
    client.send_to(&error_passive_frame(), server.addr).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut buf = vec![0u8; 4096];
    match client.try_recv_from(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((n, _)) => panic!("the same state was reported twice: {:02x?}", &buf[..n]),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

// =================================================================================================
// Silence, and the four ways of arriving at it
// =================================================================================================

/// **An LLM failure must put nothing on the bus.**
///
/// This is the test the whole failure design exists for. CAN has no error *reply*: the thing
/// called an error frame corrupts a frame in flight for every node, and repeated ones drive
/// controllers bus-off. So a backend outage transmits nothing, and the failure survives only in
/// the log, tagged `decision=`.
#[tokio::test]
async fn an_llm_failure_transmits_nothing() -> E2EResult<()> {
    let mut server = start(
        "You are an engine control unit answering OBD-II requests.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

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
        line.contains("nothing transmitted"),
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

/// `no_response` is a decision, and is logged as one — distinguishable from a failure even though
/// the bus cannot tell them apart.
#[tokio::test]
async fn no_response_is_a_decision_and_is_tagged_as_one() -> E2EResult<()> {
    let handlers = vec![json!({
        "event_pattern": "can_frame_received",
        "handler": {"type": "static", "actions": [{"type": "no_response"}]}
    })];

    let mut server = start("", Some(handlers), json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

    let line = server
        .wait_for_status("decision=", 30)
        .await
        .ok_or("the decision was never reported")?;
    assert!(
        line.contains("decision=model_reject"),
        "an explicit no_response is a real decision, not a silence: {line}"
    );

    let mut buf = vec![0u8; 4096];
    match client.try_recv_from(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((n, _)) => panic!("no_response transmitted something: {:02x?}", &buf[..n]),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// With no instruction and no handler there is no ECU to simulate, so the server listens and
/// **makes no LLM call at all**.
///
/// This matters more here than in most protocols: a real CAN bus carries thousands of frames a
/// second, and a model round-trip per frame would be ruinous as well as pointless.
#[tokio::test]
async fn with_no_policy_the_server_listens_and_never_calls_the_model() -> E2EResult<()> {
    let mut server = start("", None, json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&obd_request(), server.addr).await?;

    let line = server
        .wait_for_status("decision=no_policy", 30)
        .await
        .ok_or("the no-policy decision was never reported")?;
    assert!(line.contains("listening only"), "got: {line}");

    let mut buf = vec![0u8; 4096];
    match client.try_recv_from(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((n, _)) => panic!("a passive listener transmitted: {:02x?}", &buf[..n]),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

// =================================================================================================
// Startup parameters
// =================================================================================================

/// A parameter that would do nothing is refused by name rather than silently ignored.
#[tokio::test]
async fn udp_peer_is_refused_on_the_socketcan_transport() -> E2EResult<()> {
    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "CAN".to_string(),
            String::new(),
        ))
        .await;

    let (ctx, _rx) = spawn_context(
        &state,
        server_id,
        json!({"transport": "socketcan", "udp_peer": "127.0.0.1:9999"}),
        UNREACHABLE_LLM,
    )?;
    let err = CanProtocol::new()
        .spawn(ctx)
        .await
        .expect_err("udp_peer means nothing on a real CAN socket")
        .to_string();
    assert!(err.contains("udp_peer"), "got: {err}");
    assert!(
        err.contains("would do nothing"),
        "the refusal must say why: {err}"
    );
    Ok(())
}

/// An unknown transport names the two that exist.
#[tokio::test]
async fn an_unknown_transport_is_refused_by_name() -> E2EResult<()> {
    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "CAN".to_string(),
            String::new(),
        ))
        .await;

    let (ctx, _rx) = spawn_context(
        &state,
        server_id,
        json!({"transport": "j1939"}),
        UNREACHABLE_LLM,
    )?;
    let err = CanProtocol::new()
        .spawn(ctx)
        .await
        .expect_err("j1939 is not a transport this protocol offers")
        .to_string();
    assert!(err.contains("socketcan"), "got: {err}");
    assert!(err.contains("udp"), "got: {err}");
    Ok(())
}

/// An undeclared startup key is refused before anything is bound, naming itself.
#[test]
fn an_undeclared_startup_parameter_is_refused() {
    let protocol = CanProtocol::new();
    let err = StartupParams::new(
        json!({"bitrate": 500000}),
        protocol.get_startup_parameters(),
    )
    .expect_err("bitrate is set with `ip link`, not by NetGet")
    .to_string();
    assert!(err.contains("bitrate"), "the key must name itself: {err}");
}

/// The `udp_peer` parameter is what lets an unprompted transmission reach somewhere, and it is
/// read — a declared parameter nothing reads is an advertised knob that does nothing.
#[tokio::test]
async fn udp_peer_directs_transmissions_before_anything_is_received() -> E2EResult<()> {
    // A socket that never speaks to the server: without `udp_peer` there would be nowhere to
    // send, because the sink falls back to "whoever spoke last".
    let listener = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = listener.local_addr()?;

    let server = start(
        "",
        Some(static_frame_handler("can_frame_received")),
        json!({"udp_peer": peer.to_string()}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    // Provoke the event from a *different* socket, so only `udp_peer` can explain the delivery.
    let prodder = UdpSocket::bind("127.0.0.1:0").await?;
    prodder.send_to(&obd_request(), server.addr).await?;

    let frame = recv_frame(&listener, 20, "the frame directed by udp_peer").await?;
    assert_eq!(frame.id, 0x7E8);
    Ok(())
}
