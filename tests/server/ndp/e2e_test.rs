//! NDP end to end: a host solicits, the model authors what the link will believe, a message goes
//! out — or, when it must not, nothing does.
//!
//! # Why this is in-process and over UDP
//!
//! NDP's real transport is a raw ICMPv6 socket, which needs root or `CAP_NET_RAW`. Nothing in this
//! repository has that, and `server_startup` refuses to spawn a protocol whose declared privilege
//! is unmet — correctly — so the usual child-process harness cannot start an NDP server at all on
//! an unprivileged host. This suite therefore builds a real `SpawnContext` and calls
//! `Server::spawn` directly, the way `tests/server/lldp/e2e_test.rs` and
//! `tests/server/bluetooth_ble_beacon/e2e_test.rs` do, and asks the protocol for its declared
//! `transport: "udp"` test transport.
//!
//! That transport carries `source(16) || destination(16) || ICMPv6 message`, which is the part of
//! the IPv6 header the ICMPv6 checksum is computed over. It is in that shape on purpose: the
//! pseudo-header checksum is the single most error-prone thing in this protocol, and a test
//! transport that carried only the ICMPv6 bytes could not check it. Here every message the server
//! emits is verified against the addresses it claims to have travelled between, and a message
//! whose checksum is wrong is proven to be dropped.
//!
//! What this does not buy is any evidence about the raw socket — see this directory's `CLAUDE.md`.
//!
//! # LLM budget
//!
//! **One call**, in `a_router_advertisement_the_model_authors_reaches_the_wire`. Every other test
//! here either uses a static handler (no call by construction) or points at `127.0.0.1:1` to
//! prove a call *cannot* have succeeded.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ndp \
//!       --test server ndp -- --test-threads=100

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{Protocol, Server};
use netget::llm::OllamaClient;
use netget::protocol::{SpawnContext, StartupParams};
use netget::server::ndp::actions::NdpProtocol;
use netget::server::ndp::codec::{self, NdpMessage, NdpOption, PrefixInformation};
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;

/// An endpoint nothing listens on. Any test using it proves the outcome happened *without* a
/// successful model call.
const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";

/// The address the server is configured to speak from, and therefore half of every pseudo-header.
const SERVER_ADDRESS: &str = "fe80::1";
/// The link-layer address the server is configured with.
const SERVER_MAC: &str = "02:00:00:00:00:07";
/// The host on the other end.
const HOST_ADDRESS: &str = "fe80::abcd";

fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("a literal IPv6 address")
}

/// A running NDP server plus everything needed to observe it.
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
    /// Polls rather than sleeping: the assertions are about *which* decision was taken, and a
    /// fixed sleep long enough to be reliable under `--test-threads=100` would make every test in
    /// the file slow.
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

    /// Wait until every needle has been seen at least once, in any order.
    async fn wait_for_all(&mut self, needles: &[&str], secs: u64) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        let mut outstanding: Vec<String> = needles.iter().map(|n| n.to_string()).collect();
        let mut seen = Vec::new();
        while !outstanding.is_empty() && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(250), self.status_rx.recv()).await {
                Ok(Some(line)) => {
                    outstanding.retain(|n| !line.contains(n.as_str()));
                    seen.push(line);
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        if !outstanding.is_empty() {
            println!("never saw {outstanding:?}; lines seen: {seen:#?}");
        }
        outstanding
    }
}

/// Start an NDP server on the UDP test transport, in-process.
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
            "NDP".to_string(),
            instruction.to_string(),
        ))
        .await;

    if let Some(handlers) = handlers {
        let config = netget::events::handler::EventHandler::parse_event_handlers(handlers)?;
        state
            .with_server_mut(server_id, |s| s.event_handler_config = Some(config))
            .await;
    }

    let protocol = NdpProtocol::new();
    if let Some(obj) = startup_params.as_object_mut() {
        obj.entry("transport").or_insert_with(|| json!("udp"));
        obj.entry("link_local_address")
            .or_insert_with(|| json!(SERVER_ADDRESS));
        obj.entry("link_layer_address")
            .or_insert_with(|| json!(SERVER_MAC));
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

/// Wrap a message for the UDP test transport, with a correct checksum.
fn datagram(source: &str, destination: &str, message: &NdpMessage) -> Vec<u8> {
    let (s, d) = (addr(source), addr(destination));
    let bytes = message.encode(s, d).expect("the message encodes");
    codec::encode_addressed(s, d, &bytes)
}

fn router_solicitation() -> Vec<u8> {
    datagram(
        HOST_ADDRESS,
        "ff02::2",
        &NdpMessage::RouterSolicitation {
            options: vec![NdpOption::SourceLinkLayerAddress([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ])],
        },
    )
}

fn neighbor_solicitation(target: &str) -> Vec<u8> {
    let target = addr(target);
    datagram(
        HOST_ADDRESS,
        &codec::solicited_node_multicast(target).to_string(),
        &NdpMessage::NeighborSolicitation {
            target,
            options: vec![NdpOption::SourceLinkLayerAddress([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ])],
        },
    )
}

/// Decode whatever the server sent back, and check the checksum it computed over the pseudo-header
/// of the addresses it claims to have used.
///
/// This is the assertion that makes the whole transport worth having: a server that computed the
/// checksum over the ICMPv6 bytes alone would produce a message every real host discards, and it
/// would pass every test that only looked at the fields.
fn decode_reply(datagram: &[u8]) -> (Ipv6Addr, Ipv6Addr, NdpMessage) {
    let (source, destination, message) =
        codec::decode_addressed(datagram).expect("the reply is an addressed ICMPv6 message");
    codec::verify_checksum(message, source, destination)
        .expect("the reply's checksum is correct over the IPv6 pseudo-header it was built for");
    (
        source,
        destination,
        NdpMessage::decode(message).expect("the reply is a real NDP message"),
    )
}

/// A static handler that answers a neighbour solicitation.
fn static_neighbor_handler() -> Vec<Value> {
    vec![json!({
        "event_pattern": "ndp_neighbor_solicitation",
        "handler": {
            "type": "static",
            "actions": [{
                "type": "send_neighbor_advertisement",
                "target": "fe80::1",
                "router": true,
                "solicited": true,
                "override": true
            }]
        }
    })]
}

// =============================================================================================
// The happy path — the message this protocol exists for
// =============================================================================================

/// **The model authors what an entire link will believe.**
///
/// A host solicits a router; the model answers with a prefix, a DNS server and an MTU of its own
/// choosing; and those become a real Router Advertisement which the test decodes — and whose
/// checksum it verifies against the pseudo-header — exactly as a host's IPv6 stack would.
///
/// This is `mitm6` with reasoning: a host that accepted this would install `fe80::1` as its
/// default router, build an address out of `2001:db8:1::/64` and resolve every name through
/// `2001:db8:1::53`.
#[tokio::test]
async fn a_router_advertisement_the_model_authors_reaches_the_wire() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("ndp_router_solicitation")
        .respond_with_actions(json!([{
            "type": "send_router_advertisement",
            "hop_limit": 64,
            "managed": false,
            "other": false,
            "router_lifetime": 1800,
            "prefixes": [{
                "prefix": "2001:db8:1::",
                "length": 64,
                "on_link": true,
                "autonomous": true,
                "valid_lifetime": 2592000,
                "preferred_lifetime": 604800
            }],
            "rdnss": ["2001:db8:1::53"],
            "rdnss_lifetime": 600,
            "mtu": 1500
        }]))
        .expect_calls(1)
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "You are an IPv6 router on this link.",
        None,
        json!({}),
        &url,
        Some(mock),
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&router_solicitation(), server.addr).await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buf))
        .await
        .map_err(|_| "no advertisement came back within 30s")??;

    let (source, destination, message) = decode_reply(&buf[..n]);
    assert_eq!(
        source,
        addr(SERVER_ADDRESS),
        "the source comes from the server's configuration, not the model — it is what a host \
         installs as its default router"
    );
    assert_eq!(
        destination,
        addr(HOST_ADDRESS),
        "a solicited advertisement goes back to the host that asked"
    );

    let NdpMessage::RouterAdvertisement(ra) = message else {
        panic!("a router solicitation must be answered with a Router Advertisement");
    };
    assert_eq!(ra.cur_hop_limit, 64);
    assert!(!ra.managed);
    assert!(!ra.other);
    assert_eq!(ra.router_lifetime, 1800);

    assert!(
        ra.options
            .contains(&NdpOption::PrefixInformation(PrefixInformation {
                prefix: addr("2001:db8:1::"),
                prefix_length: 64,
                on_link: true,
                autonomous: true,
                valid_lifetime: 2_592_000,
                preferred_lifetime: 604_800,
            })),
        "the prefix the model chose reaches the wire intact: {:?}",
        ra.options
    );
    assert!(
        ra.options.contains(&NdpOption::Mtu(1500)),
        "the MTU option is present"
    );
    assert!(
        ra.options.contains(&NdpOption::Rdnss {
            lifetime: 600,
            servers: vec![addr("2001:db8:1::53")],
        }),
        "the RDNSS list is what makes this a complete traffic redirect and not merely a route"
    );
    assert!(
        ra.options
            .contains(&NdpOption::SourceLinkLayerAddress([0x02, 0, 0, 0, 0, 0x07])),
        "the server fills in its own link-layer address, which the model does not know"
    );

    let mock = server.mock.take().expect("the mock was started");
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    Ok(())
}

/// A static handler answers a neighbour solicitation without the model — the shape the dashboard
/// and the documentation recommend for a deterministic responder.
///
/// The unreachable LLM endpoint is what gives this teeth: a message arriving proves no model call
/// was needed, rather than merely that one was not counted.
#[tokio::test]
async fn a_static_handler_answers_a_neighbor_solicitation_with_no_llm_call() -> E2EResult<()> {
    let mut server = start(
        "",
        Some(static_neighbor_handler()),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(&neighbor_solicitation("fe80::1"), server.addr)
        .await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), client.recv_from(&mut buf))
        .await
        .map_err(|_| "the static handler produced no message within 20s")??;

    let (source, destination, message) = decode_reply(&buf[..n]);
    assert_eq!(source, addr(SERVER_ADDRESS));
    assert_eq!(
        destination,
        addr(HOST_ADDRESS),
        "the answer goes back to the node that solicited"
    );

    let NdpMessage::NeighborAdvertisement {
        router,
        solicited,
        override_flag,
        target,
        ..
    } = &message
    else {
        panic!("a neighbour solicitation must be answered with a Neighbour Advertisement");
    };
    assert!(router);
    assert!(solicited);
    assert!(override_flag);
    assert_eq!(*target, addr("fe80::1"));
    assert_eq!(
        message.target_link_layer(),
        Some([0x02, 0, 0, 0, 0, 0x07]),
        "the link-layer address a peer will send traffic to comes from the server's config"
    );

    assert!(
        server.wait_for_status("fail_closed", 1).await.is_none(),
        "a static handler must not reach the LLM at all"
    );
    Ok(())
}

/// All five message types raise their own event, and each is answerable.
///
/// An event declared and never raised is a defect this repository has shipped in bulk
/// (`tests/event_emit_sites_test.rs` exists for it), and a static-source check cannot tell which
/// decoded message maps to which event. This drives one of each through the real transport and
/// requires the corresponding `decision=model_reject` line, which names the event id.
#[tokio::test]
async fn every_message_type_raises_its_own_event() -> E2EResult<()> {
    let handlers = vec![json!({
        "event_pattern": "ndp_*",
        "handler": {
            "type": "static",
            "actions": [{"type": "no_response", "reason": "observing"}]
        }
    })];

    let mut server = start("", Some(handlers), json!({}), UNREACHABLE_LLM, None).await?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    let messages = vec![
        NdpMessage::RouterSolicitation { options: vec![] },
        NdpMessage::RouterAdvertisement(codec::RouterAdvertisement {
            cur_hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![NdpOption::Mtu(1500)],
        }),
        NdpMessage::NeighborSolicitation {
            target: addr("fe80::1"),
            options: vec![],
        },
        NdpMessage::NeighborAdvertisement {
            router: false,
            solicited: true,
            override_flag: true,
            target: addr("fe80::abcd"),
            options: vec![],
        },
        NdpMessage::Redirect {
            target: addr("fe80::9"),
            destination: addr("2001:db8:2::9"),
            options: vec![],
        },
    ];

    for message in &messages {
        client
            .send_to(
                &datagram(HOST_ADDRESS, SERVER_ADDRESS, message),
                server.addr,
            )
            .await?;
    }

    let missing = server
        .wait_for_all(
            &[
                "ndp_router_solicitation decision=",
                "ndp_router_advertisement_received decision=",
                "ndp_neighbor_solicitation decision=",
                "ndp_neighbor_advertisement decision=",
                "ndp_redirect_received decision=",
            ],
            30,
        )
        .await;
    assert!(
        missing.is_empty(),
        "these events were declared but never raised: {missing:?}"
    );
    Ok(())
}

// =============================================================================================
// The checksum, on the running server
// =============================================================================================

/// A message whose checksum does not match the addresses it claims to have travelled between is
/// dropped, and a correct one immediately afterwards is not.
///
/// The control matters: without it, "no reply" is indistinguishable from a server that was not
/// listening at all.
#[tokio::test]
async fn a_message_with_a_wrong_checksum_is_dropped() -> E2EResult<()> {
    let mut server = start(
        "",
        Some(static_neighbor_handler()),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // Corrupt exactly the checksum field of an otherwise perfect solicitation.
    let mut corrupted = neighbor_solicitation("fe80::1");
    corrupted[32 + 2] ^= 0xff;
    client.send_to(&corrupted, server.addr).await?;

    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(750), client.recv_from(&mut buf)).await {
        Err(_) => {}
        Ok(Ok((n, _))) => panic!(
            "a message with a bad checksum was answered: {:02x?}",
            &buf[..n]
        ),
        Ok(Err(e)) => return Err(e.into()),
    }

    // The control: the same solicitation with its real checksum is answered.
    client
        .send_to(&neighbor_solicitation("fe80::1"), server.addr)
        .await?;
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), client.recv_from(&mut buf))
        .await
        .map_err(|_| "the uncorrupted solicitation was not answered either")??;
    let (_, _, message) = decode_reply(&buf[..n]);
    assert_eq!(message.message_type(), 136);

    let _ = server.wait_for_status("__nothing__", 0).await;
    Ok(())
}

// =============================================================================================
// Silence, and the ways of arriving at it
// =============================================================================================

/// **An LLM failure must put nothing on the wire.**
///
/// This is the test the whole protocol's failure design exists for. Every NDP message writes
/// something into the peer's stack — a neighbour cache entry, a default route, a resolver list —
/// and what to write is exactly what the failed call was supposed to decide. There is no error
/// message to send instead, so a fabricated one is cache poisoning at best and a full traffic
/// redirect at worst. The failure is visible only in the log, tagged `decision=`.
#[tokio::test]
async fn an_llm_failure_sends_nothing() -> E2EResult<()> {
    let mut server = start(
        "You are an IPv6 router on this link.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&router_solicitation(), server.addr).await?;

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
        line.contains("nothing sent"),
        "the consequence must be stated, not inferred: {line}"
    );

    // And nothing came back. Checked after the decision is known, so this is not a race with a
    // message still in flight.
    let mut buf = vec![0u8; 4096];
    match client.try_recv_from(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((n, _)) => panic!(
            "a message was transmitted after an LLM failure: {:02x?}",
            &buf[..n]
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// No error text ever reaches the wire either — not even in a field a model might have filled.
///
/// This is the second half of the `WireFailure` rule: ~25 protocols were fixed for answering a
/// peer with netget's own retry machinery interpolated into the reply. NDP cannot do that because
/// it sends nothing at all, and this asserts the stronger property directly.
#[tokio::test]
async fn no_backend_error_text_can_reach_a_peer() -> E2EResult<()> {
    let mut server = start(
        "You are an IPv6 router.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(&neighbor_solicitation("fe80::1"), server.addr)
        .await?;
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

/// With no instruction and no handler there is no policy, so there is no address we can honestly
/// claim — and, just as importantly, no LLM round-trip per received packet. A raw ICMPv6 socket
/// on a busy link sees a great many.
#[tokio::test]
async fn no_policy_means_no_message_and_no_llm_call() -> E2EResult<()> {
    let mut server = start("", None, json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(&neighbor_solicitation("fe80::1"), server.addr)
        .await?;

    let line = server
        .wait_for_status("decision=no_policy", 20)
        .await
        .ok_or("a passively observed solicitation must still be reported")?;
    assert!(line.contains("observing only"), "{line}");

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            client.try_recv_from(&mut buf),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "with no configured policy there is no address to claim"
    );
    Ok(())
}

/// `no_response` is a real answer and must be distinguishable, in the log, from the model having
/// produced nothing. On the wire the two are identical.
#[tokio::test]
async fn a_deliberate_refusal_is_logged_as_a_decision() -> E2EResult<()> {
    let handlers = vec![json!({
        "event_pattern": "ndp_neighbor_solicitation",
        "handler": {
            "type": "static",
            "actions": [{"type": "no_response", "reason": "not authoritative for that address"}]
        }
    })];

    let mut server = start("", Some(handlers), json!({}), UNREACHABLE_LLM, None).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(&neighbor_solicitation("2001:db8:9::9"), server.addr)
        .await?;

    let line = server
        .wait_for_status("decision=model_reject", 20)
        .await
        .ok_or("a deliberate refusal must be tagged distinctly")?;
    assert!(line.contains("nothing sent"), "{line}");

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            client.try_recv_from(&mut buf),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "no_response means no message"
    );
    Ok(())
}

// =============================================================================================
// Startup contract
// =============================================================================================

/// A parameter that cannot be honoured fails the start, rather than being accepted and ignored.
///
/// An advertised knob that silently does nothing is the defect `startup_param_drift_test` exists
/// for; a knob that is *rejected* when it would do nothing is the same principle applied to a
/// combination the protocol cannot honour.
#[tokio::test]
async fn unusable_startup_parameters_are_refused() -> E2EResult<()> {
    let protocol = NdpProtocol::new();

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
            json!({"transport": "udp", "link_local_address": "192.0.2.1"}),
            "link_local_address",
        ),
        (
            json!({"transport": "udp", "link_layer_address": "zz"}),
            "link-layer address",
        ),
        // `raw` with no interface: NDP is link-local, so there is no useful default and starting
        // anyway would produce a server that can never transmit to ff02::1.
        (json!({"transport": "raw"}), "needs an interface"),
    ] {
        let state = Arc::new(AppState::new());
        let server_id = state
            .add_server(ServerInstance::new(
                ServerId::new(0),
                0,
                "NDP".to_string(),
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
    let protocol = NdpProtocol::new();
    let err = StartupParams::new(
        json!({"router_lifetime": 1800}),
        protocol.get_startup_parameters(),
    )
    .expect_err("router_lifetime is an action field, not a startup parameter");

    let message = err.to_string();
    assert!(message.contains("router_lifetime"), "{message}");
    for declared in [
        "transport",
        "udp_peer",
        "link_local_address",
        "link_layer_address",
    ] {
        assert!(
            message.contains(declared),
            "the error should list '{declared}': {message}"
        );
    }
}

/// The raw transport refuses rather than sitting in `Running` having received nothing.
///
/// This is the ARP/DataLink/ICMP/IS-IS defect, fixed four separate times elsewhere. Here the
/// interface lookup fails first — and it is deliberately *before* the socket, because a raw
/// ICMPv6 socket with no scope id cannot send to `ff02::1` at all, so opening one first would
/// produce a server that starts and can never transmit.
#[tokio::test]
async fn the_raw_transport_refuses_rather_than_pretending() -> E2EResult<()> {
    let protocol = NdpProtocol::new();
    let state = Arc::new(AppState::new());
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "NDP".to_string(),
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
        .expect_err("a device that does not exist cannot produce a running socket");
    assert!(
        format!("{err:#}").contains("netget-no-such-device0"),
        "the refusal must name the device: {err:#}"
    );
    Ok(())
}

/// The protocol declares `RawSockets` and `connectionless()`, and both matter.
///
/// `RawSockets` is what makes `server_startup` refuse NDP on an unprivileged host — including in
/// UDP mode, since privilege is a static property of a protocol and cannot depend on a parameter.
/// Declaring `None` to make the test transport reachable through `open_server` would be a lie
/// about the transport anyone actually uses.
///
/// `connectionless()` is what admits NDP's per-peer bookkeeping entries to the 10-second idle
/// sweep; without it they would accumulate for the life of the server.
#[test]
fn the_metadata_declares_what_the_transport_really_needs() {
    use netget::protocol::metadata::{DevelopmentState, PrivilegeRequirement};

    let metadata = NdpProtocol::new().metadata();
    assert_eq!(
        metadata.privilege_requirement,
        PrivilegeRequirement::RawSockets
    );
    assert!(metadata.connectionless);
    assert_eq!(
        metadata.state,
        DevelopmentState::Experimental,
        "the raw ICMPv6 transport has never been executed; see src/server/ndp/CLAUDE.md"
    );
    assert!(
        metadata.notes.iter().any(|n| n.contains("NOT PROVEN")),
        "the notes must say which half of this protocol is evidence and which is not"
    );
}
