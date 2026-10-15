//! Tests for the WireGuard VPN server.
//!
//! # What these tests actually validate, and why they look like this
//!
//! NetGet's WireGuard server is a *thin orchestration layer* over
//! `defguard_wireguard_rs`. NetGet implements **none** of the WireGuard protocol
//! itself - no Noise_IK handshake, no ChaCha20-Poly1305, no packet parsing. All
//! of that lives in the platform backend: the kernel module on Linux, or the
//! **external `wireguard-go` binary** on macOS (defguard literally shells out to
//! `Command::new("wireguard-go")`). Creating the interface therefore needs root
//! (and, on macOS, wireguard-go installed and in PATH).
//!
//! Consequences for testing:
//!
//! * There is **no NetGet-authored handshake/crypto code to drive** with real
//!   curve25519 keys - that layer simply does not exist in this repo.
//! * A real end-to-end handshake (a `wg` client, `wg-quick`, or an in-process
//!   `boringtun` peer) can only run against a *running* server, which needs root
//!   + a backend. It has never been run and cannot run in CI. It lives here only
//!   as a root-gated `#[ignore]`d harness that **fails loudly** rather than
//!   skipping-as-pass (see `test_wireguard_real_backend_startup`).
//! * `boringtun` was evaluated as an in-process real WireGuard peer. It is a
//!   genuine, independent implementation (BSD-3-Clause), but with the server
//!   unable to start here it has nothing to handshake against; a
//!   boringtun-against-boringtun test would validate Cloudflare's library, not
//!   NetGet, so it was deliberately NOT added.
//!
//! What we CAN validate without privilege is the code NetGet actually owns: the
//! action executors that implement the LLM's control surface
//! (`authorize_peer` / `reject_peer` / `disconnect_peer` /
//! `set_peer_traffic_limit`) and the event/action declarations that decide what
//! the model is even allowed to answer with. Those are covered below and run in
//! CI.
//!
//! The previous version of this file was fictional: it mocked a
//! `wireguard_packet_received` event and a `log_packet` action that **do not
//! exist** in the implementation (the server raises `wireguard_peer_connected`
//! and has no packet-sniffing honeypot path at all), and every test was
//! `#[ignore]`d behind root, so the mismatch never surfaced.

#![cfg(unix)]

use crate::server::helpers::*;
// `::netget::` (absolute extern-crate path) is required: `use crate::server::helpers::*`
// glob-imports the `helpers::netget` module, which would otherwise shadow the crate name.
use ::netget::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use ::netget::server::wireguard::actions::{WireguardProtocol, WIREGUARD_PEER_CONNECTED_EVENT};
use serde_json::json;

/// Decode an `ActionResult::Output(json_bytes)` back into a `serde_json::Value`.
///
/// The executors return their structured decision as JSON-encoded bytes in
/// `Output`; the server layer decodes and applies it. Any other variant is a
/// test failure with a descriptive message.
fn output_json(result: ActionResult) -> serde_json::Value {
    match result {
        ActionResult::Output(bytes) => {
            serde_json::from_slice(&bytes).expect("executor Output was not valid JSON")
        }
        other => panic!("expected ActionResult::Output, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// authorize_peer
// ---------------------------------------------------------------------------

#[test]
fn authorize_peer_returns_structured_authorization() {
    let proto = WireguardProtocol::new();
    let result = proto
        .execute_action(json!({
            "type": "authorize_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": ["10.20.30.2/32"],
            "endpoint": "203.0.113.45:51820",
            "message": "ok"
        }))
        .expect("authorize_peer with valid params must succeed");

    let out = output_json(result);
    assert_eq!(out["action"], "authorize_peer");
    assert_eq!(
        out["public_key"],
        "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
    );
    assert_eq!(out["allowed_ips"], json!(["10.20.30.2/32"]));
    // Endpoint is echoed back in canonical SocketAddr form for the server to apply.
    assert_eq!(out["endpoint"], "203.0.113.45:51820");
    assert_eq!(out["message"], "ok");
}

#[test]
fn authorize_peer_endpoint_is_optional() {
    let proto = WireguardProtocol::new();
    let out = output_json(
        proto
            .execute_action(json!({
                "type": "authorize_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "allowed_ips": ["10.20.30.9/32"]
            }))
            .expect("authorize_peer without endpoint must succeed"),
    );
    assert_eq!(out["action"], "authorize_peer");
    assert!(
        out["endpoint"].is_null(),
        "omitted endpoint must serialize as null"
    );
    // Default message is applied when none is supplied.
    assert_eq!(out["message"], "Peer authorized");
}

#[test]
fn authorize_peer_rejects_missing_public_key() {
    let proto = WireguardProtocol::new();
    let err = proto
        .execute_action(json!({
            "type": "authorize_peer",
            "allowed_ips": ["10.20.30.2/32"]
        }))
        .expect_err("missing public_key must be an error, not a silent pass");
    assert!(
        err.to_string().contains("public_key"),
        "error should name the missing field, got: {err}"
    );
}

#[test]
fn authorize_peer_rejects_empty_allowed_ips() {
    let proto = WireguardProtocol::new();
    // An empty allowed_ips would configure a peer that can route nothing; the
    // executor must refuse it rather than push a useless peer to the interface.
    let err = proto
        .execute_action(json!({
            "type": "authorize_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": []
        }))
        .expect_err("empty allowed_ips must be an error");
    assert!(
        err.to_string().contains("allowed_ips"),
        "error should name allowed_ips, got: {err}"
    );
}

#[test]
fn authorize_peer_rejects_missing_allowed_ips() {
    let proto = WireguardProtocol::new();
    proto
        .execute_action(json!({
            "type": "authorize_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
        }))
        .expect_err("missing allowed_ips must be an error");
}

// ---------------------------------------------------------------------------
// disconnect_peer
// ---------------------------------------------------------------------------

#[test]
fn disconnect_peer_returns_structured_disconnect() {
    let proto = WireguardProtocol::new();
    let out = output_json(
        proto
            .execute_action(json!({
                "type": "disconnect_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "reason": "suspicious traffic"
            }))
            .expect("disconnect_peer with valid params must succeed"),
    );
    assert_eq!(out["action"], "disconnect_peer");
    assert_eq!(
        out["public_key"],
        "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
    );
    assert_eq!(out["reason"], "suspicious traffic");
}

#[test]
fn disconnect_peer_defaults_reason_and_requires_public_key() {
    let proto = WireguardProtocol::new();

    // Default reason when omitted.
    let out = output_json(
        proto
            .execute_action(json!({
                "type": "disconnect_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
            }))
            .expect("disconnect_peer without reason must succeed"),
    );
    assert_eq!(out["reason"], "Disconnected by admin");

    // But public_key is mandatory - there is nothing to disconnect without it.
    proto
        .execute_action(json!({ "type": "disconnect_peer" }))
        .expect_err("disconnect_peer without public_key must be an error");
}

// ---------------------------------------------------------------------------
// reject_peer / set_peer_traffic_limit (documented no-ops)
// ---------------------------------------------------------------------------

#[test]
fn reject_peer_is_a_noop_result() {
    // reject_peer's interface effect (peer removal) is applied by the server
    // loop, not the stateless executor; the executor itself is a NoAction. This
    // pins that documented behavior so it is not "fixed" into an Output later.
    let proto = WireguardProtocol::new();
    let result = proto
        .execute_action(json!({
            "type": "reject_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "reason": "unknown key"
        }))
        .expect("reject_peer must succeed");
    assert!(matches!(result, ActionResult::NoAction));
}

#[test]
fn set_peer_traffic_limit_is_unenforced_noop() {
    // set_peer_traffic_limit is documented as NOT enforced (no tc/iptables). It
    // must resolve to NoAction so nothing pretends a limit was applied.
    let proto = WireguardProtocol::new();
    let result = proto
        .execute_action(json!({
            "type": "set_peer_traffic_limit",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "limit_mbps": 100
        }))
        .expect("set_peer_traffic_limit must succeed");
    assert!(matches!(result, ActionResult::NoAction));
}

// ---------------------------------------------------------------------------
// dispatch errors
// ---------------------------------------------------------------------------

#[test]
fn unknown_action_is_rejected() {
    let proto = WireguardProtocol::new();
    proto
        .execute_action(json!({ "type": "not_a_real_action" }))
        .expect_err("unknown action type must error");
}

#[test]
fn missing_type_is_rejected() {
    let proto = WireguardProtocol::new();
    proto
        .execute_action(json!({ "public_key": "x" }))
        .expect_err("action without a 'type' must error");
}

// ---------------------------------------------------------------------------
// event / action declaration integrity
//
// call_llm builds the model's tool list from EventType.actions, NOT from
// get_sync_actions(). These tests guard that the peer-connected event advertises
// exactly the interface-changing actions and does not advertise the unenforced
// traffic-limit no-op (which would promise enforcement that never happens).
// ---------------------------------------------------------------------------

#[test]
fn peer_connected_event_advertises_the_interface_changing_actions() {
    let action_names: Vec<&str> = WIREGUARD_PEER_CONNECTED_EVENT
        .actions
        .iter()
        .map(|a| a.name.as_str())
        .collect();

    assert!(
        action_names.contains(&"authorize_peer"),
        "peer_connected must offer authorize_peer, got {action_names:?}"
    );
    assert!(
        action_names.contains(&"reject_peer"),
        "peer_connected must offer reject_peer, got {action_names:?}"
    );
    assert!(
        action_names.contains(&"disconnect_peer"),
        "peer_connected must offer disconnect_peer, got {action_names:?}"
    );
    // The unenforced no-op must NOT be advertised on the event.
    assert!(
        !action_names.contains(&"set_peer_traffic_limit"),
        "set_peer_traffic_limit is unenforced and must not be advertised, got {action_names:?}"
    );
}

#[test]
fn protocol_advertises_wireguard_add_peer_as_the_only_async_action() {
    // get_async_actions() now advertises exactly `wireguard_add_peer`: the
    // user-triggered action that PRE-adds a peer's public key so a subsequent
    // handshake is accepted and wireguard_peer_connected becomes reachable. This
    // is the fix for caveat (1) - the reactive-only authorize flow being
    // unreachable for a genuinely new peer. `list_peers` / `remove_peer` /
    // `get_server_info` remain unadvertised (they were dead no-ops).
    let proto = WireguardProtocol::new();
    let state = ::netget::state::app_state::AppState::new();
    let names: Vec<String> = proto
        .get_async_actions(&state)
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert_eq!(
        names,
        vec!["wireguard_add_peer".to_string()],
        "WireGuard must advertise exactly wireguard_add_peer as its async action, got {names:?}"
    );
}

#[test]
fn metadata_is_experimental_until_a_real_peer_handshakes() {
    use ::netget::protocol::metadata::DevelopmentState;
    // This assertion used to demand Beta, on the reasoning that Stable requires validation
    // against a real client and that has never happened here. The reasoning is right and it
    // proves more than it was used for: Beta is defined as "human-reviewed, works against real
    // clients", so the very same missing evidence rules Beta out as well.
    //
    // Nothing has completed a handshake against this server. `boringtun` was evaluated as an
    // in-test peer and deliberately not adopted, and the only root-gated harness is #[ignore]d
    // and asserts on NetGet's own log line rather than on peer behaviour. NetGet also
    // implements none of the WireGuard protocol itself and cannot bring an interface up on
    // macOS without an external wireguard-go binary.
    //
    // When a real peer does complete a real exchange, raise this and the metadata together.
    let proto = WireguardProtocol::new();
    assert_eq!(
        proto.metadata().state,
        DevelopmentState::Experimental,
        "WireGuard must stay Experimental until a real peer completes a handshake against it"
    );
}

// ---------------------------------------------------------------------------
// wireguard_add_peer: the pre-authorization action that makes the flow reachable
//
// The config-mutation logic (`build_peer_config`) is a pure function so it can be
// tested with no root and no WireGuard backend: it is exactly what add_peer feeds
// to `configure_peer`, so validating it validates the key + allowed-ips that would
// be pushed to the interface, and its fail-closed rejection of a malformed key.
// ---------------------------------------------------------------------------

#[test]
fn build_peer_config_accepts_valid_key_and_ips() {
    use ::netget::server::wireguard::build_peer_config;
    let key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    let peer = build_peer_config(
        key,
        &["10.20.30.2/32".to_string(), "10.20.30.3/32".to_string()],
        Some("203.0.113.45:51820".parse().unwrap()),
    )
    .expect("valid key + ips must build a peer config");

    // The peer pushed to configure_peer carries exactly the requested key, IPs and
    // endpoint - i.e. add_peer would authorize precisely this key.
    assert_eq!(peer.public_key.to_string(), key);
    let ips: Vec<String> = peer.allowed_ips.iter().map(|m| m.to_string()).collect();
    assert_eq!(ips, vec!["10.20.30.2/32", "10.20.30.3/32"]);
    assert_eq!(
        peer.endpoint.map(|e| e.to_string()),
        Some("203.0.113.45:51820".to_string())
    );
}

#[test]
fn build_peer_config_rejects_malformed_key() {
    use ::netget::server::wireguard::build_peer_config;
    // A malformed public key must fail-closed rather than configure a garbage peer.
    let err = build_peer_config(
        "not-a-valid-wireguard-key",
        &["10.20.30.2/32".to_string()],
        None,
    )
    .expect_err("malformed public key must be rejected");
    assert!(
        err.to_string().to_lowercase().contains("public key"),
        "error should name the public key, got: {err}"
    );
}

#[test]
fn build_peer_config_rejects_empty_and_malformed_allowed_ips() {
    use ::netget::server::wireguard::build_peer_config;
    let key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    // Empty allowed_ips: a peer that can route nothing must be refused.
    let err = build_peer_config(key, &[], None).expect_err("empty allowed_ips must be rejected");
    assert!(
        err.to_string().contains("allowed_ips"),
        "error should name allowed_ips, got: {err}"
    );

    // A malformed CIDR must fail the whole request rather than being silently
    // dropped, which would configure fewer routes than the operator asked for.
    let err = build_peer_config(key, &["not-a-cidr".to_string()], None)
        .expect_err("malformed allowed IP must be rejected");
    assert!(
        err.to_string().contains("Invalid allowed IP"),
        "error should name the bad IP, got: {err}"
    );
}

#[tokio::test]
async fn add_peer_action_is_declared_and_documented() {
    // The async action the model is offered must exist and require the two fields
    // add_peer needs. This is what makes the authorize decision reachable up front.
    let proto = WireguardProtocol::new();
    let state = ::netget::state::app_state::AppState::new();
    let def = proto
        .get_async_actions(&state)
        .into_iter()
        .find(|a| a.name == "wireguard_add_peer")
        .expect("wireguard_add_peer must be advertised");

    let required: Vec<&str> = def
        .parameters
        .iter()
        .filter(|p| p.required)
        .map(|p| p.name.as_str())
        .collect();
    assert!(
        required.contains(&"public_key"),
        "public_key must be required"
    );
    assert!(
        required.contains(&"allowed_ips"),
        "allowed_ips must be required"
    );
}

#[tokio::test]
async fn add_peer_via_stateless_execute_action_errors_without_server() {
    // Dispatched on the stateless protocol struct (no server context), the action
    // must NOT silently succeed - there is no interface to configure.
    let proto = WireguardProtocol::new();
    proto
        .execute_action(json!({
            "type": "wireguard_add_peer",
            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "allowed_ips": ["10.20.30.2/32"]
        }))
        .expect_err("wireguard_add_peer without a running server must error, not no-op");
}

#[tokio::test]
async fn add_peer_via_state_fails_closed_without_server_id() {
    // execute_action_with_state with no server_id must fail-closed: no server to
    // reach, so no peer is added. A missing authorization must never become an
    // accept-all.
    let proto = WireguardProtocol::new();
    let state = ::netget::state::app_state::AppState::new();
    let err = proto
        .execute_action_with_state(
            json!({
                "type": "wireguard_add_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "allowed_ips": ["10.20.30.2/32"]
            }),
            state,
            None,
        )
        .await
        .expect_err("wireguard_add_peer with no server id must fail-closed");
    assert!(
        err.to_string().contains("server"),
        "error should explain the missing server context, got: {err}"
    );
}

#[tokio::test]
async fn add_peer_via_state_rejects_empty_allowed_ips_before_touching_server() {
    // Validation happens before the server lookup, so a request that can route
    // nothing is refused rather than reaching the interface. Fail-closed input.
    let proto = WireguardProtocol::new();
    let state = ::netget::state::app_state::AppState::new();
    let err = proto
        .execute_action_with_state(
            json!({
                "type": "wireguard_add_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "allowed_ips": []
            }),
            state,
            None,
        )
        .await
        .expect_err("empty allowed_ips must be rejected");
    assert!(
        err.to_string().contains("allowed_ips"),
        "error should name allowed_ips, got: {err}"
    );
}

#[tokio::test]
async fn execute_action_with_state_delegates_non_add_peer_actions() {
    // Sync actions carry no live-state needs, so the override must forward them to
    // the stateless executor verbatim (here: disconnect_peer -> structured Output).
    let proto = WireguardProtocol::new();
    let state = ::netget::state::app_state::AppState::new();
    let result = proto
        .execute_action_with_state(
            json!({
                "type": "disconnect_peer",
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "reason": "test"
            }),
            state,
            None,
        )
        .await
        .expect("disconnect_peer must be delegated and succeed");
    let out = output_json(result);
    assert_eq!(out["action"], "disconnect_peer");
}

// ---------------------------------------------------------------------------
// Root-gated real-backend harness.
//
// This is the ONLY path that could exercise a real handshake, and it needs root
// plus a WireGuard backend (the kernel module, or the external `wireguard-go`
// binary on macOS). It is #[ignore]d so the normal suite never runs it, and when
// run with `--ignored` it FAILS LOUDLY if the interface cannot be created - it
// never skips-as-pass. That is deliberate: a green tick here must mean the real
// backend actually came up, not that the test quietly gave up.
//
// NOTE for whoever runs this with privilege: the reactive-only gap is now closed
// by `wireguard_add_peer` - pre-authorize the initiator's static public key first
// (a WireGuard responder drops a handshake from an unconfigured key), then a real
// client's handshake will be accepted and `wireguard_peer_connected` will fire.
// Earning Stable requires driving that end to end and then asserting: the handshake
// response message, that a transport data packet authenticates and decrypts to the
// expected plaintext, and that a forged/replayed packet is rejected. A `boringtun`
// in-process initiator is the recommended driver for that work.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "Requires root + a WireGuard backend (kernel, or wireguard-go on macOS). \
             Run explicitly with --ignored under privilege; fails loudly otherwise."]
async fn test_wireguard_real_backend_startup() -> E2EResult<()> {
    // Drive NetGet's real spawn path (which internally uses defguard's backend)
    // and require that the interface actually comes up. Without root and/or a
    // backend, `create_interface` fails, NetGet's spawn returns Err, and
    // server_startup reports an error - which we detect and PANIC on. This never
    // skips-as-pass: it returns Ok only after confirming the real interface was
    // created.
    let config = NetGetConfig::new("Start a WireGuard VPN server on port 0").with_mock(|mock| {
        mock.on_instruction_containing("WireGuard")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "wireguard",
                    "instruction": "Accept VPN clients"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    // The server subprocess logs "Interface created successfully" only when the
    // real backend brought the interface up. Anything else is a hard failure.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let created = server
        .output_contains("Interface created successfully")
        .await;
    let failed = server
        .output_contains("Failed to create WireGuard interface")
        .await
        || server
            .output_contains("Failed to create WireGuard API")
            .await;

    if !created || failed {
        let out = server.get_output().await;
        server.stop().await.ok();
        panic!(
            "WireGuard interface did not come up. This test requires root and a WireGuard \
             backend (on macOS, the external `wireguard-go` binary in PATH). It fails rather \
             than skipping.\n--- server output ---\n{}",
            out.join("\n")
        );
    }

    println!("✓ WireGuard interface created via the real backend");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
