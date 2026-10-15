//! A model-supplied `target_port` narrowed with `as u16` tunnelled somewhere else.
//!
//! `66079 as u16` is `543`. `establish_tunnel` is how the model names where the CONNECT
//! should go, so the wrap sent the tunnel to a *different service on the same host* than the
//! one it asked for — quietly, with every log line downstream naming the port it ended up at
//! rather than the one it was given.
//!
//! This is the client-side form of the fail-open class: nothing reports an error, the tunnel
//! is established, and it is established to the wrong place. A client that loses its target
//! must fail rather than pick one.

#![cfg(unix)]

use netget::client::http_proxy::actions::HttpProxyClientProtocol;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match HttpProxyClientProtocol::new().execute_action(action) {
        Ok(ClientActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

fn tunnel_to(port: serde_json::Value) -> serde_json::Value {
    json!({"type": "establish_tunnel", "target_host": "example.com", "target_port": port})
}

#[test]
fn an_out_of_range_target_port_is_refused_not_wrapped() {
    // 66079 -> 543, 65536 -> 0, 65579 -> 43. Each is a real port somewhere else.
    for wrapping in [66079u64, 65536, 65579, 131072] {
        assert!(
            run(tunnel_to(json!(wrapping))).is_none(),
            "target_port {wrapping} must be refused: `as u16` makes it {}, so the tunnel \
             reaches a different service than the model named",
            wrapping % 65536
        );
    }
    // Port 0 is not a destination either.
    assert!(
        run(tunnel_to(json!(0))).is_none(),
        "target_port 0 is not a TCP port and must be refused"
    );

    // The refusal must not cost the legitimate call: both ends of the range still work and
    // reach the tunnel unchanged.
    for good in [1u64, 80, 443, 8443, 65535] {
        let data =
            run(tunnel_to(json!(good))).unwrap_or_else(|| panic!("{good} is a real TCP port"));
        assert_eq!(
            data["target_port"].as_u64(),
            Some(good),
            "target_port {good} must reach the tunnel unchanged, got {data}"
        );
        assert_eq!(data["target_host"].as_str(), Some("example.com"));
    }

    // An absent port stays an error rather than acquiring a default destination.
    assert!(
        run(json!({"type": "establish_tunnel", "target_host": "example.com"})).is_none(),
        "an absent target_port must stay an error"
    );
}
