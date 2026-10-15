//! What `send_rip_response` / `send_rip_request` accept must match what their descriptions
//! promise, and a field that will not fit its wire slot must be refused rather than truncated.
//!
//! The model copies the parameter description verbatim, so a description saying "metric 1-15"
//! over an executor that accepted 300 (and put `300` on the wire as a 32-bit metric, which no
//! RIP implementation treats as anything but unreachable) is a defect in the model-facing
//! surface even though nothing panics.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rip --test server -- rip::action_validation --test-threads=100

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::rip::actions::RipProtocol;
use serde_json::json;

fn route(metric: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "send_rip_response",
        "routes": [{
            "ip_address": "192.168.1.0",
            "subnet_mask": "255.255.255.0",
            "next_hop": "0.0.0.0",
            "metric": metric
        }]
    })
}

#[test]
fn a_response_encodes_the_metric_the_model_asked_for() {
    let protocol = RipProtocol::new();

    // RFC 2453 §3.4.2: 1-15 reachable, 16 = infinity (withdraw the route). Both ends of the
    // range must survive, because 16 is how a model retracts an advertisement.
    for metric in [1u32, 15, 16] {
        let result = protocol
            .execute_action(route(json!(metric)))
            .unwrap_or_else(|e| panic!("metric {metric} should be accepted: {e}"));
        let ActionResult::Output(packet) = result else {
            panic!("send_rip_response should produce a datagram");
        };
        assert_eq!(packet.len(), 24, "4-byte header + one 20-byte route entry");
        assert_eq!(packet[0], 2, "command should be Response(2)");
        assert_eq!(packet[1], 2, "version should be RIPv2");
        assert_eq!(
            u32::from_be_bytes([packet[20], packet[21], packet[22], packet[23]]),
            metric,
            "the metric on the wire must be the one the model asked for"
        );
    }
}

#[test]
fn a_metric_outside_the_ripv2_range_is_refused_not_truncated() {
    let protocol = RipProtocol::new();

    // 0 is not a legal distance; anything past 16 has no meaning; and the last two used to be
    // silently wrapped by an `as u32` cast into a value that looked legitimate.
    for metric in [0u64, 17, 300, u32::MAX as u64 + 1, u64::MAX] {
        let err = protocol
            .execute_action(route(json!(metric)))
            .expect_err(&format!("metric {metric} should be refused"));
        assert!(
            err.to_string().contains("metric"),
            "the refusal should name the field, got: {err}"
        );
    }
}

#[test]
fn a_route_tag_that_does_not_fit_sixteen_bits_is_refused() {
    let protocol = RipProtocol::new();

    let ok = protocol.execute_action(json!({
        "type": "send_rip_response",
        "routes": [{"ip_address": "10.0.0.0", "metric": 1, "route_tag": 65535}]
    }));
    assert!(ok.is_ok(), "65535 is the largest legal route tag: {ok:?}");

    let err = protocol
        .execute_action(json!({
            "type": "send_rip_response",
            "routes": [{"ip_address": "10.0.0.0", "metric": 1, "route_tag": 65536}]
        }))
        .expect_err("route_tag 65536 does not fit the 2-byte wire field");
    assert!(
        err.to_string().contains("route_tag"),
        "the refusal should name the field, got: {err}"
    );
}

#[test]
fn both_directions_hold_the_same_twenty_five_entry_ceiling() {
    let protocol = RipProtocol::new();

    // RFC 2453 §3.6 sizes a RIP datagram at 4 + 25*20 = 504 bytes. The Response path checked
    // this and the Request path did not, so a Request could be built oversize.
    let many: Vec<serde_json::Value> = (0..26)
        .map(|i| json!({"ip_address": format!("10.0.{i}.0"), "metric": 1}))
        .collect();

    for action_type in ["send_rip_response", "send_rip_request"] {
        let err = protocol
            .execute_action(json!({"type": action_type, "routes": many}))
            .unwrap_err();
        assert!(
            err.to_string().contains("Too many routes"),
            "{action_type} should cap at 25 entries, got: {err}"
        );
    }

    // 25 is still fine on both.
    let exactly_25: Vec<serde_json::Value> = (0..25)
        .map(|i| json!({"ip_address": format!("10.0.{i}.0"), "metric": 1}))
        .collect();
    for action_type in ["send_rip_response", "send_rip_request"] {
        assert!(
            protocol
                .execute_action(json!({"type": action_type, "routes": exactly_25.clone()}))
                .is_ok(),
            "{action_type} should accept exactly 25 entries"
        );
    }
}

#[test]
fn a_request_with_no_routes_asks_for_the_whole_table() {
    let protocol = RipProtocol::new();

    let ActionResult::Output(packet) = protocol
        .execute_action(json!({"type": "send_rip_request"}))
        .expect("the declared example omits `routes`")
    else {
        panic!("send_rip_request should produce a datagram");
    };

    // RFC 2453 §3.9.1: a single entry with AFI 0 and metric 16 means "send me everything".
    assert_eq!(packet.len(), 24);
    assert_eq!(packet[0], 1, "command should be Request(1)");
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0, "AFI 0");
    assert_eq!(
        u32::from_be_bytes([packet[20], packet[21], packet[22], packet[23]]),
        16,
        "metric 16"
    );
}
