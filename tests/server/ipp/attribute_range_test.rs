//! A model-supplied attribute number narrowed with `as i32` went out as a different number.
//!
//! The sibling of `status_range_test.rs`, one layer down. `http_status` was the code the model
//! *chose*; this is every integer it puts in an attribute group — `job-id`, `job-k-octets`,
//! `printer-up-time`, `queued-job-count` — and the encoder read them with
//! `n.as_i64().unwrap_or(0) as i32`.
//!
//! `4294967296 as i32` is **0**, and `job-id: 0` is not a job the model was talking about; the
//! client reads a well-formed response about a different job and has no way to know. There is
//! no wrapping variant here that flips a refusal into a success the way LDAP's `256 as u8 → 0`
//! did, but the silence is the same and so is the fix: refuse while the original value is still
//! visible, because after the cast there is nothing left to check.
//!
//! A non-integral number is refused for a related reason — IPP's `integer` syntax has no
//! fractional form, and `as_i64().unwrap_or(0)` turned `1.5` into `0` rather than saying so.
//!
//! The length bound is the same class in the other direction: IPP's `value-length` is two
//! bytes, and the encoder clamped to `u16::MAX` and wrote a message *declaring* the truncated
//! length. Self-consistent, parseable, and not what the model said.

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::ipp::actions::IppProtocol;
use serde_json::json;

/// The encoded IPP body, or `None` if the executor refused the action.
fn encode(action: serde_json::Value) -> Option<Vec<u8>> {
    match IppProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => {
            let hex = data["body_hex"].as_str().expect("body_hex").to_string();
            Some(hex::decode(hex).expect("the executor's own hex must decode"))
        }
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn an_integer_outside_ipp_range_is_refused_not_wrapped() {
    for action in ["ipp_printer_attributes", "ipp_job_attributes"] {
        for bad in [
            4_294_967_296i64, // -> 0
            2_147_483_648,    // i32::MAX + 1 -> i32::MIN
            -2_147_483_649,
            i64::MAX,
            i64::MIN,
        ] {
            assert!(
                encode(json!({"type": action, "attributes": {"job-id": bad}})).is_none(),
                "{action}: job-id {bad} must be refused; `as i32` rewrites it silently"
            );
        }

        // Inside the range, the number must still be encoded, and encoded as itself.
        let body = encode(json!({"type": action, "attributes": {"job-id": 2_147_483_647i64}}))
            .unwrap_or_else(|| panic!("{action}: i32::MAX is a legal IPP integer"));
        assert!(
            body.windows(4).any(|w| w == 2_147_483_647i32.to_be_bytes()),
            "{action}: the boundary value must appear on the wire unchanged"
        );

        let body = encode(json!({"type": action, "attributes": {"job-id": -1}}))
            .unwrap_or_else(|| panic!("{action}: IPP integers are signed"));
        assert!(
            body.windows(4).any(|w| w == (-1i32).to_be_bytes()),
            "{action}: a negative integer must survive"
        );
    }
}

#[test]
fn an_out_of_range_integer_inside_an_array_is_refused_too() {
    // Multi-valued attributes are the easy place for a bound to be forgotten: the value the
    // encoder narrows is nested one level down from the one a naive check would look at.
    assert!(
        encode(json!({
            "type": "ipp_printer_attributes",
            "attributes": {"operations-supported": [2, 4, 4_294_967_296i64]}
        }))
        .is_none(),
        "an out-of-range value in the middle of a set must be refused like any other"
    );
    assert!(
        encode(json!({
            "type": "ipp_printer_attributes",
            "attributes": {"operations-supported": [2, 4, 11]}
        }))
        .is_some(),
        "a legal set must still encode"
    );
}

#[test]
fn a_fractional_number_is_refused_rather_than_becoming_zero() {
    assert!(
        encode(json!({"type": "ipp_job_attributes", "attributes": {"job-id": 1.5}})).is_none(),
        "IPP's integer syntax has no fractional form; `as_i64().unwrap_or(0)` made this 0"
    );
}

#[test]
fn a_value_too_long_for_ipps_length_field_is_refused_not_truncated() {
    let huge = "x".repeat(u16::MAX as usize + 1);
    assert!(
        encode(json!({"type": "ipp_printer_attributes", "attributes": {"printer-info": huge}}))
            .is_none(),
        "IPP's value-length is two bytes; clamping to 65535 writes a message that declares a \
         length the model never asked for"
    );

    // Exactly at the bound is representable and must still work.
    let at_bound = "x".repeat(u16::MAX as usize);
    assert!(
        encode(json!({"type": "ipp_printer_attributes", "attributes": {"printer-info": at_bound}}))
            .is_some(),
        "65535 bytes is the largest value IPP can express, and it is legal"
    );
}

#[test]
fn ordinary_attributes_still_encode() {
    // The refusals above must not have become a refusal of everything. This is the shipped
    // startup example, and it has to survive.
    let body = encode(json!({
        "type": "ipp_printer_attributes",
        "attributes": {
            "printer-name": "NetGet Printer",
            "printer-state": "idle",
            "printer-is-accepting-jobs": true,
            "queued-job-count": 0,
            "printer-uri-supported": ["ipp://localhost:631/printers/p1"]
        }
    }))
    .expect("the documented example must encode");
    assert!(
        body.windows(14).any(|w| w == b"NetGet Printer"),
        "the printer name must reach the wire"
    );
}
