//! A model-supplied RFB coordinate narrowed with `as u16` asked for a different rectangle.
//!
//! RFB carries x, y, width and height in two bytes each and the pointer button mask in one.
//! Every one of them was read as `data["x"].as_u64().unwrap_or(0) as u16`, so a number the
//! field cannot hold was silently rewritten rather than refused: **`65736` becomes `200`**,
//! `70000` becomes `4464`, and a button mask of `257` becomes `1`.
//!
//! Nothing anywhere recorded that the request differed from the answer. The client asked the
//! server for a region nobody named, the server answered that region, and the model saw a
//! plausible reply to a question it did not ask — the arithmetic fail-open
//! `tests/narrowing_cast_drift_test.rs` exists for, on the client side of the same protocol.
//!
//! These assert the **bytes on the wire**, not the guard helpers, because the guards being
//! correct and the guards being *wired in* are different claims and only the second one
//! matters.


use netget::client::vnc::VncClient;
use serde_json::json;

/// Run one action against an in-memory writer and return what it would have written.
async fn wire(action: &str, data: serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    VncClient::send_vnc_message_with_writer(&mut out, action, &data, 800, 600)
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tokio::test]
async fn an_out_of_range_coordinate_is_refused_not_wrapped() {
    for key in ["x", "y", "width", "height"] {
        for bad in [65536u64, 65736, 70000, u64::MAX] {
            let err = wire(
                "request_framebuffer_update",
                json!({ "incremental": false, key: bad }),
            )
            .await
            .expect_err(&format!(
                "{key}={bad} must be refused; `as u16` rewrites it into a rectangle nobody named"
            ));
            assert!(
                err.contains(key),
                "the error must name the field the model has to fix: {err}"
            );
        }
    }

    // 65736 is the case worth naming: it is 200 after the cast, a perfectly ordinary
    // coordinate, so nothing downstream could ever have noticed.
    let err = wire(
        "send_pointer_event",
        json!({ "x": 65736, "y": 0, "button_mask": 1 }),
    )
    .await
    .expect_err("65736 is 200 after `as u16` and must be refused");
    assert!(err.contains('x'), "{err}");
}

#[tokio::test]
async fn an_out_of_range_button_mask_is_refused() {
    let err = wire(
        "send_pointer_event",
        json!({ "x": 10, "y": 20, "button_mask": 257 }),
    )
    .await
    .expect_err("the RFB button mask is one byte; 257 is not button 1 again");
    assert!(err.contains("button_mask"), "{err}");
}

#[tokio::test]
async fn in_range_coordinates_still_reach_the_wire_unchanged() {
    // The refusals must not have become a refusal of everything, and the boundary value must
    // survive as itself — a guard that clamped would pass the tests above and fail this.
    let msg = wire(
        "request_framebuffer_update",
        json!({ "incremental": false, "x": 1, "y": 2, "width": 65535, "height": 600 }),
    )
    .await
    .expect("65535 is the largest extent RFB can express, and it is legal");

    assert_eq!(msg.len(), 10, "FramebufferUpdateRequest is 10 bytes");
    assert_eq!(msg[0], 3, "message type 3");
    assert_eq!(msg[1], 0, "incremental=false");
    assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "x");
    assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 2, "y");
    assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 65535, "width");
    assert_eq!(u16::from_be_bytes([msg[8], msg[9]]), 600, "height");

    let msg = wire(
        "send_pointer_event",
        json!({ "x": 300, "y": 400, "button_mask": 255 }),
    )
    .await
    .expect("every bit of the mask is legal");
    assert_eq!(msg.len(), 6, "PointerEvent is 6 bytes");
    assert_eq!(msg[0], 5);
    assert_eq!(msg[1], 255, "button mask");
    assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 300);
    assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 400);
}

#[tokio::test]
async fn omitted_coordinates_still_default_to_the_framebuffer() {
    // `width`/`height` default to the negotiated framebuffer size, which is the reason the
    // guard takes a default rather than requiring the field.
    let msg = wire("request_framebuffer_update", json!({ "incremental": true }))
        .await
        .expect("an incremental request naming nothing is the common case");
    assert_eq!(msg[1], 1, "incremental=true");
    assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 800, "width defaults");
    assert_eq!(u16::from_be_bytes([msg[8], msg[9]]), 600, "height defaults");
}
