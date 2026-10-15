//! A model-supplied `status_code` on `ollama_error_response` narrowed with `as u16`
//! delivered the refusal as a success.
//!
//! `model_error_response` reads the model's raw action and did
//! `StatusCode::from_u16(code as u16)`. `65736 as u16` is `200`, `from_u16(200)` succeeds,
//! and the client received HTTP 200 with a body that happens to carry an `error` key — which
//! every Ollama client reads as an answered request. The function's own doc comment says the
//! one distinction that has to survive is "a refusal and an outage must not be diagnosed as
//! each other"; arithmetic was quietly erasing a third one, refusal versus success.
//!
//! A 2xx is rejected even when written literally, for the same reason: this path only ever
//! builds refusals. An unusable value falls back to 400 rather than failing the request, so
//! the refusal itself always survives.

use netget::server::ollama::model_error_response as refusal;
use serde_json::json;

fn status_of(status_code: serde_json::Value) -> u16 {
    let action = json!({
        "type": "ollama_error_response",
        "error_message": "model 'gpt-4' is not served by this instance",
        "status_code": status_code,
    });
    refusal(&[action])
        .expect("an ollama_error_response action must always produce a refusal")
        .status()
        .as_u16()
}

#[test]
fn a_wrapping_status_does_not_become_a_success() {
    assert_eq!(
        status_of(json!(65736)),
        400,
        "65736 narrows to 200 under `as u16`, which would deliver the refusal as a success"
    );
    // 65536 + 201, 65536 + 204: every 2xx has a wrapping pre-image.
    assert_eq!(status_of(json!(65737)), 400);
    assert_eq!(status_of(json!(65740)), 400);
}

#[test]
fn a_literal_success_status_is_refused_too() {
    for success in [200, 201, 204, 299] {
        assert_eq!(
            status_of(json!(success)),
            400,
            "{success} is a success status; this action only ever builds refusals"
        );
    }
}

#[test]
fn out_of_range_and_nonsense_fall_back_to_400() {
    for bad in [
        json!(0),
        json!(99),
        json!(600),
        json!(1000),
        json!(-1),
        json!("404"),
        json!(null),
    ] {
        assert_eq!(
            status_of(bad.clone()),
            400,
            "{bad} is not a refusal status and must fall back to 400"
        );
    }
}

#[test]
fn real_refusal_statuses_reach_the_wire_unchanged() {
    for good in [400, 401, 403, 404, 413, 429, 500, 503] {
        assert_eq!(
            status_of(json!(good)),
            good,
            "{good} is a legitimate refusal status and must pass through"
        );
    }
}

#[test]
fn the_refusal_body_carries_the_models_message() {
    let action = json!({
        "type": "ollama_error_response",
        "error_message": "model 'gpt-4' is not served by this instance",
        "status_code": 404,
    });
    let response = refusal(&[action]).expect("a refusal must be produced");
    assert_eq!(response.status().as_u16(), 404);
}

#[test]
fn no_error_action_means_no_refusal() {
    let actions = vec![json!({"type": "ollama_chat_response", "message_content": "hi"})];
    assert!(
        refusal(&actions).is_none(),
        "only ollama_error_response builds a refusal; a success action must not"
    );
}
