//! A model-supplied JSON-RPC `code` narrowed with `as i32` reported a different fault.
//!
//! `as_i64()… as i32` wraps in silence. The interesting direction is not that the number
//! changes but *where it lands*: JSON-RPC reserves -32768..-32000 for protocol-level faults,
//! so a wrapped application code can arrive claiming to be a parse error or an invalid
//! request the server never had — and a client branching on the code handles it as such.
//!
//! `-32601 + 2^32` is the worked example: it is a perfectly ordinary integer in the model's
//! answer and becomes `-32601`, "method not found", on the wire.


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::mcp::actions::McpProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match McpProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

fn error_with(code: serde_json::Value) -> serde_json::Value {
    json!({"type": "mcp_error_response", "code": code, "message": "no such tool"})
}

#[test]
fn a_code_that_does_not_fit_i32_is_refused() {
    // Each of these narrows into the reserved band and would claim a transport fault.
    for wrapping in [4294934695i64, -4294934695, 4294967296, -4294967296] {
        assert!(
            run(error_with(json!(wrapping))).is_none(),
            "code {wrapping} must be refused: `as i32` makes it {}, which is a different \
             fault from the one the model reported",
            wrapping as i32
        );
    }
    for wrapping in [2147483648i64, -2147483649, i64::MAX, i64::MIN] {
        assert!(
            run(error_with(json!(wrapping))).is_none(),
            "code {wrapping} does not fit the 32-bit integer JSON-RPC uses"
        );
    }

    // The refusal must not have become a refusal of everything: the standard codes and an
    // application code still pass through unchanged.
    for good in [
        -32700i64,
        -32601,
        -32603,
        -32000,
        1,
        2147483647,
        -2147483648,
    ] {
        let data = run(error_with(json!(good)))
            .unwrap_or_else(|| panic!("{good} fits a 32-bit JSON-RPC code"));
        assert_eq!(
            data["code"].as_i64(),
            Some(good),
            "code {good} must reach the client unchanged, got {data}"
        );
    }

    // An absent code stays an error rather than acquiring a default.
    assert!(
        run(json!({"type": "mcp_error_response", "message": "no such tool"})).is_none(),
        "an absent code must stay an error"
    );
}
