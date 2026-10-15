//! A model-supplied `error_code` narrowed with `as i32` encoded ZooKeeper *success*.
//!
//! `4294967296 as i32` is `0`, and in this executor `is_error = error_code != 0` decides the
//! entire shape of the reply: at zero the refusal becomes a grant and a body is appended to
//! it. A model that meant NONODE or NOAUTH told the client the operation completed.
//!
//! `zookeeper_response` already refused an *absent* or non-integer `error_code` for exactly
//! this reason — but the guard asks whether the field is an integer, and `4294967296` is one.
//! It never asked whether the integer survived the narrowing.
//!
//! `xid` is the same cast on a correlation identifier. A client matches replies by xid alone,
//! so a wrapped one answers whichever request happened to carry the truncated value.


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::zookeeper::actions::ZookeeperProtocol;
use serde_json::json;

/// The `Custom` payload the executor built, or `None` if it refused the action.
fn run(action: serde_json::Value) -> Option<serde_json::Value> {
    match ZookeeperProtocol.execute_action(action) {
        Ok(ActionResult::Custom { data, .. }) => Some(data),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

fn response(error_code: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "zookeeper_response",
        "xid": 3,
        "zxid": 11,
        "error_code": error_code,
    })
}

#[test]
fn an_error_code_that_narrows_to_zero_is_refused() {
    // Each of these is `0` after `as i32` — which is ZooKeeper's OK.
    for wrapping in [4294967296i64, -4294967296, 8589934592] {
        assert!(
            run(response(json!(wrapping))).is_none(),
            "error_code {wrapping} must be refused: `as i32` makes it 0, `is_error` goes \
             false, and the model's refusal is encoded as the grant it was refusing"
        );
    }
    // And any other value that does not survive the narrowing, whatever it lands on.
    for wrapping in [2147483648i64, -2147483649, i64::MAX, i64::MIN] {
        assert!(
            run(response(json!(wrapping))).is_none(),
            "error_code {wrapping} does not fit a 32-bit wire integer and must be refused"
        );
    }

    // The refusal must not have become a refusal of everything: the real codes still work,
    // and an error still reads as an error.
    for code in [-101i64, -102, -110, -103] {
        let data = run(response(json!(code)))
            .unwrap_or_else(|| panic!("{code} is a real ZooKeeper error code"));
        assert_eq!(data["error_code"].as_i64(), Some(code));
        assert_eq!(
            data["body_hex"].as_str(),
            Some(""),
            "an error reply is header-only: {data}"
        );
    }
    // 0 is still a grant, and still reachable.
    let ok = run(response(json!(0))).expect("error_code 0 is a legitimate success");
    assert_eq!(ok["error_code"].as_i64(), Some(0));
}

#[test]
fn an_out_of_range_xid_is_refused() {
    // `4294967297 as i32` is 1: the reply would be matched to whichever request carried xid 1.
    let mut wrapped = response(json!(0));
    wrapped["xid"] = json!(4294967297i64);
    assert!(
        run(wrapped).is_none(),
        "xid 4294967297 must be refused; `as i32` makes it 1 and the reply is correlated with \
         a request that asked something else"
    );

    // Both ends of the real range still pass, and an omitted xid still defers to the
    // connection loop rather than being forced to 0.
    let mut edge = response(json!(0));
    edge["xid"] = json!(2147483647i64);
    assert_eq!(
        run(edge).expect("maxInt xid is legal")["xid"].as_i64(),
        Some(2147483647)
    );

    let mut absent = response(json!(0));
    absent.as_object_mut().unwrap().remove("xid");
    let data = run(absent).expect("an omitted xid must still answer");
    assert!(
        data["xid"].is_null(),
        "an omitted xid must stay absent so the connection loop can substitute the real one, \
         got {data}"
    );
}
