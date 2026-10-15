//! A model-supplied `result_code` narrowed with `as u8` encoded LDAP *success*.
//!
//! The wrap lands on the worst possible value here. `256 as u8` is `0`, and resultCode `0` is
//! `success` — so every refusal the model can express sits a multiple of 256 away from a
//! directory telling the client the bind, the write or the search completed. Fail-open by
//! arithmetic, and silent: the encoder produced a perfectly well-formed success.
//!
//! `message_id` had the same shape through `as i32`. A client matches replies by messageID
//! alone, so `4294967297` becoming `1` answers whichever request happened to hold that id.
//!
//! # Why this compares encodings rather than decoding BER
//!
//! The responses are hand-rolled BER, so a test that re-implemented the decoder would agree
//! with the encoder about being wrong together. Asserting that the out-of-range value is
//! *refused*, and that it would otherwise have been byte-identical to the success encoding,
//! needs no decoder and holds however resultCode is framed. `fail_open_action_defaults_test`
//! makes the same argument for the sibling defect in these actions.

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::ldap::actions::LdapProtocol;
use serde_json::json;

/// The bytes the action encoded, or `None` if the executor refused it.
fn encoded(action: serde_json::Value) -> Option<Vec<u8>> {
    match LdapProtocol.execute_action(action) {
        Ok(ActionResult::Output(bytes)) => Some(bytes),
        Ok(other) => panic!("expected Output, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

/// The three write/read responses that take a model-supplied `result_code`.
/// (`ldap_bind_response` picks its own from `success` and is not in this class.)
const CODE_BEARING: [&str; 4] = [
    "ldap_search_response",
    "ldap_add_response",
    "ldap_modify_response",
    "ldap_delete_response",
];

fn base(action_type: &str, code: serde_json::Value) -> serde_json::Value {
    json!({
        "type": action_type,
        "message_id": 7,
        "result_code": code,
        "message": "",
        "dn": "cn=test,dc=example,dc=com",
        "entries": [],
    })
}

#[test]
fn a_result_code_past_255_must_not_encode_as_success() {
    for action_type in CODE_BEARING {
        // The success encoding is what the wrap produced, so it is the thing to be distinct
        // from. It must still be reachable: this test must not pass by refusing everything.
        let success = encoded(base(action_type, json!(0)))
            .unwrap_or_else(|| panic!("{action_type}: resultCode 0 must still encode"));

        for wrapping in [256u64, 512, 49 + 256, 65536] {
            let got = encoded(base(action_type, json!(wrapping)));
            assert!(
                got.is_none(),
                "{action_type}: result_code {wrapping} must be refused. `as u8` reduces it \
                 mod 256, and {} is what a client reads as the operation having succeeded.",
                wrapping % 256
            );
        }

        // Specifically: 256 must never become the success bytes.
        assert_ne!(
            encoded(base(action_type, json!(256))).unwrap_or_default(),
            success,
            "{action_type}: result_code 256 encoded exactly what resultCode 0 encodes — the \
             directory asserting the operation completed"
        );

        // A real refusal still works and is distinguishable from success.
        let refused = encoded(base(action_type, json!(49)))
            .unwrap_or_else(|| panic!("{action_type}: 49 (invalidCredentials) must encode"));
        assert_ne!(
            refused, success,
            "{action_type}: an explicit refusal must not encode as success"
        );
        // As does the far end of the byte the encoder writes.
        assert!(
            encoded(base(action_type, json!(255))).is_some(),
            "{action_type}: 255 fits the encoded ENUMERATED and must be accepted"
        );
    }
}

#[test]
fn an_out_of_range_message_id_is_refused() {
    // maxInt is 2147483647 (RFC 4511 §4.1.1). Past it, `as i32` wraps and the reply is
    // correlated with a request that asked something else.
    for action_type in [
        "ldap_bind_response",
        "ldap_search_response",
        "ldap_add_response",
        "ldap_modify_response",
        "ldap_delete_response",
    ] {
        let with = |id: i64| {
            let mut v = base(action_type, json!(0));
            v["message_id"] = json!(id);
            v
        };

        assert!(
            encoded(with(4294967297)).is_none(),
            "{action_type}: message_id 4294967297 must be refused; `as i32` makes it 1, so the \
             reply is matched to whichever request carried id 1"
        );
        assert!(
            encoded(with(-1)).is_none(),
            "{action_type}: a negative message_id is outside INTEGER (0 .. maxInt)"
        );
        assert!(
            encoded(with(2147483647)).is_some(),
            "{action_type}: maxInt itself is legal and must be accepted"
        );
    }
}
