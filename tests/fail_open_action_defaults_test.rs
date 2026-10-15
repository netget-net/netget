//! A forgotten field in an action must never be read as a successful outcome.
//!
//! # The bug class
//!
//! The dangerous shape here is not "the LLM was wrong", it is "the LLM said nothing about
//! this field and the executor supplied a success". OAuth2 was the reference case and is
//! fixed; these are the same shape found elsewhere, in the parameter defaults rather than in
//! the no-action branch:
//!
//! - `send_imap_response` defaulted `status` to `"OK"`. A tagged response with no status
//!   rendered `A001 OK`, and `handle_auth` reads a tagged OK as a successful LOGIN — so a
//!   dropped field authenticated the session. RFC 3501 §7.1 gives a tagged response no
//!   default condition.
//! - `ldap_add_response` / `ldap_modify_response` / `ldap_delete_response` defaulted
//!   `success` to `true`, which selects resultCode 0 — the directory telling the client the
//!   write landed. (`ldap_bind_response` was always correctly `false`; only the three write
//!   operations fell open.)
//!
//! # Why the LDAP assertions compare encodings instead of decoding BER
//!
//! The responses are hand-rolled BER, and a test that re-implements the decoder would pass
//! whenever the two implementations agreed on being wrong together. Comparing an omitted
//! field against both explicit spellings is stronger and needs no decoder: the omission must
//! encode byte-for-byte what an explicit failure encodes, and must differ from an explicit
//! success. That holds regardless of how resultCode is framed on the wire.

// Every user of these lives behind a feature gate, so a build with none of the protocols
// compiled in leaves them unused. That is a legitimate configuration, not a mistake.
#[allow(unused_imports)]
use netget::llm::actions::protocol_trait::{ActionResult, Server};
#[allow(unused_imports)]
use serde_json::json;

/// The bytes an action encodes, or `None` if the executor refused it.
#[allow(dead_code)]
fn encoded<P: Server>(protocol: &P, action: serde_json::Value) -> Option<Vec<u8>> {
    match protocol.execute_action(action) {
        Ok(ActionResult::Output(bytes)) => Some(bytes),
        Ok(other) => panic!("expected Output, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

mod ldap {
    use super::*;
    use netget::server::ldap::actions::LdapProtocol;

    /// `success` omitted must encode the failure, not the success.
    fn omission_is_not_success(action_type: &str, failure_code: u64) {
        let base = json!({
            "type": action_type,
            "message_id": 7,
            "message": "",
        });

        let mut omitted = base.clone();
        omitted["dn"] = json!("cn=test,dc=example,dc=com");

        let mut claimed = omitted.clone();
        claimed["success"] = json!(true);

        let mut refused = omitted.clone();
        refused["success"] = json!(false);

        let omitted = encoded(&LdapProtocol, omitted)
            .unwrap_or_else(|| panic!("{} with no `success` should still answer", action_type));
        let claimed = encoded(&LdapProtocol, claimed).expect("explicit success should answer");
        let refused = encoded(&LdapProtocol, refused).expect("explicit failure should answer");

        assert_ne!(
            omitted, claimed,
            "{}: omitting `success` encodes the same bytes as claiming success, so a model \
             that forgot the field told the client the write landed. resultCode 0 is a \
             statement about a directory that netget does not have.",
            action_type
        );
        assert_eq!(
            omitted, refused,
            "{}: omitting `success` must encode exactly what an explicit failure encodes \
             (resultCode {}), so there is one unambiguous meaning for a missing field.",
            action_type, failure_code
        );
    }

    #[test]
    fn add_response_does_not_succeed_by_omission() {
        omission_is_not_success("ldap_add_response", 68);
    }

    #[test]
    fn modify_response_does_not_succeed_by_omission() {
        omission_is_not_success("ldap_modify_response", 32);
    }

    #[test]
    fn delete_response_does_not_succeed_by_omission() {
        omission_is_not_success("ldap_delete_response", 32);
    }

    /// An explicit `result_code` is still authoritative on its own — the fix must not have
    /// made `success` mandatory for a model that names the code directly.
    #[test]
    fn an_explicit_result_code_still_wins_without_success() {
        let bytes = encoded(
            &LdapProtocol,
            json!({
                "type": "ldap_add_response",
                "message_id": 7,
                "dn": "cn=test,dc=example,dc=com",
                "result_code": 0,
                "message": "",
            }),
        )
        .expect("an explicit result_code should answer");

        let refused = encoded(
            &LdapProtocol,
            json!({
                "type": "ldap_add_response",
                "message_id": 7,
                "dn": "cn=test,dc=example,dc=com",
                "success": false,
                "message": "",
            }),
        )
        .expect("explicit failure should answer");

        assert_ne!(
            bytes, refused,
            "`result_code: 0` names the outcome outright and must still encode success; \
             defaulting `success` to false may not override an explicit code."
        );
    }
}

#[cfg(all(unix, feature = "bluetooth"))]
mod bluetooth_ble {
    use netget::server::bluetooth_ble::write_response_status;
    use serde_json::json;

    /// `respond_to_write` declares a `status` of 'success' or 'error'. Nothing read it: both
    /// consumption sites skip the action as "handled inline", and the inline handler answered
    /// ATT Success unconditionally — so a model rejecting a write was told the central it had
    /// been accepted. The Write Response is the only signal the central gets.
    #[test]
    fn an_explicit_error_status_refuses_the_write() {
        let refused = write_response_status(&[json!({
            "type": "respond_to_write",
            "status": "error"
        })]);

        assert!(
            matches!(
                refused,
                ble_peripheral_rust::gatt::peripheral_event::RequestResponse::UnlikelyError
            ),
            "a model answering status=\"error\" must refuse the write on the wire; \
             acknowledging it Success discards the decision entirely"
        );
    }

    /// Silence is still consent — most writes are accepted, and a handler that answered the
    /// event without naming a status has agreed to it. Only an explicit refusal refuses.
    #[test]
    fn success_and_omission_both_acknowledge() {
        for action in [
            json!({"type": "respond_to_write", "status": "success"}),
            json!({"type": "respond_to_write"}),
            json!({"type": "send_notification", "value": "0048"}),
        ] {
            assert!(
                matches!(
                    write_response_status(std::slice::from_ref(&action)),
                    ble_peripheral_rust::gatt::peripheral_event::RequestResponse::Success
                ),
                "{} should acknowledge the write",
                action
            );
        }
    }
}

mod imap {
    use super::*;
    use netget::server::imap::actions::ImapProtocol;

    #[test]
    fn a_tagged_response_without_a_status_is_refused() {
        let result = ImapProtocol.execute_action(json!({
            "type": "send_imap_response",
            "tag": "A001",
            "message": "LOGIN completed",
        }));

        let err = result.err().unwrap_or_else(|| {
            panic!(
                "send_imap_response with no `status` was accepted. It used to default to \
                 \"OK\", rendering `A001 OK` — which handle_auth reads as a successful LOGIN, \
                 so a dropped field authenticated the session."
            )
        });

        let message = err.to_string();
        assert!(
            message.contains("status"),
            "the refusal must name the missing field so the model can correct it, got: {}",
            message
        );
    }

    #[test]
    fn an_explicit_refusal_is_encoded_as_a_refusal() {
        let bytes = encoded(
            &ImapProtocol,
            json!({
                "type": "send_imap_response",
                "tag": "A001",
                "status": "NO",
                "message": "LOGIN failed",
            }),
        )
        .expect("an explicit NO should encode");

        let text = String::from_utf8(bytes).expect("IMAP responses are ASCII");
        assert!(
            text.starts_with("A001 NO"),
            "expected a tagged NO, got: {:?}",
            text
        );
        assert!(
            !text.contains("A001 OK"),
            "a refusal must not contain the tagged OK that marks a session authenticated, \
             got: {:?}",
            text
        );
    }
}
