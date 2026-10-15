//! What `SshAgentProtocol::execute_action` turns the model's answer into.
//!
//! Both of this protocol's model-facing hex examples were **wrong**, and had been for as long
//! as they existed: `send_identities_list` advertised a key blob declaring 32 bytes of
//! ed25519 public key and then supplying three, and `send_sign_response` advertised a
//! signature blob declaring 64 bytes and supplying four. A client reading either walks off the
//! end of the blob. Nothing caught it because nothing proofreads hex — which is the argument
//! `tests/example_hex_drift_test.rs` makes, and this file is the other half of the repair:
//! the model now names the algorithm, or pastes an authorized_keys line, and the server builds
//! the framing.
//!
//! These are pure `Value -> ActionResult` assertions. No socket, no LLM, no privilege.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh-agent \
//!       --test server -- server::ssh_agent::executor --test-threads=100

#![cfg(unix)]

use netget::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use netget::server::ssh_agent::actions::SshAgentProtocol;

/// A real 51-byte ed25519 blob: string("ssh-ed25519") || string(32-byte key).
const PUBLIC_KEY_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH98ewNgR4yzG9S6UrA3P6sN2mFMedO/XrRqPcibUAfr";

fn custom(action: serde_json::Value) -> serde_json::Value {
    match SshAgentProtocol::new()
        .execute_action(action.clone())
        .unwrap_or_else(|e| panic!("executor refused {action}: {e:#}"))
    {
        ActionResult::Custom { data, .. } => data,
        other => panic!("expected Custom from {action}, got {other:?}"),
    }
}

fn refusal(action: serde_json::Value) -> String {
    format!(
        "{:#}",
        SshAgentProtocol::new()
            .execute_action(action.clone())
            .err()
            .unwrap_or_else(|| panic!("{action} was accepted; it must be refused"))
    )
}

/// An authorized_keys line becomes the wire blob, with the length prefixes intact.
#[test]
fn an_openssh_public_key_line_becomes_the_wire_blob() {
    let data = custom(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{"public_key": PUBLIC_KEY_LINE, "comment": "deploy-key"}]
    }));
    let identity = &data["identities"][0];
    assert_eq!(identity["comment"], "deploy-key");

    let blob = hex::decode(identity["public_key_blob_hex"].as_str().unwrap()).unwrap();
    assert_eq!(blob.len(), 51, "4 + 11 + 4 + 32");
    assert_eq!(&blob[0..4], &11u32.to_be_bytes(), "algorithm name length");
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(
        &blob[15..19],
        &32u32.to_be_bytes(),
        "the declared key length..."
    );
    assert_eq!(
        blob.len() - 19,
        32,
        "...and the bytes actually there. The old hex example declared 32 and supplied 3."
    );
}

/// The comment in the line is used when the identity does not give one.
#[test]
fn the_comment_in_the_line_is_a_fallback_not_an_override() {
    let with_line_comment = custom(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{"public_key": format!("{PUBLIC_KEY_LINE} from-the-line")}]
    }));
    assert_eq!(
        with_line_comment["identities"][0]["comment"],
        "from-the-line"
    );

    let explicit = custom(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{
            "public_key": format!("{PUBLIC_KEY_LINE} from-the-line"),
            "comment": "explicit"
        }]
    }));
    assert_eq!(
        explicit["identities"][0]["comment"], "explicit",
        "'comment' is what `ssh-add -l` prints, so it wins"
    );
}

/// A truncated blob is refused rather than sent.
///
/// This is precisely the defect the advertised example carried: length prefixes that promise
/// more bytes than the blob holds. `ssh_fields_span_exactly` is the whole check.
#[test]
fn a_truncated_key_blob_is_refused() {
    // string("ssh-ed25519") || u32(32) || three bytes — the old example, base64'd.
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&11u32.to_be_bytes());
    truncated.extend_from_slice(b"ssh-ed25519");
    truncated.extend_from_slice(&32u32.to_be_bytes());
    truncated.extend_from_slice(&[0xe5, 0xa1, 0xb3]);
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&truncated);

    let err = refusal(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{"public_key": format!("ssh-ed25519 {encoded}"), "comment": "x"}]
    }));
    assert!(
        err.contains("truncated"),
        "the error must name the defect, got {err}"
    );
}

/// A line whose word disagrees with the blob's own algorithm name is refused.
#[test]
fn a_mislabelled_public_key_is_refused() {
    let err = refusal(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{
            "public_key": PUBLIC_KEY_LINE.replace("ssh-ed25519 ", "ssh-rsa "),
            "comment": "x"
        }]
    }));
    assert!(err.contains("ssh-ed25519"), "got {err}");
}

/// Neither spelling, and both spellings, are errors — never resolved by picking one.
#[test]
fn an_identity_needs_exactly_one_spelling_of_its_key() {
    assert!(refusal(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{"comment": "no key at all"}]
    }))
    .contains("public_key"));

    assert!(refusal(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{
            "public_key": PUBLIC_KEY_LINE,
            "public_key_blob_hex": "0000000b7373682d6564323535313900000020aabbccdd",
            "comment": "both"
        }]
    }))
    .contains("both"));
}

/// The hex escape hatch still means "these exact bytes", for a blob with no text form.
#[test]
fn the_key_blob_hex_escape_hatch_is_passed_through() {
    let data = custom(serde_json::json!({
        "type": "send_identities_list",
        "identities": [{"public_key_blob_hex": "0000000b7373682d6564323535313900000020aabbccdd", "comment": "raw"}]
    }));
    assert_eq!(
        data["identities"][0]["public_key_blob_hex"],
        "0000000b7373682d6564323535313900000020aabbccdd"
    );
}

/// An empty identity list is a valid answer and must stay one — it is what `ssh-add -l`
/// reports as "no identities".
#[test]
fn an_empty_identity_list_is_still_valid() {
    let data = custom(serde_json::json!({"type": "send_identities_list", "identities": []}));
    assert_eq!(data["identities"].as_array().unwrap().len(), 0);
}

/// Naming the algorithm produces a correctly framed signature of the right size.
#[test]
fn naming_the_algorithm_frames_a_correctly_sized_signature() {
    let data = custom(serde_json::json!({
        "type": "send_sign_response",
        "algorithm": "ssh-ed25519"
    }));
    let blob = hex::decode(data["signature_hex"].as_str().unwrap()).unwrap();

    assert_eq!(&blob[0..4], &11u32.to_be_bytes());
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    let declared = u32::from_be_bytes([blob[15], blob[16], blob[17], blob[18]]) as usize;
    assert_eq!(declared, 64, "an ed25519 signature is 64 bytes");
    assert_eq!(
        blob.len() - 19,
        declared,
        "the declared length must equal the bytes present — the old example declared 64 and \
         supplied 4"
    );
}

/// Raw signature bytes go inside the framing the algorithm builds, not beside it.
#[test]
fn explicit_signature_bytes_are_framed_not_replaced() {
    let data = custom(serde_json::json!({
        "type": "send_sign_response",
        "algorithm": "ssh-ed25519",
        "signature_bytes_hex": "aabbccdd"
    }));
    let blob = hex::decode(data["signature_hex"].as_str().unwrap()).unwrap();
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &4u32.to_be_bytes());
    assert_eq!(&blob[19..], &[0xaa, 0xbb, 0xcc, 0xdd]);
}

/// An algorithm with no known signature size is refused rather than guessed at.
#[test]
fn an_unknown_algorithm_with_nothing_to_frame_is_refused() {
    let err = refusal(serde_json::json!({
        "type": "send_sign_response",
        "algorithm": "ecdsa-sha2-nistp256"
    }));
    assert!(
        err.contains("signature_bytes_hex"),
        "the error must say what would make it work, got {err}"
    );
}

/// The framed-blob escape hatch still works, and both spellings at once do not.
#[test]
fn the_signature_hex_escape_hatch_is_passed_through_and_never_combined() {
    let data = custom(serde_json::json!({
        "type": "send_sign_response",
        "signature_hex": "0000000b7373682d65643235353139000000040a1b2c3d"
    }));
    assert_eq!(
        data["signature_hex"], "0000000b7373682d65643235353139000000040a1b2c3d",
        "bytes the caller supplied reach the wire unchanged"
    );

    assert!(refusal(serde_json::json!({
        "type": "send_sign_response",
        "algorithm": "ssh-ed25519",
        "signature_hex": "0000000b7373682d65643235353139000000040a1b2c3d"
    }))
    .contains("not both"));

    assert!(refusal(serde_json::json!({"type": "send_sign_response"})).contains("algorithm"));
    assert!(refusal(serde_json::json!({
        "type": "send_sign_response",
        "signature_hex": "zznothex"
    }))
    .contains("hex"));
}

/// Every advertised example is accepted by its own executor.
///
/// `tests/executable_examples_test.rs` covers this tree-wide; asserting it here means a change
/// to SSH Agent's own examples fails SSH Agent's own suite.
#[test]
fn every_advertised_example_is_accepted_by_its_own_executor() {
    let protocol = SshAgentProtocol::new();
    for action in protocol.get_sync_actions() {
        if action.name == "wait_for_more" || action.name == "close_connection" {
            continue; // not Custom results; covered by the e2e suite
        }
        protocol
            .execute_action(action.example.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "the advertised example for {} is refused by its own executor: {e:#}\n{}",
                    action.name, action.example
                )
            });
    }
}
