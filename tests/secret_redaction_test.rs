//! Credential-named values are redacted wherever NetGet echoes startup parameters or actions.
//!
//! `src/utils/redact.rs` is applied to the `open_client` / `open_server` summary on the status
//! stream and to the executor's per-action DEBUG line. The end-to-end check is in
//! `tests/client/radius/real_server_test.rs`, which asserts the RADIUS shared secret is absent
//! from everything NetGet printed; this file pins the function itself.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test secret_redaction_test

use netget::utils::redact::{redact_sensitive, REDACTED};
use serde_json::json;

#[test]
fn credential_named_keys_are_redacted_at_any_depth_and_nothing_else_is() {
    let shown = redact_sensitive(&json!({
        "secret": "testing123",
        "accounting_port": 1813,
        "nested": {"Bind_Password": "pw", "user": "alice", "list": [{"api_key": "k"}]},
        "shared_secret": null,
        "token": "startup-token",
        "auth": {"client_token": "returned-token", "token_type": "service", "token_policies": ["default"], "token_present": true}
    }));
    assert_eq!(shown["secret"], REDACTED);
    assert_eq!(shown["accounting_port"], 1813);
    assert_eq!(shown["nested"]["Bind_Password"], REDACTED);
    assert_eq!(shown["nested"]["user"], "alice");
    assert_eq!(shown["nested"]["list"][0]["api_key"], REDACTED);
    assert!(
        shown["shared_secret"].is_null(),
        "an absent value is not invented"
    );
    assert!(!shown.to_string().contains("testing123"));
    assert_eq!(shown["token"], REDACTED);
    assert_eq!(shown["auth"]["client_token"], REDACTED);
    assert_eq!(shown["auth"]["token_type"], "service");
    assert_eq!(shown["auth"]["token_policies"], json!(["default"]));
    assert_eq!(shown["auth"]["token_present"], true);
}

#[test]
fn nesting_past_the_bound_is_hidden_rather_than_walked() {
    use netget::utils::redact::MAX_REDACT_DEPTH;
    let mut value = json!("bottom");
    for _ in 0..(MAX_REDACT_DEPTH + 10) {
        value = json!({ "n": value });
    }
    let shown = redact_sensitive(&value).to_string();
    assert!(
        !shown.contains("bottom"),
        "the walk must stop at MAX_REDACT_DEPTH"
    );
    assert!(shown.contains(REDACTED));
}

#[test]
fn bearer_credentials_and_http_auth_headers_are_hidden_without_hiding_usage() {
    let original = json!({
        "access_token": "access credential",
        "refreshToken": "refresh credential",
        "id_token": "identity credential",
        "idToken": "camel case identity credential",
        "authToken": "camel case auth credential",
        "token": "generic credential",
        "headers": {
            "Authorization": "Bearer credential",
            "Proxy-Authorization": "Basic credential",
            "X-API-Key": "API credential",
            "Cookie": "session=credential",
            "Set-Cookie": "session=credential; HttpOnly"
        },
        "input_tokens": 100,
        "max_tokens": 200,
        "token_url": "https://example.test/token"
    });
    let shown = redact_sensitive(&original);
    for key in [
        "access_token",
        "refreshToken",
        "id_token",
        "idToken",
        "authToken",
        "token",
    ] {
        assert_eq!(shown[key], REDACTED, "{key}");
    }
    for value in shown["headers"].as_object().unwrap().values() {
        assert_eq!(value, REDACTED);
    }
    for key in ["input_tokens", "max_tokens", "token_url"] {
        assert_eq!(shown[key], original[key]);
    }
    assert_eq!(
        original["access_token"], "access credential",
        "redaction must not change the credential used on the wire"
    );
}

/// Four client parameters that are credentials without being called one. Each reached the
/// `open_client` summary and the executor's DEBUG line verbatim: `is_sensitive_key` matched
/// `password` but not `passcode`, nothing in `community`, nothing in `proxy_auth`, and
/// `auth` only as the substring of `auth_token` / `authorization`. A bare `auth` is hidden
/// when it is a string; an `auth` object (Vault's answer) is still walked, as the first test
/// in this file requires.
#[test]
fn credentials_that_are_not_called_one_are_redacted_and_their_describers_are_not() {
    let shown = redact_sensitive(&json!({
        "passcode": "stomp-pass",
        "community": "public",
        "proxy_auth": "user:pw",
        "auth": "alice:s3cret",
        "Auth": "alice:s3cret",
        "nested": {"community_string": "private", "PROXY-AUTH": "u:p"},
        // Describers of a mechanism, not the credential itself.
        "auth_type": "basic",
        "auth_url": "https://idp.example/authorize",
        "authenticated": true,
        "auth_method": "password-less",
        "routing_key": "orders.created",
        "access_key_id": "AKIA-not-a-secret",
        "key_type": "ed25519",
        "secret_access_key": "this one is"
    }));
    for key in [
        "passcode",
        "community",
        "proxy_auth",
        "auth",
        "Auth",
        "secret_access_key",
    ] {
        assert_eq!(shown[key], json!(REDACTED), "{key} must be hidden");
    }
    assert_eq!(shown["nested"]["community_string"], json!(REDACTED));
    assert_eq!(shown["nested"]["PROXY-AUTH"], json!(REDACTED));
    assert_eq!(shown["auth_type"], json!("basic"));
    assert_eq!(shown["auth_url"], json!("https://idp.example/authorize"));
    assert_eq!(shown["authenticated"], json!(true));
    assert_eq!(shown["auth_method"], json!("password-less"));
    assert_eq!(shown["routing_key"], json!("orders.created"));
    assert_eq!(shown["access_key_id"], json!("AKIA-not-a-secret"));
    assert_eq!(shown["key_type"], json!("ed25519"));
}

/// LoRaWAN's keys sit inside the `devices` array of both roles; the EUIs that name a device
/// are shown, the keys never are.
#[test]
fn lorawan_device_keys_are_redacted_and_their_euis_are_not() {
    let shown = redact_sensitive(&json!({"devices": [
        {"name": "meter-1", "dev_eui": "0102030405060708", "app_eui": "0000000000000000",
         "app_key": "2b7e151628aed2a6abf7158809cf4f3c"},
        {"dev_addr": "26011bda", "nwk_s_key": "000102030405060708090a0b0c0d0e0f",
         "app_s_key": "0f0e0d0c0b0a09080706050403020100"}
    ]}));
    let d = &shown["devices"];
    for (i, key) in [(0, "app_key"), (1, "nwk_s_key"), (1, "app_s_key")] {
        assert_eq!(d[i][key], json!(REDACTED), "{key} must be hidden");
    }
    assert_eq!(d[0]["dev_eui"], json!("0102030405060708"));
    assert_eq!(d[0]["app_eui"], json!("0000000000000000"));
    assert_eq!(d[0]["name"], json!("meter-1"));
    assert_eq!(d[1]["dev_addr"], json!("26011bda"));
}

/// A startup parameter's diagnostic applies the redactor's own key/value rule. A string-valued
/// `auth` (`username:password`) is a credential by its value, not its name, so the name-only
/// check let it into the "expected …, got …" error a mistyped `auth` produces.
#[test]
fn a_string_auth_in_a_startup_parameter_error_is_redacted() {
    use netget::llm::actions::ParameterDefinition;
    use netget::protocol::StartupParams;

    let schema = vec![ParameterDefinition {
        name: "auth".to_string(),
        type_hint: "object".to_string(),
        description: String::new(),
        required: false,
        example: json!(null),
        default: None,
    }];
    let error = StartupParams::new_validated(json!({"auth": "alice:s3cret"}), schema)
        .err()
        .expect("a string where an object is declared is refused")
        .to_string();
    assert!(!error.contains("s3cret"), "{error}");
    assert!(
        error.contains("auth") && error.contains(REDACTED),
        "the error still names the parameter: {error}"
    );
}

/// The SNMP `community` and STOMP `passcode` ride on every event of their protocol, so they
/// are masked where they are shown but do not make the event private: tracing and the
/// access-log detail stay on for SNMP and STOMP.
#[test]
fn community_and_passcode_are_masked_when_shown_without_making_the_event_private() {
    use netget::utils::redact::{contains_credentials, is_shown_redacted};
    let snmp = json!({"community": "public", "oid": "1.3.6.1.2.1.1.1.0"});
    let stomp = json!({"command": "CONNECT", "login": "guest", "passcode": "guest"});
    assert!(
        !contains_credentials(&snmp),
        "an SNMP event must not be private"
    );
    assert!(
        !contains_credentials(&stomp),
        "a STOMP CONNECT must not be private"
    );
    assert!(is_shown_redacted("community", &json!("public")));
    assert!(is_shown_redacted("passcode", &json!("guest")));
    assert_eq!(redact_sensitive(&snmp)["community"], json!(REDACTED));
    assert_eq!(redact_sensitive(&stomp)["passcode"], json!(REDACTED));
    assert!(
        contains_credentials(&json!({"password": "x"})),
        "a real credential still makes the event private"
    );
}
