//! `StartupParams` must report bad model/client input, never panic.
//!
//! The JSON reaching `StartupParams` comes from the LLM (`open_server`) or
//! straight from an MCP client (`start_server`'s `startup_params`), so it is
//! untrusted. Every accessor returns a `Result` so the failure travels back to
//! the caller as a tool error instead of aborting the per-request task.

use netget::llm::actions::ParameterDefinition;
use netget::protocol::{StartupParamError, StartupParams};
use serde_json::json;

fn param(name: &str, type_hint: &str) -> ParameterDefinition {
    ParameterDefinition {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: String::new(),
        required: false,
        example: json!(null),
        default: None,
    }
}

fn schema() -> Vec<ParameterDefinition> {
    vec![
        param("send_first", "boolean"),
        param("banner", "string"),
        param("max_connections", "number"),
        param("headers", "object"),
        param("hosts", "array"),
    ]
}

#[test]
fn preflight_checks_required_types_typed_arrays_and_unions() {
    let mut required = param("token", "string");
    required.required = true;
    assert!(StartupParams::new_validated(json!({}), vec![required.clone()]).is_err());
    assert!(StartupParams::new_validated(json!({"token": null}), vec![required]).is_err());
    for (hint, valid, invalid) in [
        ("boolean", json!(false), json!("false")),
        ("integer", json!(42), json!(1.5)),
        ("array of strings", json!(["one"]), json!(["one", 2])),
        ("string | number", json!(42), json!([])),
        ("array of booleans", json!([true]), json!([1])),
    ] {
        StartupParams::new_validated(json!({"value": valid}), vec![param("value", hint)]).unwrap();
        assert!(
            StartupParams::new_validated(json!({"value": invalid}), vec![param("value", hint)])
                .is_err(),
            "{hint}"
        );
    }
}

#[test]
fn parameter_container_must_be_an_object() {
    for value in [
        json!(null),
        json!(true),
        json!(42),
        json!("send_first"),
        json!([]),
        json!([{"send_first": true}]),
    ] {
        let error = StartupParams::new(value.clone(), schema())
            .expect_err("non-object parameter container accepted");
        assert!(
            matches!(error, StartupParamError::Invalid { .. }),
            "{value}: {error}"
        );
        assert!(error.to_string().contains("JSON object"));
    }
    StartupParams::new(json!({}), schema()).expect("empty object remains valid");
}

#[test]
fn undeclared_key_is_rejected_by_new() {
    let err = StartupParams::new(json!({ "undeclared_xyz": 1 }), schema())
        .expect_err("undeclared key must be rejected");

    match &err {
        StartupParamError::Undeclared { key, allowed, .. } => {
            assert_eq!(key, "undeclared_xyz");
            // The allowed list is what a retrying model needs, so it must be complete.
            assert_eq!(
                allowed,
                &vec![
                    "banner".to_string(),
                    "headers".to_string(),
                    "hosts".to_string(),
                    "max_connections".to_string(),
                    "send_first".to_string(),
                ]
            );
        }
        other => panic!("expected Undeclared, got {other:?}"),
    }

    // The message names the offending key and lists the allowed ones — and, because this is
    // the caller's mistake and the caller is an MCP user or the model, it speaks about their
    // input rather than telling them how to write a protocol.
    let msg = err.to_string();
    assert!(msg.contains("undeclared_xyz"), "{msg}");
    assert!(msg.contains("send_first"), "{msg}");
    assert!(
        !msg.contains("get_startup_parameters()"),
        "a caller-supplied unknown key is not a protocol bug; got: {msg}"
    );
    assert!(msg.contains("unknown startup parameter"), "{msg}");
}

#[test]
fn declared_keys_are_accepted_by_new() {
    StartupParams::new(json!({ "send_first": true, "banner": "hi" }), schema())
        .expect("declared keys must be accepted");
}

#[test]
fn wrong_typed_value_is_an_error_not_a_panic() {
    let params = StartupParams::new(json!({ "send_first": "yes-please" }), schema()).unwrap();

    let err = params
        .get_optional_bool("send_first")
        .expect_err("a string is not a boolean");
    let msg = err.to_string();
    assert!(msg.contains("send_first"), "{msg}");
    assert!(msg.contains("not a boolean"), "{msg}");
    assert!(matches!(err, StartupParamError::Invalid { .. }));
}

#[test]
fn missing_required_value_is_an_error() {
    let params = StartupParams::new(json!({}), schema()).unwrap();

    assert!(params.get_string("banner").is_err());
    assert!(params.get_bool("send_first").is_err());
    assert!(params.get_i64("max_connections").is_err());
    assert!(params.get_u64("max_connections").is_err());
    assert!(params.get_object("headers").is_err());
    assert!(params.get_array("hosts").is_err());
}

#[test]
fn absent_optional_values_are_none() {
    let params = StartupParams::new(json!({}), schema()).unwrap();

    assert_eq!(params.get_optional_bool("send_first").unwrap(), None);
    assert_eq!(params.get_optional_string("banner").unwrap(), None);
    assert_eq!(params.get_optional_i64("max_connections").unwrap(), None);
    assert_eq!(params.get_optional_u64("max_connections").unwrap(), None);
    assert_eq!(params.get_optional_u32("max_connections").unwrap(), None);
    assert!(params.get_optional_object("headers").unwrap().is_none());
    assert!(params.get_optional_array("hosts").unwrap().is_none());
}

#[test]
fn explicit_null_reads_as_absent() {
    // A model that spells "unset" as `null` should not be treated as a type error.
    let params = StartupParams::new(json!({ "banner": null }), schema()).unwrap();
    assert_eq!(params.get_optional_string("banner").unwrap(), None);
}

#[test]
fn present_values_round_trip() {
    let params = StartupParams::new(
        json!({
            "send_first": true,
            "banner": "220 ready",
            "max_connections": 12,
            "headers": { "x": "y" },
            "hosts": ["a", "b"],
        }),
        schema(),
    )
    .unwrap();

    assert!(params.get_bool("send_first").unwrap());
    assert_eq!(params.get_string("banner").unwrap(), "220 ready");
    assert_eq!(params.get_i64("max_connections").unwrap(), 12);
    assert_eq!(params.get_u64("max_connections").unwrap(), 12);
    assert_eq!(
        params.get_optional_u32("max_connections").unwrap(),
        Some(12)
    );
    assert_eq!(params.get_object("headers").unwrap().len(), 1);
    assert_eq!(params.get_array("hosts").unwrap().len(), 2);
}

#[test]
fn u32_overflow_is_an_error() {
    let params =
        StartupParams::new(json!({ "max_connections": u32::MAX as u64 + 1 }), schema()).unwrap();

    let msg = params
        .get_optional_u32("max_connections")
        .unwrap_err()
        .to_string();
    assert!(msg.contains("max_connections"), "{msg}");
    assert!(msg.contains("u32::MAX"), "{msg}");
}

#[test]
fn accessing_a_key_the_protocol_never_declared_is_an_error() {
    let params = StartupParams::new(json!({}), schema()).unwrap();

    let err = params
        .get_optional_string("never_declared")
        .expect_err("undeclared key must not be readable");
    let msg = err.to_string();
    assert!(msg.contains("never_declared"), "{msg}");
    assert!(msg.contains("banner"), "{msg}");
}

fn deeply_constructed_params() -> serde_json::Value {
    let mut value = serde_json::Value::Null;
    for _ in 0..10_000 {
        value = serde_json::Value::Array(vec![value]);
    }
    let mut params = serde_json::Map::new();
    params.insert("hosts".into(), value);
    serde_json::Value::Object(params)
}

#[test]
fn constructed_startup_json_is_refused_before_copy_format_or_recursive_drop() {
    for validate_types in [false, true] {
        let params = deeply_constructed_params();
        let result = if validate_types {
            StartupParams::new_validated(params, schema())
        } else {
            StartupParams::new(params, schema())
        };
        let error = result.unwrap_err().to_string();
        assert!(error.contains("budget"), "{error}");
    }
    for params in [
        json!({"banner": "x".repeat(8 * 1024 * 1024)}),
        json!({"hosts": vec![serde_json::Value::Null; 65_536]}),
    ] {
        assert!(StartupParams::new(params, schema())
            .unwrap_err()
            .to_string()
            .contains("budget"));
    }
    let mut owned = Some(deeply_constructed_params());
    assert!(StartupParams::preflight_owned(&mut owned).is_err());
    assert!(
        owned.is_none(),
        "rejected owned input must be consumed safely"
    );
    let value = json!({"banner": "ordinary", "hosts": [1, 2]});
    StartupParams::preflight(&value).unwrap();
    let params = StartupParams::new_validated(value, schema()).unwrap();
    assert_eq!(params.get_string("banner").unwrap(), "ordinary");
}

#[test]
fn startup_errors_redact_sensitive_values_and_keep_actionable_types_and_keys() {
    const MARKER: &str = "STARTUP_SECRET_MARKER_3ef1";
    let definitions = vec![
        param("banner", "string"),
        param("password", "string"),
        param("headers", "object"),
    ];
    let params = StartupParams::new(
        json!({"password": MARKER, "headers": {"authorization": MARKER, "ordinary": "visible"}}),
        definitions.clone(),
    )
    .unwrap();
    for rendered in [
        params.get_string("banner").unwrap_err().to_string(),
        params.get_bool("banner").unwrap_err().to_string(),
        params.get_i64("banner").unwrap_err().to_string(),
        params.get_u64("banner").unwrap_err().to_string(),
        params.get_object("banner").unwrap_err().to_string(),
        params.get_array("banner").unwrap_err().to_string(),
        params
            .get_optional_string("headers")
            .unwrap_err()
            .to_string(),
        format!("{params:?}"),
    ] {
        assert!(!rendered.contains(MARKER), "{rendered}");
        assert!(
            rendered.contains("visible"),
            "ordinary diagnostics retained: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }
    assert_eq!(params.get_string("password").unwrap(), MARKER);
    assert_eq!(
        params.get_object("headers").unwrap()["authorization"],
        MARKER
    );
    let raw = json!({"password": {"nested": MARKER}});
    let error = StartupParams::new_validated(raw.clone(), definitions.clone())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("password") && error.contains("expected string"),
        "{error}"
    );
    assert!(!error.contains(MARKER), "{error}");
    let params = StartupParams::new(raw, definitions).unwrap();
    for error in [
        params
            .get_optional_string("password")
            .unwrap_err()
            .to_string(),
        params
            .get_optional_bool("password")
            .unwrap_err()
            .to_string(),
        params.get_optional_i64("password").unwrap_err().to_string(),
        params.get_optional_u64("password").unwrap_err().to_string(),
        params.get_optional_u32("password").unwrap_err().to_string(),
        params
            .get_optional_array("password")
            .unwrap_err()
            .to_string(),
    ] {
        assert!(!error.contains(MARKER), "{error}");
        assert!(error.contains("password") && error.contains("<redacted>"));
    }
    let params = StartupParams::new(
        json!({"password": MARKER}),
        vec![param("password", "string")],
    )
    .unwrap();
    assert!(!params
        .get_optional_object("password")
        .unwrap_err()
        .to_string()
        .contains(MARKER));
    let error = StartupParams::new_validated(
        json!({"value": "ordinary-wrong-type"}),
        vec![param("value", "boolean")],
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("expected boolean") && error.contains("ordinary-wrong-type"),
        "{error}"
    );
}
