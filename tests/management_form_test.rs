//! Tests for the interactive create/update *form* (`InteractiveForm` in
//! `netget::cli::management`).
//!
//! Two layers:
//!  - **Pure form logic** — field prefill, required flags, value coercion, and the
//!    collected-values → `ServerForm`/`ClientForm` assembly. These need no network.
//!  - **Protocol-level data path** — a form built and filled the way the TUI drives
//!    it produces a `ServerForm` that actually creates a working HTTP server, and an
//!    update form edit actually changes the response on the wire. This mirrors
//!    `tests/management_test.rs`, proving the form reuses the same executors.
//!
//! No LLM is involved: servers use *static* handlers. Everything binds 127.0.0.1.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use netget::cli::management::{
    self, server_declared_params, InteractiveForm, ServerForm, ServerPrefill,
};
use netget::llm::actions::ParameterDefinition;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::sync::mpsc;

// --------------------------------------------------------------------------
// Shared helpers (mirrors tests/management_test.rs)
// --------------------------------------------------------------------------

fn static_http_handler(body: &str) -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "http_request",
        "handler": {
            "type": "static",
            "actions": [ { "type": "send_http_response", "status": 200, "body": body } ]
        }
    })]
}

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

fn connect_retry(port: u16) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("could not connect to 127.0.0.1:{port}");
}

fn http_get(port: u16) -> String {
    let mut stream = connect_retry(port);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Snapshot a running server into a `ServerPrefill`, exactly as the TUI's
/// `start_form` does when it opens an `/edit` form.
/// Exactly what the TUI's edit path does, via the one shared constructor. Rebuilding this
/// by hand here is how the test stopped testing the real thing.
async fn prefill_from(state: &AppState, id: ServerId) -> ServerPrefill {
    let s = state.get_server(id).await.expect("server exists");
    ServerPrefill::from_server(&s)
}

fn field_names(form: &InteractiveForm) -> Vec<String> {
    form.fields.iter().map(|f| f.name.clone()).collect()
}

// --------------------------------------------------------------------------
// Pure form-logic tests
// --------------------------------------------------------------------------

/// A create form exposes the common fields plus every declared startup param,
/// carrying each param's name/type/required/help through from the schema.
#[test]
fn create_server_form_has_common_and_declared_fields() {
    let schema = server_declared_params("http").expect("http compiled in");
    let form = InteractiveForm::create_server("http", &schema);

    let names = field_names(&form);
    for common in [
        "port",
        "instruction",
        "initial_memory",
        "event_handlers",
        "feedback_instructions",
    ] {
        assert!(names.contains(&common.to_string()), "missing {common}");
    }

    // Every declared param is present as a field, with its metadata preserved.
    for p in &schema {
        let f = form
            .fields
            .iter()
            .find(|f| f.name == p.name)
            .unwrap_or_else(|| panic!("declared param {} not in form", p.name));
        assert_eq!(f.type_label, p.type_hint);
        assert_eq!(f.required, p.required);
        assert_eq!(f.help, p.description);
    }

    // On create, port prefills to the OS-assign sentinel and the prompt/title are
    // sensible.
    let port_field = form.fields.iter().find(|f| f.name == "port").unwrap();
    assert_eq!(port_field.prefill, "0");
    assert!(form.title().contains("Create"));
    assert!(form.prompt().contains("port"));
}

/// Numeric and boolean param values entered as text are coerced to real JSON
/// numbers/bools; plain strings stay strings. Uses a synthetic schema so the test
/// does not depend on any particular protocol's params.
#[test]
fn param_values_coerced_by_declared_type() {
    let schema = vec![
        ParameterDefinition {
            name: "max_conns".to_string(),
            type_hint: "number".to_string(),
            description: "max connections".to_string(),
            required: false,
            example: serde_json::json!(10),
            default: None,
        },
        ParameterDefinition {
            name: "verbose".to_string(),
            type_hint: "boolean".to_string(),
            description: "verbose".to_string(),
            required: false,
            example: serde_json::json!(true),
            default: None,
        },
        ParameterDefinition {
            name: "label".to_string(),
            type_hint: "string".to_string(),
            description: "a label".to_string(),
            required: false,
            example: serde_json::json!("x"),
            default: None,
        },
    ];
    let mut form = InteractiveForm::create_server("tcp", &schema);
    assert!(form.set_field_value("max_conns", "42"));
    assert!(form.set_field_value("verbose", "true"));
    assert!(form.set_field_value("label", "hello"));

    let sf = form.into_server_form().expect("builds");
    let params = sf.startup_params.expect("params present");
    assert_eq!(params["max_conns"], serde_json::json!(42));
    assert_eq!(params["verbose"], serde_json::json!(true));
    assert_eq!(params["label"], serde_json::json!("hello"));
}

/// A non-numeric value for a numeric param is rejected, naming the field.
#[test]
fn bad_numeric_param_rejected_naming_field() {
    let schema = vec![ParameterDefinition {
        name: "max_conns".to_string(),
        type_hint: "number".to_string(),
        description: "max connections".to_string(),
        required: false,
        example: serde_json::json!(10),
        default: None,
    }];
    let mut form = InteractiveForm::create_server("tcp", &schema);
    form.set_field_value("max_conns", "not-a-number");
    let err = form.into_server_form().expect_err("must reject");
    assert!(err.to_string().contains("max_conns"), "got: {err}");
}

/// `event_handlers` must be a JSON array; a JSON object is rejected clearly.
#[test]
fn event_handlers_must_be_json_array() {
    let form_schema = server_declared_params("http").unwrap();
    let mut form = InteractiveForm::create_server("http", &form_schema);
    form.set_field_value("event_handlers", "{\"not\":\"an array\"}");
    let err = form.into_server_form().expect_err("must reject");
    assert!(err.to_string().contains("event_handlers"), "got: {err}");
}

/// Unspecified (empty) fields fall through to protocol defaults: they do not land
/// in the built form at all.
#[test]
fn unspecified_fields_are_skipped() {
    let schema = server_declared_params("http").unwrap();
    let mut form = InteractiveForm::create_server("http", &schema);
    // Only set the port; leave everything else empty.
    form.set_field_value("port", "8080");

    let sf = form.into_server_form().expect("builds");
    assert_eq!(sf.port, Some(8080));
    assert!(sf.instruction.is_none(), "unset instruction stays None");
    assert!(sf.initial_memory.is_none());
    assert!(sf.event_handlers.is_none());
    assert!(
        sf.startup_params.is_none(),
        "no params set => no startup_params object"
    );
}

/// Submitting fields in sequence advances and completes; `remote_addr` is the one
/// required common field on a client create form.
#[test]
fn client_create_form_requires_remote_addr() {
    // Empty schema is fine; we only care about the common client fields.
    let form = InteractiveForm::create_client("redis", &[]);
    let remote = form
        .fields
        .iter()
        .find(|f| f.name == "remote_addr")
        .expect("remote_addr field");
    assert!(remote.required, "remote_addr is required on client create");

    // Drive it to completion the way the TUI does.
    let mut form = form;
    let mut steps = 0;
    while !form.is_complete() {
        let name = form.current_field().unwrap().name.clone();
        let val = if name == "remote_addr" {
            "127.0.0.1:6379"
        } else {
            ""
        };
        form.submit_current(val);
        steps += 1;
        assert!(steps < 50, "form did not terminate");
    }
    let cf = form.into_client_form().expect("builds");
    assert_eq!(cf.remote_addr.as_deref(), Some("127.0.0.1:6379"));
    assert!(cf.instruction.is_none());
}

// --------------------------------------------------------------------------
// Protocol-level data-path tests
// --------------------------------------------------------------------------

/// A create form, filled the way the TUI drives it, builds a `ServerForm` that
/// creates a working HTTP server answering on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_form_builds_working_http_server() {
    let state = new_state().await;

    let schema = server_declared_params("http").unwrap();
    let mut form = InteractiveForm::create_server("http", &schema);
    form.set_field_value("port", "0"); // OS-assigned
    form.set_field_value(
        "event_handlers",
        &serde_json::to_string(&static_http_handler("FORM-MADE")).unwrap(),
    );

    let sf: ServerForm = form.into_server_form().expect("form builds a ServerForm");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = sf.create(&state, tx).await.expect("create via form");
    let port = wait_for_port(&state, id).await;

    let resp = http_get(port);
    assert!(resp.contains("FORM-MADE"), "server response: {resp}");
}

/// An update form is PREFILLED with the running server's current handler, and
/// editing that field and submitting changes the response on the wire — hot, no
/// restart — via the shared `update_server` executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_form_prefills_and_changes_response() {
    let state = new_state().await;

    // Stand up an HTTP server with OLD-BODY, using a create form.
    let mut create =
        InteractiveForm::create_server("http", &server_declared_params("http").unwrap());
    create.set_field_value("port", "0");
    create.set_field_value(
        "event_handlers",
        &serde_json::to_string(&static_http_handler("OLD-BODY")).unwrap(),
    );
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = create
        .into_server_form()
        .unwrap()
        .create(&state, tx)
        .await
        .expect("create");
    let port = wait_for_port(&state, id).await;
    assert!(http_get(port).contains("OLD-BODY"));

    // Open an update form prefilled from the running server.
    let prefill = prefill_from(&state, id).await;
    let schema = server_declared_params("http").unwrap();
    let mut form = InteractiveForm::update_server(id.as_u32(), "http", &schema, &prefill);

    // The event_handlers field is prefilled with the current handler config.
    let eh = form
        .fields
        .iter()
        .find(|f| f.name == "event_handlers")
        .unwrap();
    assert!(
        eh.prefill.contains("OLD-BODY"),
        "update form should prefill current handlers, got: {}",
        eh.prefill
    );
    // Port prefilled with the concrete bound port (an update snapshot).
    let portf = form.fields.iter().find(|f| f.name == "port").unwrap();
    assert_eq!(portf.prefill, port.to_string());

    // Operator edits the handler to NEW-BODY, leaves everything else prefilled.
    form.set_field_value(
        "event_handlers",
        &serde_json::to_string(&static_http_handler("NEW-BODY")).unwrap(),
    );

    let sf = form.into_server_form().expect("update form builds");
    let (tx2, _rx2) = mpsc::unbounded_channel();
    let outcome = management::update_server(&state, id, sf, tx2)
        .await
        .expect("update via form");
    assert!(!outcome.restarted, "handler-only edit must be hot");
    assert_eq!(outcome.id, id.as_u32());

    let after = http_get(port);
    assert!(
        after.contains("NEW-BODY") && !after.contains("OLD-BODY"),
        "wire should show NEW-BODY, got: {after}"
    );
}
