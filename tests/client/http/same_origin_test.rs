//! An HTTP-family client is bound to one origin, and the model cannot point it elsewhere.
//!
//! The `http`, `http2` and `webdav` clients accept an absolute URL as an action's `path`, and
//! until September 2026 they sent it wherever it pointed — with the startup
//! `default_headers` (API keys, cookies) on it and, for WebDAV, the `auth` credential as
//! `Authorization: Basic`. The model reads the peer's responses, so a prompt-injected
//! "fetch http://attacker/" exfiltrated the operator's credential in one request, and an
//! internal address was reachable from wherever the client ran. `resolve_same_origin`
//! refuses any origin but the client's own, and the reqwest clients follow no redirect to
//! another origin.
//!
//! The wire half: a client bound to one local server is told to fetch a URL on a second
//! listener, which counts its accepts and must count zero. Zero LLM calls — every client
//! event is answered by a zero-action static rule, and the model URL is a closed port.
//!
//! Run with:
//!   cargo test --no-default-features --features http,webdav --test client -- http::same_origin


use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::http_fetch::{origin_of, resolve_same_origin};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[test]
fn a_relative_path_is_appended_to_the_base() {
    assert_eq!(
        resolve_same_origin("http://127.0.0.1:8080", "/api/users").unwrap(),
        "http://127.0.0.1:8080/api/users"
    );
    assert_eq!(
        resolve_same_origin("127.0.0.1:8080", "/x").unwrap(),
        "http://127.0.0.1:8080/x",
        "a bare host:port base is http://"
    );
}

#[test]
fn an_absolute_url_on_the_same_origin_is_accepted_whatever_its_spelling() {
    // The result is the URL parser's serialization of what was checked, so a default port
    // is dropped and the scheme lowercased.
    for (base, path, expected) in [
        (
            "http://example.test:8080",
            "http://example.test:8080/next?page=2",
            "http://example.test:8080/next?page=2",
        ),
        (
            "http://EXAMPLE.test:8080/",
            "http://example.test:8080/x",
            "http://example.test:8080/x",
        ),
        (
            "http://example.test",
            "http://example.test:80/x",
            "http://example.test/x",
        ),
        (
            "https://example.test:443",
            "https://example.test/x",
            "https://example.test/x",
        ),
        (
            "example.test:8080",
            "http://example.test:8080/x",
            "http://example.test:8080/x",
        ),
        (
            "http://example.test:8080",
            "HTTP://example.test:8080/x",
            "http://example.test:8080/x",
        ),
    ] {
        assert_eq!(
            resolve_same_origin(base, path).unwrap(),
            expected,
            "{base} + {path}"
        );
    }
}

/// Assert `path` resolves against `base` to `expected`, and that the result is on the
/// base's origin with no userinfo, read back through the same WHATWG parser reqwest uses.
fn assert_stays_on_base(base: &str, path: &str, expected: &str) {
    let resolved =
        resolve_same_origin(base, path).unwrap_or_else(|e| panic!("{base} + {path}: {e:#}"));
    assert_eq!(resolved, expected, "{base} + {path}");
    // A base without a scheme is bound as http://, as resolve_same_origin reads it.
    let bound = if base.contains("://") {
        base.to_string()
    } else {
        format!("http://{base}")
    };
    assert_eq!(
        origin_of(&resolved).unwrap(),
        origin_of(&bound).unwrap(),
        "{base} + {path} left the bound origin"
    );
    let parsed = url::Url::parse(&resolved).unwrap();
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{base} + {path} carries userinfo: {resolved}"
    );
}

#[test]
fn a_relative_path_cannot_rewrite_the_authority() {
    // Appended bare, each of these would end the authority's host or port and start
    // another: `http://127.0.0.1:8080@attacker.example/x` is attacker.example with
    // userinfo `127.0.0.1:8080`, `http://example.test.attacker.example/` is another host,
    // `http://example.test:9999/` another port.
    assert_stays_on_base(
        "http://127.0.0.1:8080",
        "@attacker.example/x",
        "http://127.0.0.1:8080/@attacker.example/x",
    );
    assert_stays_on_base(
        "http://example.test",
        ".attacker.example/",
        "http://example.test/.attacker.example/",
    );
    assert_stays_on_base(
        "http://example.test",
        ":9999/",
        "http://example.test/:9999/",
    );
    assert_stays_on_base(
        "127.0.0.1:8080",
        "@attacker.example/x",
        "http://127.0.0.1:8080/@attacker.example/x",
    );
    assert_stays_on_base(
        "http://127.0.0.1:8080",
        "\\@attacker.example/x",
        "http://127.0.0.1:8080//@attacker.example/x",
    );
}

#[test]
fn legitimate_relative_paths_still_resolve_on_the_bound_origin() {
    for (base, path, expected) in [
        ("http://127.0.0.1:8080", "/ok", "http://127.0.0.1:8080/ok"),
        ("http://127.0.0.1:8080", "ok", "http://127.0.0.1:8080/ok"),
        (
            "http://127.0.0.1:8080",
            "?q=1",
            "http://127.0.0.1:8080/?q=1",
        ),
        (
            "http://127.0.0.1:8080",
            "api/x",
            "http://127.0.0.1:8080/api/x",
        ),
        ("http://127.0.0.1:8080/", "ok", "http://127.0.0.1:8080/ok"),
        ("http://127.0.0.1:8080", "", "http://127.0.0.1:8080/"),
        (
            "http://example.test/dav",
            "/file.txt",
            "http://example.test/dav/file.txt",
        ),
        (
            "http://example.test/dav",
            "?q=1",
            "http://example.test/dav?q=1",
        ),
    ] {
        assert_stays_on_base(base, path, expected);
    }
}

#[test]
fn userinfo_in_a_same_origin_url_is_refused() {
    for path in [
        "http://user:pw@127.0.0.1:8080/x",
        "http://user@127.0.0.1:8080/x",
        "http://127.0.0.1:8080@127.0.0.1:8080/x",
    ] {
        let err = resolve_same_origin("http://127.0.0.1:8080", path).expect_err(path);
        assert!(err.to_string().contains("credentials"), "{path}: {err:#}");
    }
}

#[test]
fn an_absolute_url_on_another_origin_is_refused_by_name() {
    for (base, path) in [
        ("http://127.0.0.1:8080", "http://attacker.example/steal"),
        (
            "http://127.0.0.1:8080",
            "http://169.254.169.254/latest/meta-data/",
        ),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8081/"),
        ("http://127.0.0.1:8080", "https://127.0.0.1:8080/"),
        (
            "http://example.test",
            "http://example.test.attacker.example/",
        ),
        ("http://example.test", "http://user@attacker.example/"),
    ] {
        let err = resolve_same_origin(base, path).expect_err(path);
        let text = err.to_string();
        assert!(
            text.contains("bound to") && text.contains(&origin_of(path).unwrap()),
            "{base} + {path}: {text}"
        );
    }
    assert!(resolve_same_origin("http://127.0.0.1:8080", "http://[::1/").is_err());
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

/// A minimal HTTP/1.1 server that answers everything with 200 and counts its accepts.
async fn stub_server() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (port, accepted)
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
}

async fn open_client(state: &AppState, protocol: &str, remote_addr: String) -> ClientId {
    let (tx, _rx) = mpsc::unbounded_channel();
    ClientForm {
        protocol: protocol.to_string(),
        remote_addr: Some(remote_addr),
        instruction: Some("test client".to_string()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        startup_params: Some(if protocol == "webdav" {
            serde_json::json!({ "auth": "operator:secret" })
        } else {
            serde_json::json!({ "default_headers": { "X-Api-Key": "operator-secret" } })
        }),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .unwrap_or_else(|e| panic!("create {protocol} client: {e}"))
}

async fn assert_never_reaches_foreign_host(protocol: &str, action: serde_json::Value) {
    let (home_port, home_accepts) = stub_server().await;
    let (foreign_port, foreign_accepts) = stub_server().await;
    let state = new_state().await;
    let client_id = open_client(&state, protocol, format!("http://127.0.0.1:{home_port}")).await;
    wait_for_client_handle(&state, client_id).await;

    let action_template = action;
    let mut action = action_template.clone();
    action["path"] = serde_json::json!(format!("http://127.0.0.1:{foreign_port}/steal"));
    // The refusal surfaces either as the command's error or as a Rejected outcome,
    // depending on where the client's loop reports it; a completed request is what must
    // not happen.
    match state
        .send_to_client(client_id, action, Duration::from_secs(20))
        .await
    {
        Ok(ClientSendOutcome::Executed { detail }) => assert!(
            detail.contains("bound to") || detail.contains("origin"),
            "{protocol}: the foreign request must not have completed: {detail}"
        ),
        Ok(ClientSendOutcome::Rejected { error }) => assert!(
            error.contains("bound to"),
            "{protocol}: unexpected refusal: {error}"
        ),
        Ok(other) => panic!("{protocol}: unexpected outcome {other:?}"),
        Err(e) => assert!(
            e.to_string().contains("bound to"),
            "{protocol}: unexpected error: {e:#}"
        ),
    }
    // A relative path that, appended bare, would make the base userinfo and the foreign
    // listener the host. It stays a path on the home server.
    let home_before_relative = home_accepts.load(Ordering::SeqCst);
    let mut relative = action_template.clone();
    relative["path"] = serde_json::json!(format!("@127.0.0.1:{foreign_port}/steal"));
    let outcome = state
        .send_to_client(client_id, relative, Duration::from_secs(20))
        .await
        .expect("send_to_client");
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "{protocol}: a userinfo-shaped relative path must go to the home server: {outcome:?}"
    );
    assert!(
        home_accepts.load(Ordering::SeqCst) > home_before_relative,
        "{protocol}: the userinfo-shaped relative path did not reach the home server"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        foreign_accepts.load(Ordering::SeqCst),
        0,
        "{protocol}: the foreign host was contacted"
    );

    // The client still works against its own origin, absolute URL included.
    let home_before = home_accepts.load(Ordering::SeqCst);
    let mut action = serde_json::json!({"type": "send_http_request", "method": "GET"});
    if protocol == "webdav" {
        action = serde_json::json!({"type": "propfind", "depth": "0"});
    }
    action["path"] = serde_json::json!(format!("http://127.0.0.1:{home_port}/fine"));
    let outcome = state
        .send_to_client(client_id, action, Duration::from_secs(20))
        .await
        .expect("send_to_client");
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "{protocol}: same-origin absolute URL must still work: {outcome:?}"
    );
    assert!(
        home_accepts.load(Ordering::SeqCst) > home_before,
        "{protocol}: the home server was not contacted"
    );
}

#[tokio::test]
async fn the_http_client_never_sends_the_operators_headers_to_another_host() {
    assert_never_reaches_foreign_host(
        "http",
        serde_json::json!({"type": "send_http_request", "method": "GET"}),
    )
    .await;
}

#[tokio::test]
async fn the_webdav_client_never_sends_the_share_credential_to_another_host() {
    assert_never_reaches_foreign_host(
        "webdav",
        serde_json::json!({"type": "propfind", "depth": "0"}),
    )
    .await;
}
