//! The peer must be answered when the backend fails — with a category, never a diagnosis.
//!
//! The LLM endpoint is a port nothing listens on, so `call_llm` errors on the very first
//! `xmpp_data_received` event. Before this path existed the server logged a warning and went
//! back to reading, so a client that had just sent its stream header waited on a stream header
//! that was never coming, until its own timeout.
//!
//! RFC 6120 §4.9 defines the frame for exactly this, so the server now sends a fatal
//! `<stream:error/>` and closes. §4.9.1.1 requires an opening stream tag before it, which
//! matters here because the model never answered and therefore never opened the stream.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test server -- xmpp::llm_failure --test-threads=100

#![cfg(unix)]

use std::str::FromStr;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use xmpp_parsers::minidom::Element;

const STREAMS_NS: &str = "urn:ietf:params:xml:ns:xmpp-streams";
const STREAM_NS: &str = "http://etherx.jabber.org/streams";

const CLIENT_HEADER: &str = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
     xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";

/// Port 1 on loopback: nothing listens, so every LLM call fails immediately.
async fn state_with_dead_backend() -> AppState {
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

/// Nothing internal may appear in what the peer reads. These are the tokens that leaked
/// across ~25 protocols in the original incident (see tests/wire_failure_test.rs).
fn assert_no_internals(raw: &str) {
    for token in [
        "✗",
        "retries",
        "http://127.0.0.1",
        "11434",
        "qwen",
        "/Users/",
        "LLM",
        "Ollama",
        "ollama",
        "error sending request",
        "anyhow",
    ] {
        assert!(
            !raw.contains(token),
            "xmpp stream error leaked {token:?}: {raw:?}"
        );
    }
}

#[tokio::test]
async fn backend_failure_sends_a_stream_error_carrying_only_a_category() {
    let state = state_with_dead_backend().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event handlers at all: every event goes to the (dead) backend.
    let server_id = ServerForm {
        protocol: "xmpp".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create xmpp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(CLIENT_HEADER.as_bytes())
        .await
        .expect("send stream header");
    stream.flush().await.expect("flush");

    // Read to EOF: a stream error is fatal, so the server closes right after it.
    let mut raw = String::new();
    let n = tokio::time::timeout(Duration::from_secs(60), stream.read_to_string(&mut raw))
        .await
        .expect("the peer must be answered, not left hanging")
        .expect("read");
    assert!(n > 0, "peer got EOF instead of a stream error");

    assert_no_internals(&raw);

    // The model never answered, so the server owed the peer an opening tag too — without one
    // a real client's parser rejects the error as a second root element.
    let body = raw
        .strip_prefix("<?xml version='1.0'?>")
        .expect("stream error must be preceded by an opening stream tag");
    let doc = Element::from_str(body).expect("server half of the stream must be well-formed XML");
    assert_eq!(doc.name(), "stream", "not a stream element: {raw:?}");
    assert_eq!(doc.ns(), STREAM_NS);

    let err = doc
        .children()
        .find(|c| c.is("error", STREAM_NS))
        .unwrap_or_else(|| panic!("no <stream:error/> in {raw:?}"));

    // A defined stream condition, and the two WireFailure categories map onto *different*
    // ones so a client can back off rather than record a permanent fault. A refused
    // connection classifies as Unavailable.
    let condition = err
        .children()
        .find(|c| c.name() != "text")
        .unwrap_or_else(|| panic!("no stream condition in {raw:?}"));
    assert_eq!(condition.ns(), STREAMS_NS);
    assert!(
        matches!(
            condition.name(),
            "internal-server-error" | "resource-constraint"
        ),
        "unexpected stream condition {:?}",
        condition.name()
    );
    assert_eq!(
        condition.name(),
        "internal-server-error",
        "a dead backend is Unavailable, not Overloaded"
    );

    let text = err
        .children()
        .find(|c| c.is("text", STREAMS_NS))
        .map(|t| t.text())
        .unwrap_or_default();
    assert!(
        text == "request could not be processed" || text == "backend at capacity, retry later",
        "<text/> is not a WireFailure category: {text:?}"
    );

    assert!(
        raw.trim_end().ends_with("</stream:stream>"),
        "stream was not closed after the fatal error: {raw:?}"
    );
}
