//! Does the XMPP client answer the stanzas its server sent during a model call together, when
//! it batches?
//!
//! The event loop used to call the model inline, so while the model answered it neither read
//! the stream nor wrote the model's own stanzas, and the Idle/Processing/Accumulating queue it
//! carried could never fill. Message and presence stanzas now go to an answering task over a
//! queue; it answers one per call (off) or everything waiting in one call through
//! `call_llm_for_client_batch` (on).
//!
//! This is also the first test in the tree that takes the XMPP client past tokio-xmpp's
//! `Online`, so the model path runs at all. tokio-xmpp insists on STARTTLS against a
//! certificate from the platform roots, which it reads through `rustls-native-certs` - and
//! that honours `SSL_CERT_FILE`. So the server written here presents a fresh self-signed
//! certificate for `localhost`, `SSL_CERT_FILE` names it, and the server walks the client
//! through STARTTLS, SASL PLAIN and resource binding by hand. Setting an environment variable
//! is process-wide, which is why this is a test binary of its own with one test in it.
//!
//! Once online the server sends a chat message `first`, which the mock model answers slowly,
//! then `second` and `third` during that call. Batching off is the control, in the same test as
//! the claim: three model calls, or a two-call result would prove nothing.

#![cfg(unix)]

mod helpers;

use std::sync::Arc;
use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

const MESSAGE_EVENT: &str = "xmpp_message_received";

const STREAM_HEADER: &str = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
     xmlns:stream='http://etherx.jabber.org/streams' id='s1' from='localhost' version='1.0'>";

/// Read until `needle` has arrived, and return everything read.
async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, needle: &str) -> String {
    let mut seen = String::new();
    let mut buf = [0u8; 4096];
    while !seen.contains(needle) {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("waiting for {needle:?}; got {seen:?}"))
            .expect("read");
        assert!(
            n > 0,
            "the client hung up waiting for {needle:?}; got {seen:?}"
        );
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    seen
}

/// Read the client's stream header, which is complete once its `<stream:stream ...>` tag is.
async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut seen = read_until(stream, "<stream:stream").await;
    while !seen[seen.find("<stream:stream").unwrap()..].contains('>') {
        seen.push_str(&read_until(stream, ">").await);
    }
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, xml: &str) {
    stream.write_all(xml.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
}

/// The server half up to `Online`: STARTTLS, SASL PLAIN (any password), resource binding.
async fn negotiate(
    socket: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    let mut socket = socket;
    read_header(&mut socket).await;
    send(
        &mut socket,
        &format!(
            "{STREAM_HEADER}<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\
             <required/></starttls></stream:features>"
        ),
    )
    .await;
    read_until(&mut socket, "starttls").await;
    send(
        &mut socket,
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )
    .await;
    let mut tls = acceptor.accept(socket).await.expect("TLS handshake");

    read_header(&mut tls).await;
    send(
        &mut tls,
        &format!(
            "{STREAM_HEADER}<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>\
             <mechanism>PLAIN</mechanism></mechanisms></stream:features>"
        ),
    )
    .await;
    read_until(&mut tls, "</auth>").await;
    send(
        &mut tls,
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
    )
    .await;

    read_header(&mut tls).await;
    send(
        &mut tls,
        &format!(
            "{STREAM_HEADER}<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>\
             </stream:features>"
        ),
    )
    .await;
    read_until(&mut tls, "</iq>").await;
    send(
        &mut tls,
        "<iq type='result' id='resource-binding'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>\
         <jid>alice@localhost/netget</jid></bind></iq>",
    )
    .await;
    tls
}

fn chat(body: &str) -> String {
    format!(
        "<message from='bob@localhost/phone' to='alice@localhost/netget' type='chat'>\
         <body>{body}</body></message>"
    )
}

/// One session: returns the (body, prompt) of every message event the model was asked about.
async fn session(acceptor: tokio_rustls::TlsAcceptor, batching: bool) -> Vec<(String, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(MESSAGE_EVENT)
            .and_event_data_contains("body", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        negotiate(socket, acceptor).await
    });

    let (tx, _rx) = mpsc::unbounded_channel();
    // `create` returns once the session is online, which needs the server above.
    let id = ClientForm {
        protocol: "xmpp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what your contacts say.".to_string()),
        startup_params: Some(serde_json::json!({
            "jid": "alice@localhost",
            "password": "secret",
            "session_timeout_secs": 20,
        })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let tls = tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .expect("negotiation")
        .expect("server task");
    let (mut read, mut write) = tokio::io::split(tls);
    // Keep reading whatever the client sends from here on.
    let drain = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while matches!(read.read(&mut buf).await, Ok(n) if n > 0) {}
    });

    let message_calls = |calls: Vec<helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(MESSAGE_EVENT))
            .map(|c| {
                (
                    c.context.event_data["body"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    c.context.prompt.clone(),
                )
            })
            .collect::<Vec<_>>()
    };

    send(&mut write, &chat("first")).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while message_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    send(&mut write, &chat("second")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&mut write, &chat("third")).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = message_calls(mock.recorded_calls().await);
        if calls.iter().any(|(b, _)| b == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:?}",
            calls.iter().map(|(b, _)| b).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = message_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    drain.abort();
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xmpp_client_answers_what_arrived_during_a_call_together() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let dir = tempfile::tempdir().expect("tempdir");
    let roots = dir.path().join("roots.pem");
    std::fs::write(&roots, issued.cert.pem()).expect("write roots");
    // The only test in this binary, set before the client exists: nothing else reads it.
    std::env::set_var("SSL_CERT_FILE", &roots);

    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
        issued.signing_key.serialize_der(),
    )
    .expect("key");
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert.der().clone()], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let separate = session(acceptor.clone(), false).await;
    let bodies: Vec<&str> = separate.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(
        bodies,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(acceptor, true).await;
    let bodies: Vec<&str> = batched.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(
        bodies,
        vec!["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt
        .rfind("Event: xmpp_message_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find("(1) xmpp_message_received")
        .expect("the earlier message must be listed as arrived and not yet answered");
    assert!(
        before[listed..].contains("second"),
        "the listed message must be `second`:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}
