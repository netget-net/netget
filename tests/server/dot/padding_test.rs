//! EDNS(0) Padding over DoT (RFC 7830, RFC 8467's 468-octet response blocks; RFC 8310 §8.6
//! recommends it for DNS over TLS). The DoT server answers through `dns::StreamQuery`, so the
//! padding is the DNS server's; this drives it over a real TLS session and with two real
//! clients. `tests/server/dns/padding_test.rs` holds the shared handler and assertions.
//!
//! | promise | how it is driven |
//! |---|---|
//! | a query with a Padding option gets a reply padded to a block | an answer and a SERVFAIL over one TLS session |
//! | the pad never passes 65535 octets | a 65 526-octet answer is sent unpadded, not refused |
//! | a query without one is not padded | EDNS without Padding, and no EDNS |
//! | real clients | kdig `+tls` (which pads its queries by default) and `dig +tls +padding` read padded replies; kdig `+tls +nopadding` reads an unpadded one |
//!
//! Every query is answered by a Python script handler, so no model is reached. Loopback only.

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use netget::cli::management::ServerForm;
use netget::server::dns::PADDING_BLOCK;
use netget::state::app_state::AppState;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::e2e_test::NoCertificateVerification;
use crate::server::dns::padding_test::{
    a_record, assert_dig_padded, assert_kdig_padded, assert_kdig_unpadded, assert_padded,
    assert_unpadded, query, rcode, Ask, HANDLER, NEAR_LIMIT_REPLY,
};
use crate::server::dns::zone_support::run;

async fn start() -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "dot".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": HANDLER}
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("the DoT server did not start");
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the DoT server never bound a port");
    (state, port)
}

async fn session(port: u16) -> TlsStream<TcpStream> {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("static name");
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("TLS handshake")
}

async fn exchange(stream: &mut TlsStream<TcpStream>, message: &[u8]) -> Vec<u8> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).await.expect("write");
    stream.flush().await.expect("flush");
    let len = tokio::time::timeout(Duration::from_secs(20), stream.read_u16())
        .await
        .expect("no DoT reply within 20s")
        .expect("read length");
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await.expect("read reply");
    body
}

#[tokio::test]
async fn dot_replies_are_padded_when_asked_and_only_then() {
    let (_state, port) = start().await;
    let mut stream = session(port).await;

    let reply = exchange(&mut stream, &query("pad.test", 1, Ask::Padding(1232))).await;
    assert_padded(&reply, "DoT answer");
    assert_eq!(reply.len(), PADDING_BLOCK);
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = exchange(&mut stream, &query("nothing.test", 2, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_padded(&reply, "DoT SERVFAIL");

    let reply = exchange(&mut stream, &query("near.test", 3, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::NoError);
    assert_unpadded(&reply, "DoT, 65 526-octet answer");
    assert_eq!(reply.len(), NEAR_LIMIT_REPLY);

    let reply = exchange(&mut stream, &query("pad.test", 4, Ask::EdnsOnly)).await;
    assert_unpadded(&reply, "DoT, EDNS without Padding");
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));
    let reply = exchange(&mut stream, &query("pad.test", 5, Ask::NoEdns)).await;
    assert!(Message::from_vec(&reply).unwrap().edns.is_none());
}

fn args(port: u16, extra: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = vec!["@127.0.0.1".into(), "-p".into(), port.to_string()];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv
}

#[tokio::test]
async fn kdig_and_dig_read_padded_dot_replies() {
    let (_state, port) = start().await;

    let kdig = |extra: &'static [&'static str]| {
        let argv = args(port, extra);
        async move { run("kdig", &argv, "knot-dnsutils (kdig)").await }
    };
    // kdig pads a query over TLS by default (kdig(1), +padding).
    let out = kdig(&["+tls", "+retry=0", "+time=20", "pad.test", "A"]).await;
    assert_kdig_padded(&out, "kdig +tls");
    let out = kdig(&[
        "+tls",
        "+nopadding",
        "+retry=0",
        "+time=20",
        "pad.test",
        "A",
    ])
    .await;
    assert_kdig_unpadded(&out, "kdig +tls +nopadding");

    let out = run(
        "dig",
        &args(
            port,
            &[
                "+tls",
                "+padding=128",
                "+tries=1",
                "+time=20",
                "pad.test",
                "A",
            ],
        ),
        "bind9-dnsutils (dig 9.18 or later, for +tls)",
    )
    .await;
    assert_dig_padded(&out, "dig +tls +padding=128");
}
