//! EDNS(0) Padding over DoH (RFC 7830, RFC 8467's 468-octet response blocks; RFC 8484 §8.1
//! points at both). The DoH server answers through `dns::StreamQuery`, so the padding is the
//! DNS server's; this drives it over HTTP/2 on a real TLS session and with two real clients.
//! `tests/server/dns/padding_test.rs` holds the shared handler and assertions.
//!
//! | promise | how it is driven |
//! |---|---|
//! | a query with a Padding option gets a reply padded to a block | an answer and a SERVFAIL, POSTed on one HTTP/2 connection |
//! | the pad never passes 65535 octets | a 65 526-octet answer is sent unpadded, not refused |
//! | a query without one is not padded | EDNS without Padding, and no EDNS |
//! | real clients | kdig `+https` (which pads its queries by default, as over TLS) and `dig +https +padding` read padded replies; kdig `+https +nopadding` reads an unpadded one |
//!
//! Every query is answered by a Python script handler, so no model is reached. Loopback only.

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use netget::cli::management::ServerForm;
use netget::server::dns::PADDING_BLOCK;
use netget::state::app_state::AppState;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

use super::connection_bounds_test::NoCertificateVerification;
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
        protocol: "doh".to_string(),
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
    .expect("the DoH server did not start");
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the DoH server never bound a port");
    (state, port)
}

async fn h2_client(port: u16) -> h2::client::SendRequest<bytes::Bytes> {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("static name");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("TLS handshake");
    let (client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    client.ready().await.expect("h2 client ready")
}

/// POST one query as `application/dns-message` and return the 200's body, the DNS reply.
async fn post(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    port: u16,
    body: Vec<u8>,
) -> Vec<u8> {
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(())
        .expect("build request");
    let mut ready = client.clone().ready().await.expect("h2 ready");
    let (response, mut stream) = ready.send_request(request, false).expect("send request");
    stream
        .send_data(bytes::Bytes::from(body), true)
        .expect("send body");
    let response = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .expect("no DoH response within 20s")
        .expect("response");
    assert_eq!(response.status().as_u16(), 200, "a DNS reply is a 200");
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    out
}

#[tokio::test]
async fn doh_replies_are_padded_when_asked_and_only_then() {
    let (_state, port) = start().await;
    let mut client = h2_client(port).await;

    let reply = post(&mut client, port, query("pad.test", 1, Ask::Padding(1232))).await;
    assert_padded(&reply, "DoH answer");
    assert_eq!(reply.len(), PADDING_BLOCK);
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = post(
        &mut client,
        port,
        query("nothing.test", 2, Ask::Padding(1232)),
    )
    .await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_padded(&reply, "DoH SERVFAIL");

    let reply = post(&mut client, port, query("near.test", 3, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::NoError);
    assert_unpadded(&reply, "DoH, 65 526-octet answer");
    assert_eq!(reply.len(), NEAR_LIMIT_REPLY);

    let reply = post(&mut client, port, query("pad.test", 4, Ask::EdnsOnly)).await;
    assert_unpadded(&reply, "DoH, EDNS without Padding");
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));
    let reply = post(&mut client, port, query("pad.test", 5, Ask::NoEdns)).await;
    assert!(Message::from_vec(&reply).unwrap().edns.is_none());
}

fn args(port: u16, extra: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = vec!["@127.0.0.1".into(), "-p".into(), port.to_string()];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv
}

#[tokio::test]
async fn kdig_and_dig_read_padded_doh_replies() {
    let (_state, port) = start().await;

    // `+https=/dns-query`, path only: see `real_client_test.rs::kdig_doh` for why no authority.
    let kdig = |extra: &'static [&'static str]| {
        let argv = args(port, extra);
        async move { run("kdig", &argv, "knot-dnsutils (kdig)").await }
    };
    let out = kdig(&["+https=/dns-query", "+retry=0", "+time=20", "pad.test", "A"]).await;
    assert_kdig_padded(&out, "kdig +https");
    let out = kdig(&[
        "+https=/dns-query",
        "+nopadding",
        "+retry=0",
        "+time=20",
        "pad.test",
        "A",
    ])
    .await;
    assert_kdig_unpadded(&out, "kdig +https +nopadding");

    let out = run(
        "dig",
        &args(
            port,
            &[
                "+https",
                "+padding=128",
                "+tries=1",
                "+time=20",
                "pad.test",
                "A",
            ],
        ),
        "bind9-dnsutils (dig 9.18 or later, for +https)",
    )
    .await;
    assert_dig_padded(&out, "dig +https +padding=128");
}
