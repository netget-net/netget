//! Every bound the DoH server enforces past the connection cap and the idle bound
//! (`connection_bounds_test.rs`), and every answer outcome its failure section promises, driven
//! from the wire over real TLS and HTTP/2.
//!
//! | bound / promise | test |
//! |---|---|
//! | `TLS_HANDSHAKE_TIMEOUT` (10 s) | a silent peer and a half-sent ClientHello are open at 6 s, closed by 15 s |
//! | `MAX_DOH_BODY_BYTES` (65535) | a 65535-byte POST is answered; 65536 is 413 and never reaches the model |
//! | `GOAWAY_DRAIN_TIMEOUT` (5 s) | a peer that stops reading is let go at the idle bound plus the drain, not held |
//! | answers: one message per query | an answer with two A actions is the first |
//! | answers: no sendable action | SERVFAIL in a 200, id and question echoed (`fail_closed_no_action`) |
//! | answers: bytes that are not DNS | SERVFAIL in a 200 (`fail_closed_unparseable_answer`) |
//! | answers: a reply past 65535 octets | SERVFAIL in a 200 |
//! | answers: `ignore_query` | 404, no DNS message |
//! | a query with no question | FORMERR in a 200, id echoed (`spec_reply`) |
//! | a body that is not DNS | 400 |
//!
//! Until this pass the DoH server answered a model reply with no sendable action with
//! `500 "No response generated"` — which a DoH client reads as the resolver endpoint being
//! broken — sent unparsed bytes as `application/dns-message`, and answered a query with no
//! question 400. It now answers through `dns::StreamQuery`, the DNS server's own rules, in the
//! 200 RFC 8484 §4.2.1 gives every DNS response.
//!
//! Every query is answered by a Python script handler, so no model is reached. Loopback only.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::connection_bounds_test::NoCertificateVerification;

/// `src/server/doh/mod.rs::TLS_HANDSHAKE_TIMEOUT`, duplicated so a change is re-read here.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// `src/server/doh/mod.rs::MAX_DOH_BODY_BYTES`.
const MAX_DOH_BODY_BYTES: usize = 65_535;
/// `src/server/doh/mod.rs::GOAWAY_DRAIN_TIMEOUT`.
const GOAWAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The answer to every query, chosen by name; the same cases `tests/server/dot/bounds_test.rs`
/// drives, since both answer through the DNS server's rules.
const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); e=i['event']; d=e['domain'].rstrip('.').lower(); qid=e['query_id']
def a(ip): return {'type':'send_dns_a_response','query_id':qid,'domain':e['domain'],'ip':ip,'ttl':60}
if d=='nothing.test': acts=[{'type':'notify_operator','message':'nothing to send'}]
elif d=='silent.test': acts=[{'type':'ignore_query'}]
elif d=='twice.test': acts=[a('192.0.2.1'),a('192.0.2.2')]
elif d=='junk.test': acts=[{'type':'send_dns_response','data':'%04x01000001000000000000'%qid}]
elif d=='huge.test':
    q=bytes.fromhex('%04x8180'%qid)+bytes([0,1,1,44,0,0,0,0])+bytes([4])+b'huge'+bytes([4])+b'test'+bytes([0,0,16,0,1])
    rr=bytes([0xc0,12,0,16,0,1,0,0,0,60,1,0,255])+b'x'*255
    acts=[{'type':'send_dns_response','data':(q+rr*300).hex()}]
else: acts=[a('192.0.2.53')]
print(json.dumps({'actions':acts}))"#;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn start(state: &AppState, startup_params: Option<serde_json::Value>) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "doh".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        startup_params,
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": HANDLER}
        })]),
        ..Default::default()
    }
    .create(state, tx)
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
    (id, port)
}

fn connector() -> TlsConnector {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsConnector::from(Arc::new(config))
}

async fn tls(port: u16) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("static name");
    connector().connect(name, tcp).await.expect("TLS handshake")
}

async fn h2_client(port: u16) -> h2::client::SendRequest<bytes::Bytes> {
    let (client, connection) = h2::client::handshake(tls(port).await)
        .await
        .expect("h2 handshake");
    tokio::spawn(connection);
    client.ready().await.expect("h2 client ready")
}

/// POST `body` as `application/dns-message`; the status and the response body.
async fn post(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    port: u16,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(())
        .expect("build request");
    let mut ready = client.clone().ready().await.expect("h2 ready");
    let (response, mut stream) = ready.send_request(request, false).expect("send request");
    // The body in frames the peer's window admits; a 64 KiB body is more than one window.
    let mut rest = bytes::Bytes::from(body);
    while !rest.is_empty() {
        stream.reserve_capacity(rest.len());
        let granted = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .expect("capacity")
            .expect("capacity granted");
        let chunk = rest.split_to(granted.min(rest.len()));
        stream.send_data(chunk, rest.is_empty()).expect("send body");
    }
    let response = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .expect("no DoH response within 20s")
        .expect("response");
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    (status, out)
}

fn query(domain: &str, id: u16) -> Vec<u8> {
    let mut message = DnsMessage::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_str(domain).expect("valid name"),
        RecordType::A,
    ));
    message.to_vec().expect("a query encodes")
}

async fn dns_reply(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    port: u16,
    body: Vec<u8>,
    what: &str,
) -> DnsMessage {
    let (status, body) = post(client, port, body).await;
    assert_eq!(
        status,
        200,
        "{what}: a DNS response belongs in a 200 (RFC 8484 §4.2.1), got {status} {:?}",
        String::from_utf8_lossy(&body)
    );
    DnsMessage::from_vec(&body).unwrap_or_else(|e| panic!("{what}: not a DNS message: {e}"))
}

fn a_records(message: &DnsMessage) -> Vec<String> {
    message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

fn assert_servfail(reply: &DnsMessage, id: u16, domain: &str, why: &str) {
    assert_eq!(
        reply.response_code,
        ResponseCode::ServFail,
        "{why}: expected SERVFAIL, got {reply:?}"
    );
    assert_eq!(reply.id, id, "{why}: the transaction id was not echoed");
    assert_eq!(
        reply.queries.first().map(|q| q.name().to_string()),
        Some(domain.to_string()),
        "{why}: the question was not echoed"
    );
    assert!(reply.answers.is_empty(), "{why}: SERVFAIL carried answers");
}

#[tokio::test]
async fn every_answer_outcome_is_a_dns_message_in_a_200_or_a_stated_refusal() {
    let state = new_state().await;
    let (_, port) = start(&state, None).await;
    let mut c = h2_client(port).await;

    let r = dns_reply(&mut c, port, query("nothing.test.", 0x0101), "no action").await;
    assert_servfail(
        &r,
        0x0101,
        "nothing.test.",
        "an answer with nothing sendable",
    );

    let r = dns_reply(&mut c, port, query("junk.test.", 0x0202), "junk").await;
    assert_servfail(
        &r,
        0x0202,
        "junk.test.",
        "an answer that is not a DNS message",
    );

    let started = Instant::now();
    let r = dns_reply(&mut c, port, query("huge.test.", 0x0303), "huge").await;
    assert_servfail(&r, 0x0303, "huge.test.", "an answer past 65535 octets");
    assert!(started.elapsed() < Duration::from_secs(15));

    let r = dns_reply(&mut c, port, query("twice.test.", 0x0404), "two answers").await;
    assert_eq!(r.id, 0x0404);
    assert_eq!(a_records(&r), vec!["192.0.2.1".to_string()]);

    let (status, body) = post(&mut c, port, query("silent.test.", 0x0505)).await;
    assert_eq!(
        status, 404,
        "ignore_query is a 404 with no DNS message in it"
    );
    assert!(
        DnsMessage::from_vec(&body).is_err(),
        "ignore_query must not carry a DNS message"
    );

    let empty = DnsMessage::new(0x0606, MessageType::Query, OpCode::Query)
        .to_vec()
        .expect("encode");
    let r = dns_reply(&mut c, port, empty, "a query with no question").await;
    assert_eq!(r.response_code, ResponseCode::FormErr, "{r:?}");
    assert_eq!(r.id, 0x0606);

    let (status, _) = post(&mut c, port, vec![0x77, 0x77, 0x01]).await;
    assert_eq!(status, 400, "three bytes are not a DNS message");

    let r = dns_reply(&mut c, port, query("ok.test.", 0x0707), "ok").await;
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
}

#[tokio::test]
async fn the_body_cap_admits_65535_bytes_and_refuses_one_more_before_the_model() {
    let state = new_state().await;
    let (server_id, port) = start(&state, None).await;
    let mut c = h2_client(port).await;

    // An A query for max.test padded to the cap with a NULL additional record.
    let mut m = vec![0x09, 0x09, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    m.extend_from_slice(&[
        3, b'm', b'a', b'x', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ]);
    m.extend_from_slice(&[0, 0, 10, 0, 1, 0, 0, 0, 0]);
    let rdlength = MAX_DOH_BODY_BYTES - m.len() - 2;
    m.extend_from_slice(&(rdlength as u16).to_be_bytes());
    m.resize(MAX_DOH_BODY_BYTES, 0xab);

    let started = Instant::now();
    let r = dns_reply(&mut c, port, m.clone(), "a body exactly at the cap").await;
    assert_eq!(r.id, 0x0909);
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    assert!(started.elapsed() < Duration::from_secs(10));

    let events_before = state.access_log_total().await;
    m.push(0);
    let (status, _) = post(&mut c, port, m).await;
    assert_eq!(
        status, 413,
        "one byte past MAX_DOH_BODY_BYTES must be refused"
    );
    assert_eq!(
        state.access_log_total().await,
        events_before,
        "the refused body became an event"
    );
    let _ = server_id;
}

/// Same shape as `tests/server/dot/bounds_test.rs`: one silent peer, one that stops part way
/// through its ClientHello.
#[tokio::test]
async fn the_handshake_deadline_holds_a_silent_peer_for_ten_seconds_and_no_longer() {
    let state = new_state().await;
    let (_, port) = start(&state, None).await;
    let mut silent = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut partial = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    partial
        .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01])
        .await
        .expect("partial ClientHello");
    let started = Instant::now();

    let mut probe = [0u8; 1];
    for (stream, what) in [(&mut silent, "silent"), (&mut partial, "partial")] {
        let early = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT
                .mul_f32(0.6)
                .saturating_sub(started.elapsed()),
            stream.read(&mut probe),
        )
        .await;
        assert!(
            early.is_err(),
            "the {what} peer was closed after {:?}, inside the handshake deadline: {early:?}",
            started.elapsed()
        );
    }
    for (stream, what) in [(&mut silent, "silent"), (&mut partial, "partial")] {
        let closed = tokio::time::timeout(
            (TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(5)).saturating_sub(started.elapsed()),
            stream.read(&mut probe),
        )
        .await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "the {what} peer was not closed at the handshake deadline: {closed:?}"
        );
    }
    assert!(started.elapsed() >= TLS_HANDSHAKE_TIMEOUT - Duration::from_millis(500));
}

async fn has_live_connection(state: &AppState, id: ServerId) -> bool {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .any(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
        })
        .unwrap_or(false)
}

/// At the idle bound the server sends GOAWAY and gives it `GOAWAY_DRAIN_TIMEOUT` to go out.
/// A peer that has stopped reading can keep that write from ever finishing; the drain bound is
/// what lets the connection go anyway.
///
/// The peer completes TLS and the HTTP/2 preface, then floods PING frames and never reads. h2
/// answers each PING with an ACK, so the server's writes back up until it stops reading too;
/// PINGs are not queries, so the idle clock runs regardless.
#[tokio::test]
async fn a_peer_that_stops_reading_is_released_at_the_idle_bound_plus_the_drain() {
    let state = new_state().await;
    let idle = Duration::from_secs(3);
    let (server_id, port) = start(
        &state,
        Some(serde_json::json!({"idle_timeout_secs": idle.as_secs()})),
    )
    .await;

    let stream = tls(port).await;
    let (_read_half, mut write) = tokio::io::split(stream);
    // Preface, an empty SETTINGS, then PINGs for as long as the server keeps reading them.
    let mut opening = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    opening.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    write.write_all(&opening).await.expect("preface");
    let started = Instant::now();
    let flood = tokio::spawn(async move {
        let ping = [0u8, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let burst: Vec<u8> = ping
            .iter()
            .copied()
            .cycle()
            .take(ping.len() * 4096)
            .collect();
        loop {
            if write.write_all(&burst).await.is_err() {
                break;
            }
        }
    });

    tokio::time::sleep(idle.mul_f32(0.6)).await;
    assert!(
        has_live_connection(&state, server_id).await,
        "the connection was closed inside the idle bound"
    );
    let deadline = idle + GOAWAY_DRAIN_TIMEOUT + Duration::from_secs(8);
    let mut released = false;
    while started.elapsed() < deadline {
        if !has_live_connection(&state, server_id).await {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        released,
        "a peer that stopped reading still held its connection {:?} after its last byte — the \
         GOAWAY drain is not bounded",
        started.elapsed()
    );
    flood.abort();
}
