//! Every bound the DoT server enforces, and every answer outcome its failure section promises,
//! driven from the wire over a real TLS session.
//!
//! The six-conditions pass for `dot` (November 2026) read `src/server/dot/AGENTS.md` as a list
//! of assertions. Each test below is one of them, at its boundary, from both sides where the
//! bound has two:
//!
//! | bound / promise | test |
//! |---|---|
//! | `TLS_HANDSHAKE_TIMEOUT` (10 s) | a silent peer and a half-sent ClientHello are open at 6 s, closed by 15 s |
//! | `idle_timeout_secs` (default 300) | a query 2 s into a 3 s bound is answered; silence after it closes the connection; 0 and 3601 refused |
//! | `MESSAGE_READ_TIMEOUT` (10 s) | a body finished 4 s after its prefix is answered (`connection_bounds_test.rs` has the other side) |
//! | the u16 length prefix (65535) | a 65535-byte query is read whole and answered; a zero length closes |
//! | the compression-pointer screen | a 2 000-hop chain closes its connection, and the server answers the next one |
//! | answers: one message per query | an answer with two A actions puts exactly one reply on the wire |
//! | answers: no sendable action | SERVFAIL, id and question echoed (`fail_closed_no_action`) |
//! | answers: bytes that are not DNS | SERVFAIL (`fail_closed_unparseable_answer`) |
//! | answers: a reply past 65535 octets | SERVFAIL, and the stream stays framed for the next query |
//! | answers: `ignore_query` | nothing, and the connection goes on |
//! | a query with no question | FORMERR, id echoed (`spec_reply`) |
//!
//! Until this pass the five "answers" rows were false: the DoT server wrote nothing for a model
//! answer with no sendable action, sent every message an answer produced, put unparsed bytes on
//! the wire, refused an oversize reply by writing nothing, and treated a query with no question
//! or an undecodable message as something to skip while the resolver waited. It now answers
//! through `dns::StreamQuery`, the DNS server's own rules.
//!
//! Every query is answered by a Python script handler, so no model is reached and every answer
//! is exactly the one the test names. Loopback only.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::e2e_test::NoCertificateVerification;

/// `src/server/dot/mod.rs::TLS_HANDSHAKE_TIMEOUT`. Duplicated rather than imported, so a change
/// to the constant makes this file be re-read rather than silently follow it.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `src/server/dot/mod.rs::MESSAGE_READ_TIMEOUT`.
const MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The answer to every query, chosen by name. The names are the cases in the table above.
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

async fn create(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
) -> anyhow::Result<ServerId> {
    let (tx, _rx) = mpsc::unbounded_channel();
    ServerForm {
        protocol: "dot".to_string(),
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
}

async fn start(state: &AppState, startup_params: Option<serde_json::Value>) -> u16 {
    let id = create(state, startup_params)
        .await
        .expect("the DoT server did not start");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the DoT server never bound a port")
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
    TlsConnector::from(Arc::new(config))
}

async fn session(port: u16) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("static name");
    connector().connect(name, tcp).await.expect("TLS handshake")
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

async fn send(stream: &mut TlsStream<TcpStream>, message: &[u8]) {
    let len = u16::try_from(message.len()).expect("a DNS message fits the prefix");
    stream
        .write_all(&len.to_be_bytes())
        .await
        .expect("write prefix");
    stream.write_all(message).await.expect("write message");
    stream.flush().await.expect("flush");
}

/// One framed reply, or `None` if nothing arrived within `wait`. Panics on EOF: the tests that
/// expect a close say so with [`assert_closed`].
async fn reply(stream: &mut TlsStream<TcpStream>, wait: Duration) -> Option<DnsMessage> {
    let mut len = [0u8; 2];
    match tokio::time::timeout(wait, stream.read_exact(&mut len)).await {
        Err(_) => return None,
        Ok(Err(e)) => panic!("the connection ended where a reply was expected: {e}"),
        Ok(Ok(_)) => {}
    }
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("a length prefix arrived without its message")
        .expect("read the reply");
    Some(DnsMessage::from_vec(&body).expect("the reply is a DNS message"))
}

async fn answered(stream: &mut TlsStream<TcpStream>, what: &str) -> DnsMessage {
    reply(stream, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| panic!("no reply to {what} within 20s"))
}

/// The peer reads EOF (or a reset) within `within`.
async fn assert_closed<S: AsyncReadExt + Unpin>(stream: &mut S, within: Duration, what: &str) {
    let mut sink = [0u8; 512];
    let outcome = tokio::time::timeout(within, async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(
        outcome.is_ok(),
        "{what}: the connection was still open after {within:?}"
    );
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
async fn every_answer_outcome_is_one_message_or_a_decision_to_send_none() {
    let state = new_state().await;
    let port = start(&state, None).await;
    let mut s = session(port).await;

    // Nothing sendable: the model answered, but only with a common action.
    send(&mut s, &query("nothing.test.", 0x0101)).await;
    let r = answered(&mut s, "an answer with no DNS action").await;
    assert_servfail(
        &r,
        0x0101,
        "nothing.test.",
        "an answer with nothing sendable",
    );

    // Bytes that are not a DNS message (a header promising a question that is not there).
    send(&mut s, &query("junk.test.", 0x0202)).await;
    let r = answered(&mut s, "an answer of unparseable bytes").await;
    assert_servfail(
        &r,
        0x0202,
        "junk.test.",
        "an answer that is not a DNS message",
    );

    // A reply past RFC 7858's 16-bit length: 300 TXT records of 255 octets, ~80 KB.
    let started = Instant::now();
    send(&mut s, &query("huge.test.", 0x0303)).await;
    let r = answered(&mut s, "an answer too large to frame").await;
    assert_servfail(&r, 0x0303, "huge.test.", "an answer past 65535 octets");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the oversize answer took {:?} to refuse",
        started.elapsed()
    );

    // Two answers to one query: exactly one goes out. The next frame on the stream must be the
    // reply to the *next* query, which is what "one" means on a pinned connection.
    send(&mut s, &query("twice.test.", 0x0404)).await;
    let r = answered(&mut s, "an answer with two A actions").await;
    assert_eq!(r.id, 0x0404);
    assert_eq!(
        a_records(&r),
        vec!["192.0.2.1".to_string()],
        "the first A action is the answer"
    );
    send(&mut s, &query("ok.test.", 0x0505)).await;
    let r = answered(&mut s, "the query after the two-answer one").await;
    assert_eq!(
        r.id, 0x0505,
        "the frame after a two-action answer was not the next query's reply — a second reply \
         to 0x0404 was written: {r:?}"
    );
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);

    // ignore_query: nothing, and the connection carries on.
    send(&mut s, &query("silent.test.", 0x0606)).await;
    assert!(
        reply(&mut s, Duration::from_secs(3)).await.is_none(),
        "ignore_query is a decision to send nothing"
    );
    send(&mut s, &query("ok.test.", 0x0707)).await;
    let r = answered(&mut s, "the query after ignore_query").await;
    assert_eq!(r.id, 0x0707);

    // No question: FORMERR from the server itself, id echoed.
    let empty = DnsMessage::new(0x0808, MessageType::Query, OpCode::Query)
        .to_vec()
        .expect("encode");
    send(&mut s, &empty).await;
    let r = answered(&mut s, "a query with no question").await;
    assert_eq!(r.response_code, ResponseCode::FormErr, "{r:?}");
    assert_eq!(r.id, 0x0808);
}

#[tokio::test]
async fn the_largest_message_the_prefix_can_carry_is_read_whole_and_a_zero_length_closes() {
    let state = new_state().await;
    let port = start(&state, None).await;

    // 65535 octets: an A query for max.test plus one NULL additional record padding it out.
    let mut m = vec![0x09, 0x09, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    m.extend_from_slice(&[
        3, b'm', b'a', b'x', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ]);
    m.extend_from_slice(&[0, 0, 10, 0, 1, 0, 0, 0, 0]);
    let rdlength = 65535 - m.len() - 2;
    m.extend_from_slice(&(rdlength as u16).to_be_bytes());
    m.resize(65535, 0xab);
    assert_eq!(m.len(), 65535);

    let mut s = session(port).await;
    let started = Instant::now();
    send(&mut s, &m).await;
    let r = answered(&mut s, "a 65535-octet query").await;
    assert_eq!(r.id, 0x0909);
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a 64 KiB query took {:?}",
        started.elapsed()
    );

    // A zero length announces no message at all; the server closes rather than read one.
    s.write_all(&[0, 0]).await.expect("zero prefix");
    s.flush().await.expect("flush");
    assert_closed(&mut s, Duration::from_secs(5), "a zero-length prefix").await;
}

/// Header + a root question + one NULL answer whose RDATA is `links` pointers each aiming at
/// the one before, + an additional record whose owner points at the last link. The shape
/// `tests/server/dns/compression_chain_test.rs` sends to the DNS server.
fn pointer_chain(links: usize) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 1];
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]);
    m.push(0);
    m.extend_from_slice(&[0, 10, 0, 1, 0, 0, 0, 0]);
    let rdlength_at = m.len();
    m.extend_from_slice(&[0, 0]);
    let rdata_start = m.len();
    let mut previous = 12u16;
    for _ in 0..links {
        let here = m.len() as u16;
        m.extend_from_slice(&(0xC000 | previous).to_be_bytes());
        previous = here;
    }
    let rdlength = (m.len() - rdata_start) as u16;
    m[rdlength_at..rdlength_at + 2].copy_from_slice(&rdlength.to_be_bytes());
    m.extend_from_slice(&(0xC000 | previous).to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    m
}

#[tokio::test]
async fn an_undecodable_query_closes_its_connection_and_the_server_answers_the_next() {
    let state = new_state().await;
    let port = start(&state, None).await;

    // A chain far past `dns_screen::MAX_POINTER_HOPS`: refused before hickory sees it. Nothing
    // in it can be answered — no id or question was read — so the connection closes, which a
    // resolver acts on at once; it used to stay open with the query unanswered.
    let mut s = session(port).await;
    send(&mut s, &pointer_chain(2_000)).await;
    assert_closed(&mut s, Duration::from_secs(5), "a pointer-chain bomb").await;

    // Twelve bytes promising a question that is not there: undecodable the ordinary way.
    let mut s = session(port).await;
    send(&mut s, &[0x55, 0x55, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    assert_closed(&mut s, Duration::from_secs(5), "a truncated question").await;

    let mut s = session(port).await;
    send(&mut s, &query("ok.test.", 0x0a0a)).await;
    let r = answered(&mut s, "a legal query after the bomb").await;
    assert_eq!(r.id, 0x0a0a, "the server stopped answering after the bomb");
}

#[tokio::test]
async fn the_handshake_deadline_holds_a_silent_peer_for_ten_seconds_and_no_longer() {
    let state = new_state().await;
    let port = start(&state, None).await;

    // One peer says nothing; the other sends a TLS record header promising a 512-byte
    // ClientHello and then stops. Both are inside `acceptor.accept()`.
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

    // Still held well inside the deadline: the bound is not shorter than declared.
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
            "the {what} peer was closed after {:?}, inside the {TLS_HANDSHAKE_TIMEOUT:?} \
             handshake deadline: {early:?}",
            started.elapsed()
        );
    }
    // And released at it.
    for (stream, what) in [(&mut silent, "silent"), (&mut partial, "partial")] {
        assert_closed(
            stream,
            (TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(5)).saturating_sub(started.elapsed()),
            what,
        )
        .await;
    }
    assert!(
        started.elapsed() >= TLS_HANDSHAKE_TIMEOUT - Duration::from_millis(500),
        "closed after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn the_idle_bound_is_the_declared_one_and_resets_on_every_query() {
    let state = new_state().await;
    let idle = Duration::from_secs(3);
    let port = start(
        &state,
        Some(serde_json::json!({"idle_timeout_secs": idle.as_secs()})),
    )
    .await;
    let mut s = session(port).await;

    // Three queries, each 2 s after the last answer: inside the bound every time, so the
    // connection is still there — six seconds in, twice the bound, because each query resets it.
    for id in [0x0b01u16, 0x0b02, 0x0b03] {
        send(&mut s, &query("ok.test.", id)).await;
        let r = answered(&mut s, "a query inside the idle bound").await;
        assert_eq!(r.id, id);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Then silence: closed at the bound, not before half of it and not long after it.
    let started = Instant::now() - Duration::from_secs(2);
    assert_closed(
        &mut s,
        idle + Duration::from_secs(10),
        "an idle DoT connection",
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= idle - Duration::from_millis(500),
        "closed after {elapsed:?}, inside the declared {idle:?}"
    );

    // Out of range is refused at start rather than clamped.
    for bad in [0u64, 3601] {
        let err = create(&state, Some(serde_json::json!({"idle_timeout_secs": bad})))
            .await
            .expect_err("an out-of-range idle_timeout_secs was accepted");
        assert!(
            format!("{err:#}").contains("idle_timeout_secs"),
            "the refusal does not name the parameter: {err:#}"
        );
    }
}

#[tokio::test]
async fn a_body_finished_inside_the_message_deadline_is_answered() {
    let state = new_state().await;
    let port = start(&state, None).await;
    let mut s = session(port).await;

    // The prefix, then the body four seconds later: slow, but inside `MESSAGE_READ_TIMEOUT`.
    // `connection_bounds_test.rs` holds the other side (a body that never finishes is closed).
    let q = query("ok.test.", 0x0c0c);
    s.write_all(&(q.len() as u16).to_be_bytes())
        .await
        .expect("prefix");
    s.write_all(&q[..3]).await.expect("first bytes");
    s.flush().await.expect("flush");
    tokio::time::sleep(MESSAGE_READ_TIMEOUT.mul_f32(0.4)).await;
    s.write_all(&q[3..]).await.expect("rest");
    s.flush().await.expect("flush");
    let r = answered(&mut s, "a slow but complete body").await;
    assert_eq!(r.id, 0x0c0c);
}
