//! Every bound the DoQ server declares, and every answer outcome its AGENTS.md promises, driven
//! from the wire over a real QUIC connection.
//!
//! | bound / promise | test |
//! |---|---|
//! | answers: no sendable action | SERVFAIL, id 0 and question echoed (`fail_closed_no_action`) |
//! | answers: one message per query | two A actions put exactly one answer, the first, on the stream |
//! | answers: past 65535 octets | SERVFAIL, not a NOERROR cut short with TC |
//! | answers: `ignore_query` | the stream is reset with DOQ_NO_ERROR |
//! | answers: an EDNS query | the answer carries an OPT |
//! | answers: question binding | an action written for another name still answers this question, id 0 |
//! | answers: any record type | an SRV query reaches the model and is answered |
//! | spec replies | no question and two questions FORMERR; class CH NOTIMP, without the model |
//! | `exchange_timeout_secs` | a handler inside the bound is answered; one past it gets SERVFAIL at the bound |
//! | `RESPONSE_WRITE_TIMEOUT` (5 s) | a peer granting no stream credit has the stream reset with DOQ_INTERNAL_ERROR |
//! | `idle_timeout_secs` | queries 2 s apart under a 3 s bound are answered; silence then closes |
//! | `max_streams` | two slow queries run in parallel; a third stream waits for credit |
//! | the frame bound (65535 + 2) | a 65535-byte query is answered; one byte more closes with DOQ_PROTOCOL_ERROR |
//! | parameter ranges | 0 and one past the maximum refuse to start, for all five |
//!
//! `e2e_test.rs` has the dangling-query reset, the handshake and connection caps, cancellation and
//! the protocol-error closes. Every query is answered by a Python script handler, so no model is
//! reached. Loopback only.
use super::support::*;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use netget::client::doq::exchange;
use netget::server::doq::wire::{encode, MAX_FRAME_BYTES, PROTOCOL_ERROR};
use serde_json::json;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// `src/server/doq/wire.rs::RESPONSE_WRITE_TIMEOUT`, duplicated so a change to it makes this file
/// be re-read.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The answer to every query, chosen by name. `slow-<ms>.test` sleeps that long first.
const HANDLER: &str = r#"import json,sys,time
e=json.load(sys.stdin)['event']; d=e['domain'].rstrip('.').lower()
def a(ip): return {'type':'send_dns_a_response','query_id':0,'domain':e['domain'],'ip':ip,'ttl':60}
if d=='nothing.test': acts=[{'type':'notify_operator','message':'nothing to send'}]
elif d=='empty.test': acts=[]
elif d=='silent.test': acts=[{'type':'ignore_query'}]
elif d=='twice.test': acts=[a('192.0.2.1'),a('192.0.2.2')]
elif d=='huge.test': acts=[{'type':'send_dns_records','query_id':0,'domain':e['domain'],'query_type':'TXT','answers':[{'type':'TXT','text':['x'*255]*3} for _ in range(100)]}]
elif d=='srv.test': acts=[{'type':'send_dns_records','query_id':0,'domain':e['domain'],'query_type':'SRV','answers':[{'type':'SRV','priority':0,'weight':5,'port':853,'target':'dns.srv.test.'}]}]
elif d=='other.test': acts=[{'type':'send_dns_a_response','query_id':7,'domain':'elsewhere.test','ip':'192.0.2.7'}]
elif d.startswith('slow-'):
    time.sleep(int(d[5:].split('.')[0])/1000); acts=[a('192.0.2.88')]
else: acts=[a('192.0.2.53')]
print(json.dumps({'actions':acts}))"#;

async fn fixture(params: serde_json::Value) -> Fixture {
    Fixture::new(
        params,
        Some(json!({"type":"script","language":"python","code":HANDLER})),
    )
    .await
}

fn a_records(message: &Message) -> Vec<String> {
    message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

/// The query's frame, written and FINed on a fresh stream; what came back, or how it was reset.
async fn raw(
    c: &quinn::Connection,
    frame: &[u8],
    wait: Duration,
) -> Result<Vec<u8>, quinn::ReadToEndError> {
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(frame).await.unwrap();
    send.finish().unwrap();
    tokio::time::timeout(wait, recv.read_to_end(MAX_FRAME_BYTES))
        .await
        .expect("the stream neither answered nor reset")
}

fn reset_code(result: Result<Vec<u8>, quinn::ReadToEndError>) -> u64 {
    match result {
        Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => code.into_inner(),
        other => panic!("expected a RESET_STREAM, got {other:?}"),
    }
}

async fn ask(c: &quinn::Connection, domain: &str, kind: &str) -> Message {
    exchange(c, &query(domain, kind), Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("{domain} {kind}: {e:#}"))
        .0
}

fn assert_servfail(r: &Message, domain: &str, what: &str) {
    assert_eq!(r.response_code, ResponseCode::ServFail, "{what}: {r:?}");
    assert_eq!(r.id, 0, "{what}: the id");
    assert_eq!(r.queries.len(), 1, "{what}: the question");
    assert_eq!(r.queries[0].name().to_string(), domain, "{what}");
    assert!(r.answers.is_empty(), "{what}: {r:?}");
}

#[tokio::test]
async fn an_answer_with_nothing_sendable_is_servfail() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    let r = ask(&c, "nothing.test", "A").await;
    assert_servfail(
        &r,
        "nothing.test.",
        "an answer holding only notify_operator",
    );
    f.decision("decision=fail_closed_no_action").await;
    let r = ask(&c, "empty.test", "A").await;
    assert_servfail(&r, "empty.test.", "an empty answer");
    // The connection goes on.
    let r = ask(&c, "plain.test", "A").await;
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    f.close().await;
}

#[tokio::test]
async fn two_messages_answer_with_the_first() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    let r = ask(&c, "twice.test", "A").await;
    assert_eq!(r.response_code, ResponseCode::NoError);
    assert_eq!(
        a_records(&r),
        vec!["192.0.2.1".to_string()],
        "two A actions answer with the first message, not a merge of both"
    );
    f.close().await;
}

#[tokio::test]
async fn an_answer_past_65535_octets_is_servfail() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    // 100 TXT records of three 255-octet strings: ~77 KB, past the 16-bit length.
    let started = Instant::now();
    let r = ask(&c, "huge.test", "TXT").await;
    assert_servfail(&r, "huge.test.", "an answer past 65535 octets");
    assert!(
        !r.metadata.truncation,
        "SERVFAIL, not a TC answer cut short"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    f.decision("decision=fail_closed_oversize_answer").await;
    f.close().await;
}

#[tokio::test]
async fn ignore_query_resets_the_stream_with_no_error() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    let silent = encode(&query("silent.test", "A")).unwrap();
    assert_eq!(
        reset_code(raw(&c, &silent, Duration::from_secs(5)).await),
        0,
        "ignore_query resets the stream with DOQ_NO_ERROR"
    );
    let r = ask(&c, "plain.test", "A").await;
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    f.close().await;
}

#[tokio::test]
async fn an_edns_query_is_answered_with_an_opt() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    let mut edns = query("plain.test", "A");
    edns.set_edns(Edns::new());
    let r = exchange(&c, &edns, Duration::from_secs(5)).await.unwrap().0;
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    assert!(r.edns.is_some(), "an EDNS query is answered with an OPT");
    let r = ask(&c, "plain.test", "A").await;
    assert!(r.edns.is_none(), "a query without EDNS gets no OPT");
    f.close().await;
}

#[tokio::test]
async fn an_answer_built_for_another_question_answers_this_one() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    // The action names another domain and a non-zero id; the stream's question and id 0 win.
    let r = ask(&c, "other.test", "ANY").await;
    assert_eq!(r.id, 0);
    assert_eq!(r.queries[0].name().to_string(), "other.test.");
    assert_eq!(r.queries[0].query_type(), RecordType::ANY);
    assert_eq!(a_records(&r), vec!["192.0.2.7".to_string()]);
    f.close().await;
}

#[tokio::test]
async fn any_record_type_reaches_the_model() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;
    let r = ask(&c, "srv.test", "SRV").await;
    assert_eq!(r.response_code, ResponseCode::NoError, "{r:?}");
    assert!(
        matches!(&r.answers[..], [rr] if matches!(&rr.data, RData::SRV(s) if s.port == 853)),
        "an SRV query reaches the model: {r:?}"
    );
    f.close().await;
}

#[tokio::test]
async fn queries_the_server_does_not_serve_are_answered_without_the_model() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;

    let none = Message::new(0, MessageType::Query, OpCode::Query);
    let r = exchange(&c, &none, Duration::from_secs(5)).await.unwrap().0;
    assert_eq!(r.response_code, ResponseCode::FormErr);
    assert_eq!(r.id, 0);

    let mut two = query("one.test", "A");
    two.add_query(Query::query(
        Name::from_str("two.test.").unwrap(),
        RecordType::A,
    ));
    let r = exchange(&c, &two, Duration::from_secs(5)).await.unwrap().0;
    assert_eq!(r.response_code, ResponseCode::FormErr);
    assert_eq!(r.queries.len(), 2, "both questions are echoed");

    let mut chaos = query("version.bind", "TXT");
    let mut q = chaos.queries[0].clone();
    q.set_query_class(DNSClass::CH);
    chaos.queries = vec![q];
    let r = exchange(&c, &chaos, Duration::from_secs(5))
        .await
        .unwrap()
        .0;
    assert_eq!(r.response_code, ResponseCode::NotImp);
    f.decision("decision=spec_reply").await;
    f.close().await;
}

#[tokio::test]
async fn exchange_deadline_answers_inside_it_and_servfails_past_it() {
    let f = fixture(json!({"exchange_timeout_secs": 2})).await;
    let (_endpoint, c) = f.peer().await;

    let r = ask(&c, "slow-500.test", "A").await;
    assert_eq!(a_records(&r), vec!["192.0.2.88".to_string()]);

    // A query whose body and FIN arrive a second after its length prefix is still inside it.
    let frame = encode(&query("late.test", "A")).unwrap();
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(&frame[..2]).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    send.write_all(&frame[2..]).await.unwrap();
    send.finish().unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(MAX_FRAME_BYTES))
        .await
        .unwrap()
        .unwrap();
    let r = netget::server::doq::wire::decode(&bytes, MessageType::Response).unwrap();
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);

    // A handler still running at the bound: SERVFAIL on the stream (RFC 9250 §4.3.2), not a reset.
    let started = Instant::now();
    let r = ask(&c, "slow-6000.test", "A").await;
    let took = started.elapsed();
    assert_servfail(
        &r,
        "slow-6000.test.",
        "a handler past the exchange deadline",
    );
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_secs(4),
        "the SERVFAIL came at {took:?}, not at the 2 s bound"
    );
    f.decision("decision=fail_closed_timeout").await;
    f.close().await;
}

#[tokio::test]
async fn an_answer_the_peer_never_takes_is_reset_after_the_write_timeout() {
    let f = fixture(json!({})).await;
    let mut transport = quinn::TransportConfig::default();
    // No credit at all on the streams the server answers on.
    transport.stream_receive_window(0u32.into());
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(f.cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    config.transport_config(std::sync::Arc::new(transport));
    endpoint.set_default_client_config(config);
    let c = endpoint
        .connect(f.addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let started = Instant::now();
    let frame = encode(&query("plain.test", "A")).unwrap();
    let code = reset_code(raw(&c, &frame, RESPONSE_WRITE_TIMEOUT * 3).await);
    let took = started.elapsed();
    assert_eq!(code, 1, "DOQ_INTERNAL_ERROR");
    assert!(
        took >= RESPONSE_WRITE_TIMEOUT - Duration::from_millis(500),
        "reset after {took:?}, before the write timeout"
    );
    f.decision("decision=fail_closed_send_error").await;
    f.close().await;
}

#[tokio::test]
async fn idle_timeout_keeps_an_active_connection_and_closes_a_silent_one() {
    let f = fixture(json!({"idle_timeout_secs": 3})).await;
    let (_endpoint, c) = f.peer().await;
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let r = ask(&c, "plain.test", "A").await;
        assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);
    }
    let silent = Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(8), c.closed())
        .await
        .expect("a silent connection outlived its idle timeout");
    let after = silent.elapsed();
    assert!(
        matches!(closed, quinn::ConnectionError::TimedOut),
        "{closed:?}"
    );
    assert!(
        after >= Duration::from_millis(2500),
        "closed {after:?} into a 3 s idle bound"
    );
    f.close().await;
}

#[tokio::test]
async fn stream_bound_runs_queries_in_parallel_and_holds_the_next_for_credit() {
    let f = fixture(json!({"max_streams": 2})).await;
    let (_endpoint, c) = f.peer().await;
    let started = Instant::now();
    let first_q = query("slow-1500.test", "A");
    let second_q = query("slow-1500.test", "A");
    let first = exchange(&c, &first_q, Duration::from_secs(10));
    let second = exchange(&c, &second_q, Duration::from_secs(10));
    let third = async {
        // Opened while both are in flight: it has to wait for one of them to finish.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let opened = Instant::now();
        let r = ask(&c, "plain.test", "A").await;
        (opened.elapsed(), r)
    };
    let (first, second, (waited, third)) = tokio::join!(first, second, third);
    let took = started.elapsed();
    assert_eq!(a_records(&first.unwrap().0), vec!["192.0.2.88".to_string()]);
    assert_eq!(
        a_records(&second.unwrap().0),
        vec!["192.0.2.88".to_string()]
    );
    assert_eq!(a_records(&third), vec!["192.0.2.53".to_string()]);
    assert!(
        took < Duration::from_millis(2900),
        "two 1.5 s queries took {took:?}: they did not run side by side"
    );
    assert!(
        waited >= Duration::from_millis(700),
        "the third stream was answered after {waited:?}, inside the two-stream credit"
    );
    f.close().await;
}

#[tokio::test]
async fn the_largest_query_is_answered_and_a_byte_past_it_is_a_protocol_error() {
    let f = fixture(json!({})).await;
    let (_endpoint, c) = f.peer().await;

    // A query padded (RFC 7830) to exactly 65535 octets: the largest frame a stream carries.
    let mut q = query("plain.test", "A");
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, Vec::new()));
    q.set_edns(edns.clone());
    let base = q.to_vec().unwrap().len();
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; 65535 - base]));
    q.set_edns(edns);
    let frame = encode(&q).unwrap();
    assert_eq!(frame.len(), MAX_FRAME_BYTES);
    let bytes = raw(&c, &frame, Duration::from_secs(10)).await.unwrap();
    let r = netget::server::doq::wire::decode(&bytes, MessageType::Response).unwrap();
    assert_eq!(a_records(&r), vec!["192.0.2.53".to_string()]);

    // One byte more is a second message on the stream (RFC 9250 §4.3.3): the read stops at the
    // frame bound and the connection is closed with DOQ_PROTOCOL_ERROR. Flow control alone does
    // not stop it — the server extends credit as it reads.
    let (mut send, _recv) = c.open_bi().await.unwrap();
    let mut over = frame.clone();
    over.push(0);
    let _ = tokio::time::timeout(Duration::from_secs(5), send.write_all(&over)).await;
    let _ = send.finish();
    let error = tokio::time::timeout(Duration::from_secs(5), c.closed())
        .await
        .expect("a stream one byte past the frame bound left the connection open");
    assert!(
        matches!(error, quinn::ConnectionError::ApplicationClosed(ref e) if e.error_code == PROTOCOL_ERROR),
        "{error:?}"
    );
    f.decision("frame; closing with DOQ_PROTOCOL_ERROR").await;
    f.close().await;
}

#[tokio::test]
async fn parameters_outside_their_range_refuse_to_start() {
    for (name, max) in [
        ("handshake_timeout_secs", 60),
        ("exchange_timeout_secs", 300),
        ("idle_timeout_secs", 3600),
        ("max_connections", 256),
        ("max_streams", 32),
    ] {
        for value in [0, max + 1] {
            let mut params = serde_json::Map::new();
            params.insert(name.into(), json!(value));
            let error = start_error(params.into()).await;
            assert!(
                error.contains(name),
                "{name}={value} should be refused naming it: {error}"
            );
        }
        // The maximum itself starts.
        let mut params = serde_json::Map::new();
        params.insert(name.into(), json!(max));
        let f = Fixture::new(params.into(), None).await;
        f.close().await;
    }
}

/// Start a DoQ server with `params` and return why it did not start.
async fn start_error(params: serde_json::Value) -> String {
    let state = netget::state::AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let created = netget::cli::management::ServerForm {
        protocol: "doq".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await;
    let server = match created {
        Err(e) => return format!("{e:#}"),
        Ok(server) => server,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let s = state.get_server(server).await.unwrap();
            if let netget::state::ServerStatus::Error(e) = s.status {
                break e;
            }
            assert!(s.local_addr.is_none(), "it started: {:?}", s.local_addr);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("neither started nor failed")
}
