//! The KDC's own guarantees, driven from a socket with NetGet's client codec: what Rust refuses
//! whatever the model says (pre-authentication, clock skew, replay, TGT and authenticator
//! integrity, the body checksum, unknown principals, lifetimes past the ceiling, flags nobody
//! asked for), the fail-closed paths, and the bounds (DER depth, declared length, rate, reply
//! size, idle connections, retransmissions). A static rule that admits everything plays the
//! most permissive model possible, so every refusal here is Rust's.
//!
//! The last test is the model's own path: a mocked LLM answers the events, through its tools,
//! for a real MIT `kinit` against the NetGet binary.

use super::support::{self, ALICE_PASSWORD, REALM, SERVICE, SERVICE_PASSWORD};
use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::client::kerberos::wire::{self, Credential, Expect, Reply, Request};
use netget::server::kerberos::codec::{self, Key, Principal};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn admit_everything(extra: Value) -> Option<Vec<Value>> {
    let mut issue =
        json!({"type": "kerberos_issue_ticket", "forwardable": true, "renewable": true});
    if let (Some(o), Some(e)) = (issue.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": [issue]}}),
    ])
}

fn static_rule(actions: Value) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": actions}}),
    ])
}

fn alice() -> Principal {
    Principal::parse("alice").unwrap().0
}

fn tgs() -> Principal {
    Principal::krbtgt(REALM)
}

fn alice_key() -> Key {
    Key::from_password(codec::ETYPE_AES256, ALICE_PASSWORD, "NETGET.TESTalice").unwrap()
}

fn request(lifetime_secs: i64) -> Request {
    Request {
        lifetime_secs,
        ..Default::default()
    }
}

async fn udp(kdc: SocketAddr, message: &[u8]) -> Option<Vec<u8>> {
    udp_within(kdc, message, Duration::from_secs(5)).await
}

async fn udp_within(kdc: SocketAddr, message: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(message, kdc).await.unwrap();
    let mut buf = vec![0u8; 70_000];
    match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn tcp_raw(kdc: SocketAddr, bytes: &[u8]) -> (Option<Vec<u8>>, tokio::net::TcpStream) {
    let mut s = tokio::net::TcpStream::connect(kdc).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let mut prefix = [0u8; 4];
    let reply = match tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut prefix)).await
    {
        Ok(Ok(_)) => {
            let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
            s.read_exact(&mut body).await.unwrap();
            Some(body)
        }
        _ => None,
    };
    (reply, s)
}

async fn tcp(kdc: SocketAddr, message: &[u8]) -> Option<Vec<u8>> {
    let mut framed = (message.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    tcp_raw(kdc, &framed).await.0
}

fn error_code(reply: &[u8]) -> i32 {
    match wire::parse_reply(reply).expect("a decodable reply") {
        Reply::Error(e) => e.error_code.0 as i32,
        Reply::As(_) => panic!("expected a KRB-ERROR, got an AS-REP"),
        Reply::Tgs(_) => panic!("expected a KRB-ERROR, got a TGS-REP"),
    }
}

fn as_req(padata: Vec<codec::types::PaData>, req: &Request) -> (Vec<u8>, u32) {
    let nonce = wire::nonce();
    (
        wire::as_req(&alice(), REALM, &tgs(), req, nonce, padata).unwrap(),
        nonce,
    )
}

/// A pre-authenticated TGT for alice, verified the way a client verifies it.
async fn get_tgt(kdc: SocketAddr, req: &Request) -> Credential {
    let key = alice_key();
    let (msg, nonce) = as_req(vec![wire::pa_enc_timestamp(&key).unwrap()], req);
    let reply = udp(kdc, &msg).await.expect("an AS reply");
    let Reply::As(rep) = wire::parse_reply(&reply).unwrap() else {
        panic!("no AS-REP: error {}", error_code(&reply));
    };
    wire::verify_rep(
        &rep,
        &key,
        codec::KU_AS_REP_ENC_PART,
        &Expect {
            client: &alice(),
            client_realm: REALM,
            service: &tgs(),
            service_realm: REALM,
            nonce,
        },
    )
    .expect("the AS-REP verifies with alice's key")
}

#[tokio::test]
async fn preauthentication_is_verified_by_the_kdc_not_the_model() {
    let kdc = support::start(admit_everything(json!({})), support::params()).await;
    let addr = kdc.addr();

    // No pre-authentication: the model said issue, Rust demands the timestamp first, and names
    // the salt and enctypes.
    let (msg, _) = as_req(vec![], &request(3600));
    let reply = udp(addr, &msg).await.unwrap();
    let Reply::Error(e) = wire::parse_reply(&reply).unwrap() else {
        panic!("a ticket without pre-authentication");
    };
    assert_eq!(e.error_code.0 as i32, codec::KDC_ERR_PREAUTH_REQUIRED);
    let info = wire::etype_info_from_error(&e);
    assert_eq!(
        info,
        vec![
            (codec::ETYPE_AES256, Some("NETGET.TESTalice".to_string())),
            (codec::ETYPE_AES128, Some("NETGET.TESTalice".to_string()))
        ]
    );
    assert!(kdc.wait_for_log("decision=enforced_preauth_required").await);

    // A timestamp encrypted under the wrong password: refused before any event is raised.
    let before = kdc.events("kerberos_as_request").await.len();
    let wrong = Key::from_password(codec::ETYPE_AES256, "not it", "NETGET.TESTalice").unwrap();
    let (msg, _) = as_req(
        vec![wire::pa_enc_timestamp(&wrong).unwrap()],
        &request(3600),
    );
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KDC_ERR_PREAUTH_FAILED
    );

    // The right key, an hour off the KDC's clock.
    let key = alice_key();
    let stale = wire::pa_enc_timestamp_at(&key, codec::now_secs() - 3600).unwrap();
    let (msg, _) = as_req(vec![stale], &request(3600));
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_AP_ERR_SKEW
    );

    // The right key and a fresh time, but the last byte of the HMAC flipped: the plaintext
    // decrypts intact, so only the integrity check can refuse it.
    let mut pa = wire::pa_enc_timestamp(&key).unwrap();
    let mut enc: codec::types::EncryptedData = codec::decode(&pa.padata_data.0 .0).unwrap();
    let last = enc.cipher.0 .0.len() - 1;
    enc.cipher.0 .0[last] ^= 0x01;
    pa.padata_data.0 .0 = codec::encode(&enc).unwrap();
    let (msg, _) = as_req(vec![pa], &request(3600));
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KDC_ERR_PREAUTH_FAILED
    );

    // An unknown principal cannot pre-authenticate at all.
    let pa = wire::pa_enc_timestamp(&key).unwrap();
    let eve = Principal::parse("eve").unwrap().0;
    let msg = wire::as_req(&eve, REALM, &tgs(), &request(3600), wire::nonce(), vec![pa]).unwrap();
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KDC_ERR_PREAUTH_FAILED
    );
    assert_eq!(
        kdc.events("kerberos_as_request").await.len(),
        before,
        "a failed pre-authentication reached the model"
    );

    // The right key, now: a ticket, flagged pre-authenticated.
    let pa = wire::pa_enc_timestamp(&key).unwrap();
    let (msg, nonce) = as_req(vec![pa.clone()], &request(3600));
    let reply = udp(addr, &msg).await.unwrap();
    let Reply::As(rep) = wire::parse_reply(&reply).unwrap() else {
        panic!(
            "no ticket for a correct pre-authentication: {}",
            error_code(&reply)
        );
    };
    let expect = Expect {
        client: &alice(),
        client_realm: REALM,
        service: &tgs(),
        service_realm: REALM,
        nonce,
    };
    let cred = wire::verify_rep(&rep, &key, codec::KU_AS_REP_ENC_PART, &expect).unwrap();
    let flags = wire::ticket_flag_names(cred.flags);
    assert!(flags.contains(&"pre_authent".to_string()) && flags.contains(&"initial".to_string()));
    // The same reply cannot be read with the wrong key.
    assert!(wire::verify_rep(&rep, &wrong, codec::KU_AS_REP_ENC_PART, &expect).is_err());

    // The same timestamp in a different request is a replay.
    let (msg, _) = as_req(vec![pa], &request(7200));
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_AP_ERR_REPEAT
    );
}

#[tokio::test]
async fn lifetimes_are_clamped_and_flags_need_both_parties() {
    let mut params = support::params();
    params["max_ticket_lifetime_secs"] = json!(3600);
    params["max_renewable_lifetime_secs"] = json!(7200);
    let kdc = support::start(
        admit_everything(json!({"lifetime_secs": 999_999, "renewable_lifetime_secs": 999_999})),
        params,
    )
    .await;

    // The model asked for 999999 seconds; the ceiling is 3600. Forwardable was granted by the
    // model but not asked for, so it is absent; renewable was not asked for either.
    let cred = get_tgt(kdc.addr(), &request(36_000)).await;
    assert_eq!(cred.endtime - cred.starttime, 3600);
    let flags = wire::ticket_flag_names(cred.flags);
    assert!(!flags.contains(&"forwardable".to_string()), "{flags:?}");
    assert!(!flags.contains(&"renewable".to_string()), "{flags:?}");
    assert!(cred.renew_till.is_none());
    assert!(kdc.wait_for_log("decision=model_issue_clamped").await);

    // Asked for and granted: forwardable, and renewable to the renewable ceiling.
    let asked = Request {
        lifetime_secs: 600,
        renewable_lifetime_secs: Some(999_999),
        forwardable: true,
        ..Default::default()
    };
    let cred = get_tgt(kdc.addr(), &asked).await;
    assert_eq!(
        cred.endtime - cred.starttime,
        600,
        "the client's own shorter till wins"
    );
    let flags = wire::ticket_flag_names(cred.flags);
    assert!(flags.contains(&"forwardable".to_string()) && flags.contains(&"renewable".to_string()));
    let renew = cred.renew_till.unwrap() - cred.starttime;
    assert!(renew <= 7200 && renew > 7000, "renewable ceiling: {renew}");

    // A service ticket never outlives the TGT it was issued against.
    let subkey = Key::random(codec::ETYPE_AES256).unwrap();
    let svc = Principal::parse(SERVICE).unwrap().0;
    let nonce = wire::nonce();
    let msg = wire::tgs_req(&cred, &svc, &request(36_000), nonce, &subkey).unwrap();
    let reply = udp(kdc.addr(), &msg).await.unwrap();
    let Reply::Tgs(rep) = wire::parse_reply(&reply).unwrap() else {
        panic!("no TGS-REP: {}", error_code(&reply));
    };
    let service = wire::verify_rep(
        &rep,
        &subkey,
        codec::KU_TGS_REP_ENC_SUBKEY,
        &Expect {
            client: &alice(),
            client_realm: REALM,
            service: &svc,
            service_realm: REALM,
            nonce,
        },
    )
    .unwrap();
    assert!(
        service.endtime <= cred.endtime,
        "service ticket outlives its TGT"
    );

    // And the ticket is encrypted in the service's own key, naming alice.
    let svc_key = Key::from_password(
        codec::ETYPE_AES256,
        SERVICE_PASSWORD,
        &svc.default_salt(REALM),
    )
    .unwrap();
    let plain = svc_key
        .decrypt_data(codec::KU_TICKET, &service.ticket.0.enc_part.0)
        .expect("the service ticket decrypts with the service's key");
    let part: codec::types::EncTicketPart = codec::decode(&plain).unwrap();
    assert_eq!(Principal::from_asn1(&part.0.cname.0).unwrap(), alice());
}

#[tokio::test]
async fn the_tgs_exchange_checks_the_tgt_the_authenticator_and_the_body() {
    let kdc = support::start(admit_everything(json!({})), support::params()).await;
    let addr = kdc.addr();
    let cred = get_tgt(addr, &request(3600)).await;
    let svc = Principal::parse(SERVICE).unwrap().0;
    let subkey = Key::random(codec::ETYPE_AES256).unwrap();

    // A TGT whose ciphertext was altered by one bit.
    let mut forged = cred.clone();
    forged.ticket.0.enc_part.0.cipher.0 .0[20] ^= 1;
    let msg = wire::tgs_req(&forged, &svc, &request(3600), wire::nonce(), &subkey).unwrap();
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_AP_ERR_BAD_INTEGRITY
    );
    assert!(kdc.wait_for_log("decision=tgt_integrity").await);

    // An authenticator under the wrong session key.
    let mut wrong_key = cred.clone();
    wrong_key.session_key = Key::random(cred.session_key.etype()).unwrap();
    let msg = wire::tgs_req(&wrong_key, &svc, &request(3600), wire::nonce(), &subkey).unwrap();
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_AP_ERR_BAD_INTEGRITY
    );
    assert!(kdc.wait_for_log("decision=authenticator_integrity").await);

    // A body changed after the authenticator's checksum was computed: one digit of `till`
    // ([5] GeneralizedTime, `a5 11 18 0f` then 15 characters), still valid DER.
    let msg = wire::tgs_req(&cred, &svc, &request(4321), wire::nonce(), &subkey).unwrap();
    let body = codec::req_body_bytes(&msg).unwrap().to_vec();
    let body_at = msg
        .windows(body.len())
        .position(|w| w == body.as_slice())
        .unwrap();
    let till_at = body
        .windows(4)
        .position(|w| w == [0xa5, 0x11, 0x18, 0x0f])
        .expect("till in the body");
    let mut tampered = msg.clone();
    let digit = body_at + till_at + 4 + 13; // the second digit of the seconds
    tampered[digit] = if tampered[digit] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        error_code(&udp(addr, &tampered).await.unwrap()),
        codec::KRB_AP_ERR_MODIFIED
    );
    assert!(kdc.wait_for_log("decision=checksum_mismatch").await);

    // The model said issue for a service with no key: Rust refuses it.
    let nope = Principal::parse("host/nope.netget.test").unwrap().0;
    let msg = wire::tgs_req(&cred, &nope, &request(3600), wire::nonce(), &subkey).unwrap();
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
    assert!(kdc.wait_for_log("decision=enforced_unknown_service").await);

    // A retransmission (identical bytes) gets the cached answer and raises no second event.
    let events = kdc.events("kerberos_tgs_request").await.len();
    let msg = wire::tgs_req(&cred, &svc, &request(3600), wire::nonce(), &subkey).unwrap();
    let first = udp(addr, &msg).await.unwrap();
    let again = udp(addr, &msg).await.unwrap();
    assert_eq!(first, again, "a retransmission gets the cached answer");
    assert!(matches!(wire::parse_reply(&first).unwrap(), Reply::Tgs(_)));
    assert_eq!(kdc.events("kerberos_tgs_request").await.len(), events + 1);
}

#[tokio::test]
async fn every_undecided_request_fails_closed_with_an_error_the_model_cannot_send() {
    // A principal that needs no pre-authentication: a server that failed open would answer this
    // very request with a ticket, so nothing but the fail-closed rule stands between it and one.
    let legacy = Principal::parse(support::LEGACY).unwrap().0;
    let msg = wire::as_req(
        &legacy,
        REALM,
        &tgs(),
        &request(3600),
        wire::nonce(),
        vec![],
    )
    .unwrap();

    // The model is unreachable.
    let kdc = support::start(None, support::params()).await;
    assert_eq!(
        error_code(&udp(kdc.addr(), &msg).await.unwrap()),
        codec::KDC_ERR_SVC_UNAVAILABLE
    );
    assert!(kdc.wait_for_log("decision=fail_closed_llm_error").await);

    // The model answered with nothing.
    let kdc = support::start(static_rule(json!([])), support::params()).await;
    assert_eq!(
        error_code(&udp(kdc.addr(), &msg).await.unwrap()),
        codec::KRB_ERR_GENERIC
    );
    assert!(kdc.wait_for_log("decision=fail_closed_no_action").await);

    // The model tried to send the fail-closed code itself, which is not in its vocabulary.
    let kdc = support::start(
        static_rule(json!([{"type": "kerberos_refuse", "error": "SVC_UNAVAILABLE"}])),
        support::params(),
    )
    .await;
    assert_eq!(
        error_code(&udp(kdc.addr(), &msg).await.unwrap()),
        codec::KRB_ERR_GENERIC
    );
    assert!(kdc.wait_for_log("decision=fail_closed_action_error").await);

    // A refusal the model did choose carries its code and text.
    let kdc = support::start(
        static_rule(json!([{"type": "kerberos_refuse", "error": "POLICY", "text": "closed for maintenance"}])),
        support::params(),
    )
    .await;
    let reply = udp(kdc.addr(), &msg).await.unwrap();
    let Reply::Error(e) = wire::parse_reply(&reply).unwrap() else {
        panic!("not an error");
    };
    assert_eq!(e.error_code.0 as i32, codec::KDC_ERR_POLICY);
    assert_eq!(wire::error_summary(&e)["text"], "closed for maintenance");
    assert!(kdc.wait_for_log("decision=model_reject").await);
}

#[tokio::test]
async fn bounds_on_what_a_peer_may_send() {
    let mut params = support::params();
    params["max_requests_per_minute_per_source"] = json!(20);
    let kdc = support::start(admit_everything(json!({})), params).await;
    let addr = kdc.addr();

    // A depth bomb inside an AS-REQ's application tag: refused by the DER walk.
    let mut bomb = vec![0x05, 0x00];
    for _ in 0..40 {
        let mut outer = vec![0x30, bomb.len() as u8];
        outer.extend_from_slice(&bomb);
        bomb = outer;
    }
    let mut msg = vec![codec::TAG_AS_REQ, bomb.len() as u8];
    msg.extend_from_slice(&bomb);
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_ERR_GENERIC
    );
    assert!(
        kdc.wait_for_log("nesting deeper than 24").await,
        "{}",
        kdc.log_text()
    );

    // Garbage, and an indefinite length.
    assert_eq!(
        error_code(&udp(addr, b"hello kdc").await.unwrap()),
        codec::KRB_AP_ERR_MSG_TYPE
    );
    assert_eq!(
        error_code(
            &udp(addr, &[codec::TAG_AS_REQ, 0x80, 0x30, 0x00, 0x00, 0x00])
                .await
                .unwrap()
        ),
        codec::KRB_ERR_GENERIC
    );

    // A reply is not a request: no answer.
    let (reply_like, _) = as_req(vec![], &request(60));
    let mut reply_like = reply_like;
    reply_like[0] = codec::TAG_AS_REP;
    assert!(udp(addr, &reply_like).await.is_none());

    // TCP: a declared length past 64 KiB, and the reserved high bit, are each answered with
    // KRB_ERR_FIELD_TOOLONG and the connection closed, without reading the body.
    for prefix in [
        (64 * 1024 + 1u32).to_be_bytes(),
        0x8000_0010u32.to_be_bytes(),
    ] {
        let (reply, mut s) = tcp_raw(addr, &prefix).await;
        assert_eq!(
            error_code(&reply.expect("an answer")),
            codec::KRB_ERR_FIELD_TOOLONG
        );
        let mut rest = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut rest))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "the connection stays open after FIELD_TOOLONG");
    }

    // A reply too big for one datagram: KRB_ERR_RESPONSE_TOO_BIG over UDP, the ticket over TCP.
    let key = alice_key();
    let many = Request {
        lifetime_secs: 3600,
        addresses: (0..80u8)
            .map(|i| std::net::IpAddr::from([10, 0, 0, i]))
            .collect(),
        ..Default::default()
    };
    let (msg, _) = as_req(vec![wire::pa_enc_timestamp(&key).unwrap()], &many);
    assert_eq!(
        error_code(&udp(addr, &msg).await.unwrap()),
        codec::KRB_ERR_RESPONSE_TOO_BIG
    );
    let (msg, _) = as_req(vec![wire::pa_enc_timestamp(&key).unwrap()], &many);
    let big = tcp(addr, &msg).await.unwrap();
    assert!(big.len() > 1400 && matches!(wire::parse_reply(&big).unwrap(), Reply::As(_)));
}

#[tokio::test]
async fn one_source_is_held_to_its_request_rate() {
    let mut params = support::params();
    params["max_requests_per_minute_per_source"] = json!(5);
    let kdc = support::start(admit_everything(json!({})), params).await;
    let mut answered = 0;
    for i in 0..10u8 {
        // Distinct bytes, so the lookaside cache answers none of them.
        if udp_within(kdc.addr(), &[b'x', i], Duration::from_millis(300))
            .await
            .is_some()
        {
            answered += 1;
        }
    }
    assert_eq!(answered, 5, "five a minute, bursting to five");
}

#[tokio::test]
async fn a_silent_tcp_peer_is_disconnected() {
    let kdc = support::start(admit_everything(json!({})), support::params()).await;
    let mut s = tokio::net::TcpStream::connect(kdc.addr()).await.unwrap();
    let mut buf = [0u8; 1];
    // FIRST_BYTE_TIMEOUT is 10 s.
    let n = tokio::time::timeout(Duration::from_secs(20), s.read(&mut buf))
        .await
        .expect("the KDC kept a silent connection open past its first-byte deadline")
        .unwrap_or(0);
    assert_eq!(n, 0);
}

/// The model's path end to end: a mocked LLM decides, through `kerberos_require_preauth` and
/// `kerberos_issue_ticket`, for a real MIT `kinit` against the NetGet binary.
#[tokio::test]
async fn a_mocked_model_admits_a_real_kinit() -> E2EResult<()> {
    let tools = support::tools();
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via kerberos for realm NETGET.TEST")
            .with_mock(|mock| {
                mock.on_instruction_containing("via kerberos")
                    .respond_with_actions(json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "kerberos",
                        "startup_params": support::params(),
                        "instruction": "Admit alice for 3 hours once she pre-authenticates"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("kerberos_as_request")
                    .respond_with_actions_from_event(|e| {
                        if e["preauth"] == "verified" {
                            json!([{"type": "kerberos_issue_ticket", "lifetime_secs": 10_800}])
                        } else {
                            json!([{"type": "kerberos_require_preauth"}])
                        }
                    })
                    .expect_calls(2)
                    .and()
            });
    let server = helpers::start_netget_server(config).await?;
    let dir = tempfile::tempdir()?;
    let conf = support::krb5_conf(
        dir.path(),
        ([127, 0, 0, 1], server.port).into(),
        support::Via::MitTcp,
    );
    let cc = dir.path().join("cc");
    let r = support::run(
        &tools.mit_kinit,
        &["alice"],
        &conf,
        &cc,
        &format!("{ALICE_PASSWORD}\n"),
    )
    .await;
    assert!(r.ok, "kinit: {}", r.text);
    let list = support::run(&tools.mit_klist, &[], &conf, &cc, "").await;
    assert!(
        list.text.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{}",
        list.text
    );
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
