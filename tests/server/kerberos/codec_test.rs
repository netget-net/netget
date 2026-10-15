//! The bounded DER walk at its exact limits, the model's refusal vocabulary, and a mutation
//! sweep: thousands of corrupted AS-REQs and TGS-REQs through the KDC's analysis, which must
//! answer or refuse every one without panicking.

use super::support::{ALICE_PASSWORD, REALM};
use netget::client::kerberos::wire::{self, Credential, Request};
use netget::server::kerberos::codec::{
    self, check_der, types, DerError, Key, Principal, MAX_DER_DEPTH,
};
use netget::server::kerberos::kdc::{Analysis, Kdc, KdcConfig};
use serde_json::json;

fn nested(depth: usize) -> Vec<u8> {
    // `depth` constructed elements around a NULL.
    let mut v = vec![0x05, 0x00];
    for _ in 0..depth {
        let mut outer = vec![0x30];
        let len = v.len();
        if len < 128 {
            outer.push(len as u8);
        } else {
            outer.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        outer.extend_from_slice(&v);
        v = outer;
    }
    v
}

#[test]
fn the_der_walk_stops_exactly_at_its_bounds() {
    assert_eq!(check_der(&nested(MAX_DER_DEPTH)), Ok(()));
    assert!(matches!(
        check_der(&nested(MAX_DER_DEPTH + 1)),
        Err(DerError::TooDeep(_))
    ));
    // A depth bomb far past the bound costs the walk nothing.
    assert!(matches!(
        check_der(&nested(5000)),
        Err(DerError::TooDeep(_))
    ));

    assert_eq!(check_der(&[]), Err(DerError::Empty));
    assert!(matches!(
        check_der(&[0x30, 0x80, 0x00, 0x00]),
        Err(DerError::Indefinite(0))
    ));
    assert!(matches!(
        check_der(&[0x1f, 0x81, 0x01, 0x00]),
        Err(DerError::LongTag(0))
    ));
    assert!(matches!(
        check_der(&[0x30, 0x03, 0x05, 0x00]),
        Err(DerError::Overrun(0))
    ));
    assert!(matches!(
        check_der(&[0x30, 0x03, 0x05, 0x02, 0x00]),
        Err(DerError::Overrun(2))
    ));
    assert!(matches!(
        check_der(&[0x05, 0x00, 0x00]),
        Err(DerError::Trailing(1))
    ));
    assert!(matches!(
        check_der(&[0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]),
        Err(DerError::LengthTooWide(0))
    ));
    // A declared length near usize::MAX is an overrun, not an overflow.
    assert!(matches!(
        check_der(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
        Err(DerError::Overrun(0))
    ));

    // Element count: 4095 NULLs inside one SEQUENCE is the limit (4096 with the SEQUENCE).
    let flat = |n: usize| {
        let body: Vec<u8> = std::iter::repeat_n([0x05u8, 0x00], n).flatten().collect();
        let mut v = vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
        v.extend_from_slice(&body);
        v
    };
    assert_eq!(check_der(&flat(codec::MAX_DER_ELEMENTS - 1)), Ok(()));
    assert_eq!(
        check_der(&flat(codec::MAX_DER_ELEMENTS)),
        Err(DerError::TooManyElements)
    );

    let mut big = vec![0x04, 0x83, 0x01, 0x00, 0x01];
    big.resize(5 + 65_537, 0);
    assert!(matches!(check_der(&big), Err(DerError::TooLarge(_))));
}

#[test]
fn the_model_cannot_send_the_fail_closed_codes() {
    for name in [
        "C_PRINCIPAL_UNKNOWN",
        "KDC_ERR_POLICY",
        "policy",
        "client-revoked",
    ] {
        assert!(codec::model_refusal_code(&json!(name)).is_ok(), "{name}");
    }
    assert_eq!(codec::model_refusal_code(&json!(6)).unwrap(), 6);
    for refused in [
        json!("SVC_UNAVAILABLE"),
        json!(29),
        json!("KRB_ERR_GENERIC"),
        json!(60),
        json!("PREAUTH_REQUIRED"),
        json!("nonsense"),
    ] {
        assert!(codec::model_refusal_code(&refused).is_err(), "{refused}");
    }
}

fn kdc() -> Kdc {
    Kdc::new(
        KdcConfig::new(
            REALM,
            &[
                ("alice".into(), ALICE_PASSWORD.into()),
                ("host/svc.netget.test".into(), "svc".into()),
            ],
            &[],
            36_000,
            604_800,
            300,
        )
        .unwrap(),
    )
}

/// A deterministic xorshift, so a failure names a reproducible seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut m = base.to_vec();
    for _ in 0..(1 + rng.next() % 4) {
        if m.is_empty() {
            break;
        }
        let at = (rng.next() as usize) % m.len();
        match rng.next() % 4 {
            0 => m[at] = rng.next() as u8,
            1 => m[at] ^= 1 << (rng.next() % 8),
            2 => {
                m.truncate(at.max(1));
            }
            _ => m.insert(at, rng.next() as u8),
        }
    }
    m
}

#[test]
fn mutated_requests_are_answered_or_refused_never_a_panic() {
    let kdc = kdc();
    let alice = Principal::parse("alice").unwrap().0;
    let tgs = Principal::krbtgt(REALM);
    let key = Key::from_password(codec::ETYPE_AES256, ALICE_PASSWORD, "NETGET.TESTalice").unwrap();
    let req = Request {
        lifetime_secs: 3600,
        ..Default::default()
    };
    let as_req = wire::as_req(
        &alice,
        REALM,
        &tgs,
        &req,
        7,
        vec![wire::pa_enc_timestamp(&key).unwrap()],
    )
    .unwrap();
    // A TGS-REQ around a ticket NetGet did not issue: it reaches the TGT check and stops there,
    // which is still every decoder on the way.
    let fake = Credential {
        client: alice.clone(),
        client_realm: REALM.into(),
        service: tgs.clone(),
        service_realm: REALM.into(),
        ticket: codec::decode(&{
            let t = types::TicketInner {
                tkt_vno: types::ExplicitContextTag0(codec::int(5)),
                realm: types::ExplicitContextTag1(codec::kstring(REALM).unwrap()),
                sname: types::ExplicitContextTag2(tgs.to_asn1().unwrap()),
                enc_part: types::ExplicitContextTag3(
                    key.encrypted_data(2, b"not a ticket", Some(1)).unwrap(),
                ),
            };
            codec::encode(&types::Ticket::from(t)).unwrap()
        })
        .unwrap(),
        session_key: Key::random(codec::ETYPE_AES256).unwrap(),
        flags: 0,
        authtime: 0,
        starttime: 0,
        endtime: i64::MAX,
        renew_till: None,
    };
    let svc = Principal::parse("host/svc.netget.test").unwrap().0;
    let tgs_req = wire::tgs_req(
        &fake,
        &svc,
        &req,
        9,
        &Key::random(codec::ETYPE_AES256).unwrap(),
    )
    .unwrap();

    let source: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let mut rng = Rng(0x5eed_4b45_5242_4552);
    let (mut asked, mut refused, mut ignored) = (0, 0, 0);
    for i in 0..6000 {
        let base = if i % 2 == 0 { &as_req } else { &tgs_req };
        let message = mutate(&mut rng, base);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match kdc.analyze(&message, source, "udp") {
                Analysis::Answer(m) => {
                    assert!(!m.reply.is_empty());
                    "refused"
                }
                Analysis::Ask(_) => "asked",
                Analysis::Ignore(_) => "ignored",
            }
        }));
        match outcome {
            Ok("refused") => refused += 1,
            Ok("asked") => asked += 1,
            Ok(_) => ignored += 1,
            Err(_) => panic!(
                "analysis panicked on mutation {i}: {}",
                hex::encode(&message)
            ),
        }
    }
    println!("mutations: {refused} refused, {asked} reached the model, {ignored} ignored");
    assert!(
        refused > 3000,
        "most corruptions must be refused: {refused}"
    );
}
