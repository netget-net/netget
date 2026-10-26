//! DH-HMAC-CHAP in-band authentication on NetGet's NVMe/TCP target, driven by the raw host of
//! `support.rs`, whose side of the exchange (HMAC, key transformation, Diffie-Hellman over
//! ffdhe2048, every message's offsets) is written in that file from the specification and not
//! taken from NetGet. The python policy plays the model: `:secure` subsystems require
//! authentication, `:open` ones do not.
use super::support::*;
use num_bigint::BigUint;
use serde_json::{json, Value};

const SECURE: &str = "nqn.2026-10.net.netget:secure";
const OPEN: &str = "nqn.2026-10.net.netget:open";
const HOST_KEY: [u8; 32] = [0x11; 32];
const CTRL_KEY: [u8; 48] = [0x5C; 48];

const AUTH_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
ns=[{'nsid':1,'size':1048576,'writable':True,'extents':[{'offset':0,'text':'secured'}]}]
if t=='nvme_tcp_connect' and e['subsystem_nqn'].endswith(':secure'):
  a=[{'type':'nvme_tcp_accept_connect','require_authentication':True,'namespaces':ns}]
elif t=='nvme_tcp_connect' and e['subsystem_nqn'].endswith(':open'):
  a=[{'type':'nvme_tcp_accept_connect','namespaces':ns}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

fn params(hashes: &str, groups: &str, ctrl: bool) -> Value {
    let mut p = json!({
        "dhchap_secret": dhhc1(&HOST_KEY, 1),
        "dhchap_hashes": hashes,
        "dhchap_dhgroups": groups,
    });
    if ctrl {
        p["dhchap_ctrl_secret"] = json!(dhhc1(&CTRL_KEY, 0));
    }
    p
}

/// ICReq and an admin Connect to `subnqn`; the Connect's completion.
async fn connect(raw: &mut Raw, subnqn: &str) -> Cqe {
    raw.icreq(0, 0).await;
    raw.connect_queue(0, 31, 0, 0, &connect_data(&HOSTID, 0xFFFF, subnqn, HOST))
        .await
}

/// A decoded challenge: (TID, HL, hash, group, SEQNUM, C1, the controller's DH value).
struct Challenge {
    tid: u16,
    hl: usize,
    hash: u8,
    group: u8,
    s1: u32,
    c1: Vec<u8>,
    dhv: Vec<u8>,
}

fn challenge(b: &[u8]) -> Challenge {
    assert_eq!(
        (b[0], b[1]),
        (1, CHALLENGE),
        "a DH-HMAC-CHAP_Challenge: {b:02x?}"
    );
    let hl = b[6] as usize;
    let dhvlen = le16(b, 10) as usize;
    Challenge {
        tid: le16(b, 4),
        hl,
        hash: b[8],
        group: b[9],
        s1: le32(b, 12),
        c1: b[16..16 + hl].to_vec(),
        dhv: b[16 + hl..16 + hl + dhvlen].to_vec(),
    }
}

/// (AUTH-ID, explanation) of an AUTH_Failure1, after checking its type and RESCODE.
fn failure(b: &[u8], tid: u16) -> u8 {
    assert_eq!(
        (b[0], b[1]),
        (0, FAILURE1),
        "an AUTH_Failure1: {:02x?}",
        &b[..16]
    );
    assert_eq!(le16(b, 4), tid, "the failure names the transaction");
    assert_eq!(b[6], AUTH_FAILED, "RESCODE: authentication failed");
    b[7]
}

/// The raw host's Diffie-Hellman over ffdhe2048: (x, g^x mod p as 256 bytes).
fn dh_key() -> (BigUint, Vec<u8>) {
    let p = BigUint::parse_bytes(FFDHE2048_P.as_bytes(), 16).unwrap();
    let x = BigUint::from_bytes_be(&rand_bytes(32)) + BigUint::from(2u8);
    let y = BigUint::from(2u8).modpow(&x, &p);
    (x, pad(&y.to_bytes_be(), 256))
}

fn session_key(hash: u8, x: &BigUint, theirs: &[u8]) -> Vec<u8> {
    let p = BigUint::parse_bytes(FFDHE2048_P.as_bytes(), 16).unwrap();
    let z = BigUint::from_bytes_be(theirs).modpow(x, &p);
    digest(hash, &pad(&z.to_bytes_be(), 256))
}

fn pad(b: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(b);
    out
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// The host's R1 for a challenge, with the host key transformed by SHA-256 as `dhhc1(_, 1)`
/// says.
fn host_response(c: &Challenge, key: &[u8], session: Option<&[u8]>, subnqn: &str) -> Vec<u8> {
    chap_response(
        c.hash,
        &transform(key, 1, HOST),
        &c.c1,
        session,
        c.s1,
        c.tid,
        b"HostHost",
        HOST,
        subnqn,
    )
}

/// Negotiate, take the challenge and reply with R1 (unidirectional, NULL group). Returns the
/// challenge and the Success1 or Failure1 the target answers.
async fn exchange(
    raw: &mut Raw,
    tid: u16,
    offer_hashes: &[u8],
    key: &[u8],
) -> (Challenge, Vec<u8>) {
    let c = raw.auth_send(&negotiate(tid, offer_hashes, &[0])).await;
    assert!(c.ok(), "Authentication Send (negotiate): {c:?}");
    let (b, c) = raw.auth_receive(4096).await;
    assert!(c.ok(), "Authentication Receive (challenge): {c:?}");
    assert_eq!(b.len(), 4096, "the receive returns AL bytes");
    let ch = challenge(&b);
    let r1 = host_response(&ch, key, None, SECURE);
    let c = raw.auth_send(&reply(tid, &r1, None, 0, &[])).await;
    assert!(c.ok(), "Authentication Send (reply): {c:?}");
    let (b, c) = raw.auth_receive(4096).await;
    assert!(c.ok(), "Authentication Receive (success1): {c:?}");
    (ch, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_does_not_authenticate_gets_nothing() {
    let srv = start(policy(AUTH_POLICY), Some(params("sha256", "null", false))).await;
    let mut raw = Raw::connect(srv.port).await;
    let c = connect(&mut raw, SECURE).await;
    assert!(c.ok(), "the Connect succeeds: {c:?}");
    assert_ne!(c.dw0 & (1 << 17), 0, "AUTHREQ.ATR is set: {c:?}");
    assert_eq!(c.dw0 & (1 << 18), 0, "no secure channel concatenation");
    for cqe in [
        raw.prop_get(0x00, true).await,
        raw.prop_set(0x14, 1 | 6 << 16 | 4 << 20).await,
        raw.identify(1, 0).await.1,
        raw.cmd(&Sqe::new(0x18, 0), &[]).await.1,
    ] {
        assert_eq!(cqe.sc(), AUTHENTICATION_REQUIRED, "{cqe:?}");
        assert!(cqe.dnr());
    }
    // A Receive before any Negotiate is out of order: AUTH_Failure1, and still nothing runs.
    let (b, c) = raw.auth_receive(4096).await;
    assert!(c.ok());
    assert_eq!(failure(&b, 0), INCORRECT_MESSAGE);
    assert_eq!(raw.prop_get(0x00, true).await.sc(), AUTHENTICATION_REQUIRED);

    // A subsystem the model does not protect: no ATR, and no authentication to run.
    let mut open = Raw::connect(srv.port).await;
    let c = connect(&mut open, OPEN).await;
    assert!(c.ok() && c.dw0 & (1 << 17) == 0, "{c:?}");
    assert_eq!(
        open.auth_send(&negotiate(1, &[1], &[0])).await.sc(),
        SEQUENCE_ERROR,
        "authentication on a queue that was not asked to authenticate"
    );
    open.enable().await;

    let events = events(&srv.state, srv.id, "nvme_tcp_connect").await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["authentication_available"], true);
    let shown = serde_json::to_string(&events).unwrap();
    let secret = dhhc1(&HOST_KEY, 1);
    let b64 = secret.split(':').nth(2).unwrap();
    assert!(
        !shown.contains("DHHC-1") && !shown.contains(b64),
        "no secret reaches the model: {shown}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unidirectional_authentication_with_each_hash_and_the_null_group() {
    for (hash, name) in [(1u8, "sha256"), (2, "sha384"), (3, "sha512")] {
        let srv = start(policy(AUTH_POLICY), Some(params(name, "null", false))).await;
        let mut raw = Raw::connect(srv.port).await;
        let c = connect(&mut raw, SECURE).await;
        let cntlid = (c.dw0 & 0xFFFF) as u16;
        let tid = 0x1200 + hash as u16;
        let (ch, s1) = exchange(&mut raw, tid, &[1, 2, 3], &HOST_KEY).await;
        assert_eq!(ch.tid, tid, "the challenge echoes the transaction");
        assert_eq!(ch.hash, hash, "{name} chosen");
        assert_eq!(ch.hl, hash_len(hash));
        assert_eq!(ch.group, 0, "the NULL group");
        assert!(ch.dhv.is_empty(), "no DH value under NULL");
        assert_ne!(ch.s1, 0, "S1 is not zero");
        assert!(ch.c1.iter().any(|b| *b != 0), "C1 is random");
        assert_eq!(
            (s1[0], s1[1]),
            (1, SUCCESS1),
            "Success1: {:02x?}",
            &s1[..16]
        );
        assert_eq!(le16(&s1, 4), tid);
        assert_eq!(s1[6] as usize, hash_len(hash), "HL");
        assert_eq!(
            s1[8], 0,
            "no RVALID: the host asked nothing of the controller"
        );
        // Authenticated: the controller comes up.
        raw.enable().await;
        let (id, c) = raw.identify(1, 0).await;
        assert!(c.ok());
        assert_eq!(le16(&id, 78), cntlid);
        // I/O queues join the authenticated controller without authenticating themselves.
        let mut io = Raw::connect(srv.port).await;
        let c = io.io_session(1, cntlid, SECURE).await;
        assert!(c.ok() && c.dw0 & (1 << 17) == 0, "{c:?}");
        let (d, c) = io.read(1, 0, 1, 512).await;
        assert!(c.ok());
        assert_eq!(&d[..7], b"secured");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidirectional_authentication_over_ffdhe2048() {
    let srv = start(
        policy(AUTH_POLICY),
        Some(params("sha384,sha256", "ffdhe2048", true)),
    )
    .await;
    let mut raw = Raw::connect(srv.port).await;
    let c = connect(&mut raw, SECURE).await;
    assert_ne!(c.dw0 & (1 << 17), 0);
    let tid = 7;
    assert!(raw
        .auth_send(&negotiate(tid, &[1, 2, 3], &[0, 1, 2, 3, 4, 5]))
        .await
        .ok());
    let (b, _) = raw.auth_receive(4096).await;
    let ch = challenge(&b);
    assert_eq!(
        (ch.hash, ch.group),
        (2, 1),
        "sha384 and ffdhe2048, the target's first choices"
    );
    assert_eq!(ch.dhv.len(), 256, "a 2048-bit public value");
    let p = BigUint::parse_bytes(FFDHE2048_P.as_bytes(), 16).unwrap();
    let theirs = BigUint::from_bytes_be(&ch.dhv);
    assert!(theirs > BigUint::from(1u8) && theirs < &p - 1u8);
    let (x, mine) = dh_key();
    let sk = session_key(2, &x, &ch.dhv);
    let r1 = host_response(&ch, &HOST_KEY, Some(&sk), SECURE);
    let c2 = rand_bytes(48);
    let s2 = 0x5eed_0002;
    let c = raw.auth_send(&reply(tid, &r1, Some(&c2), s2, &mine)).await;
    assert!(c.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!((b[0], b[1]), (1, SUCCESS1), "{:02x?}", &b[..16]);
    assert_eq!(
        b[8], 1,
        "RVALID: the controller answers the host's challenge"
    );
    let r2 = chap_response(
        2,
        &CTRL_KEY,
        &c2,
        Some(&sk),
        s2,
        tid,
        b"Controller",
        SECURE,
        HOST,
    );
    assert_eq!(
        &b[16..16 + 48],
        r2.as_slice(),
        "R2 proves the controller secret"
    );
    // Until Success2 the queue is not authenticated.
    assert_eq!(raw.prop_get(0x00, true).await.sc(), AUTHENTICATION_REQUIRED);
    let mut s2msg = vec![0u8; 16];
    s2msg[0] = 1;
    s2msg[1] = SUCCESS2;
    s2msg[4..6].copy_from_slice(&tid.to_le_bytes());
    assert!(raw.auth_send(&s2msg).await.ok());
    raw.enable().await;

    // tshark reads the Authentication Send/Receive commands (the messages are opaque to it).
    raw.oracle().also_named("nvme").assert_clean();
    let fctypes: Vec<u64> = tshark_values(&raw, "nvme.fabrics.cmd.fctype")
        .iter()
        .filter_map(|v| number(v))
        .collect();
    assert!(
        fctypes.contains(&5) && fctypes.contains(&6),
        "tshark sees Authentication Send and Receive: {fctypes:?}"
    );
    let secp: Vec<u64> = tshark_values(&raw, "nvme.fabrics.cmd.auth.secp")
        .iter()
        .filter_map(|v| number(v))
        .collect();
    assert!(
        secp.iter().all(|s| *s == 0xE9) && !secp.is_empty(),
        "{secp:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_responses_and_unusable_offers_fail_closed() {
    let srv = start(policy(AUTH_POLICY), Some(params("sha256", "null", false))).await;
    let mut raw = Raw::connect(srv.port).await;
    connect(&mut raw, SECURE).await;

    // The wrong key: AUTH_Failure1, and the queue stays shut.
    let (_, b) = exchange(&mut raw, 1, &[1], &[0x22; 32]).await;
    assert_eq!(failure(&b, 1), AUTH_FAILED);
    assert_eq!(raw.prop_get(0x00, true).await.sc(), AUTHENTICATION_REQUIRED);

    // Unusable offers: a hash this target does not take, a group it does not take.
    assert!(raw.auth_send(&negotiate(2, &[3], &[0])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 2), HASH_UNUSABLE);
    assert!(raw.auth_send(&negotiate(3, &[1], &[5])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 3), DHGROUP_UNUSABLE);

    // Four negotiations is the most a queue gets: the fifth fails even with the right key.
    let (_, b) = exchange(&mut raw, 4, &[1], &HOST_KEY).await;
    assert_eq!(
        (b[0], b[1]),
        (1, SUCCESS1),
        "the fourth, right, attempt passes"
    );
    raw.enable().await;
    assert!(raw.auth_send(&negotiate(5, &[1], &[0])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 5), AUTH_FAILED);
    assert_eq!(
        raw.prop_get(0x00, true).await.sc(),
        AUTHENTICATION_REQUIRED,
        "a failed re-authentication takes the queue's authentication away"
    );

    // Steps out of order and a transaction that changes.
    let mut raw = Raw::connect(srv.port).await;
    connect(&mut raw, SECURE).await;
    assert!(raw.auth_send(&reply(9, &[0; 32], None, 0, &[])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 9), INCORRECT_MESSAGE);
    assert!(raw.auth_send(&negotiate(10, &[1], &[0])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    let ch = challenge(&b);
    let r1 = host_response(&ch, &HOST_KEY, None, SECURE);
    assert!(raw.auth_send(&reply(11, &r1, None, 0, &[])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 10), INCORRECT_PAYLOAD);
    // Asking the controller to prove itself with no controller secret configured.
    assert!(raw.auth_send(&negotiate(12, &[1], &[0])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    let ch = challenge(&b);
    let r1 = host_response(&ch, &HOST_KEY, None, SECURE);
    assert!(raw
        .auth_send(&reply(12, &r1, Some(&[7; 32]), 99, &[]))
        .await
        .ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!(failure(&b, 12), AUTH_FAILED);
    assert_eq!(raw.prop_get(0x00, true).await.sc(), AUTHENTICATION_REQUIRED);

    // A DH value of 1 under ffdhe2048, and one of the wrong length.
    let srv = start(
        policy(AUTH_POLICY),
        Some(params("sha256", "ffdhe2048", true)),
    )
    .await;
    for (dhv, why) in [
        (pad(&[1], 256), DHGROUP_UNUSABLE),
        (vec![2u8; 128], INCORRECT_PAYLOAD),
    ] {
        let mut raw = Raw::connect(srv.port).await;
        connect(&mut raw, SECURE).await;
        assert!(raw.auth_send(&negotiate(20, &[1], &[1])).await.ok());
        let (b, _) = raw.auth_receive(4096).await;
        let ch = challenge(&b);
        assert!(raw
            .auth_send(&reply(20, &[0; 32], None, 0, &dhv))
            .await
            .ok());
        let (b, _) = raw.auth_receive(4096).await;
        assert_eq!(failure(&b, ch.tid), why);
    }

    // A host that refuses the controller's response with AUTH_Failure2 is not authenticated.
    let mut raw = Raw::connect(srv.port).await;
    connect(&mut raw, SECURE).await;
    assert!(raw.auth_send(&negotiate(30, &[1], &[1])).await.ok());
    let (b, _) = raw.auth_receive(4096).await;
    let ch = challenge(&b);
    let (x, mine) = dh_key();
    let sk = session_key(1, &x, &ch.dhv);
    let r1 = host_response(&ch, &HOST_KEY, Some(&sk), SECURE);
    assert!(raw
        .auth_send(&reply(30, &r1, Some(&[3; 32]), 5, &mine))
        .await
        .ok());
    let (b, _) = raw.auth_receive(4096).await;
    assert_eq!((b[1], b[8]), (SUCCESS1, 1));
    let mut f2 = vec![0u8; 8];
    f2[1] = FAILURE2;
    f2[4..6].copy_from_slice(&30u16.to_le_bytes());
    f2[6] = AUTH_FAILED;
    f2[7] = AUTH_FAILED;
    assert!(raw.auth_send(&f2).await.ok());
    assert_eq!(raw.prop_get(0x00, true).await.sc(), AUTHENTICATION_REQUIRED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_commands_are_checked_and_bounded() {
    let srv = start(policy(AUTH_POLICY), Some(params("sha256", "null", false))).await;
    let mut raw = Raw::connect(srv.port).await;
    connect(&mut raw, SECURE).await;
    let msg = negotiate(1, &[1], &[0]);
    // SECP, SPSP0, SPSP1 that are not DH-HMAC-CHAP's.
    for (at, v) in [(43usize, 0xEAu8), (41, 0x02), (42, 0x00)] {
        let mut sqe = auth_sqe(0x05, 72).in_capsule(72);
        sqe.0[at] = v;
        assert_eq!(raw.cmd(&sqe, &msg).await.1.sc(), INVALID_FIELD, "byte {at}");
    }
    // TL 0, and TL past the 4096 bytes any message needs.
    assert_eq!(
        raw.cmd(&auth_sqe(0x05, 0).in_capsule(0), &[]).await.1.sc(),
        INVALID_FIELD
    );
    let big = vec![0u8; 4097];
    assert_eq!(
        raw.cmd(&auth_sqe(0x05, 4097).in_capsule(4097), &big)
            .await
            .1
            .sc(),
        INVALID_FIELD
    );
    // TL that disagrees with the capsule's data.
    assert_eq!(
        raw.cmd(&auth_sqe(0x05, 80).in_capsule(72), &msg)
            .await
            .1
            .sc(),
        SGL_LENGTH_INVALID
    );
    // The negotiate by R2T rather than in the capsule.
    let sqe = auth_sqe(0x05, 72).transport(72);
    let cid = raw.capsule(&sqe, &[]).await;
    let r2t = raw.recv().await;
    assert_eq!(r2t.kind(), R2T);
    assert_eq!(le32(&r2t.header, 16), 72);
    raw.h2c(cid, le16(&r2t.header, 10), 0, &msg, true).await;
    let done = raw.recv().await.cqe();
    assert!(done.ok(), "{done:?}");
    // AL 0, AL past 8 KiB, and an AL too small for the challenge (which stays owed).
    for al in [0u32, 8193] {
        assert_eq!(raw.auth_receive_sc(al).await, INVALID_FIELD, "AL {al}");
    }
    assert_eq!(raw.auth_receive_sc(32).await, INVALID_FIELD);
    let (b, c) = raw.auth_receive(64).await;
    assert!(c.ok());
    assert_eq!(b.len(), 64);
    let ch = challenge(&b);
    assert_eq!(ch.tid, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_model_cannot_require_what_is_not_configured() {
    // No secret: the event says so, and an answer requiring authentication fails closed.
    let srv = start(policy(AUTH_POLICY), None).await;
    let mut raw = Raw::connect(srv.port).await;
    let c = connect(&mut raw, SECURE).await;
    assert_eq!(c.sc(), INTERNAL_ERROR, "{c:?}");
    assert!(c.dnr());
    assert_eq!(
        raw.prop_get(0x00, true).await.sc(),
        SEQUENCE_ERROR,
        "no controller"
    );
    let e = events(&srv.state, srv.id, "nvme_tcp_connect").await;
    assert_eq!(e[0]["authentication_available"], false);

    // Secrets that do not parse, or a controller secret alone, refuse to start the target, and
    // the error does not repeat the secret.
    for p in [
        json!({"dhchap_ctrl_secret": dhhc1(&CTRL_KEY, 0)}),
        json!({"dhchap_secret": "DHHC-1:00:c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2Nzg5MDEy:"}),
        json!({"dhchap_secret": dhhc1(&HOST_KEY, 0), "dhchap_hashes": "md5"}),
    ] {
        let state = netget::state::app_state::AppState::new_with_options(
            false,
            "http://127.0.0.1:1".into(),
        );
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let r = netget::cli::management::ServerForm {
            protocol: "nvme_tcp".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            startup_params: Some(p.clone()),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let text = match r {
            Err(e) => format!("{e:#}"),
            Ok(id) => {
                let mut status = String::new();
                for _ in 0..200 {
                    if let Some(s) = state.get_server(id).await {
                        if let netget::state::server::ServerStatus::Error(e) = &s.status {
                            status = e.clone();
                            break;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                status
            }
        };
        assert!(!text.is_empty(), "{p} does not start");
        assert!(
            !text.contains("c2VjcmV0"),
            "the error does not repeat the secret: {text}"
        );
    }
}
