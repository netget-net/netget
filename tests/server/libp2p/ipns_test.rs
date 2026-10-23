//! The host's DHT records in Rust: IPNS names Kubo publishes into NetGet's DHT and another
//! Kubo resolves out of it, provider records Kubo announces and another Kubo finds, and the
//! host asking a Kubo DHT itself (`ipfs_kad_query`). **Kubo 0.43.1** (`NETGET_KUBO`) and the
//! go-libp2p peer (`NETGET_LIBP2P_GO_PEER`), installed by `install_peers.py`; both fail rather
//! than skip when absent. The model is unreachable except where a test says otherwise, so
//! everything Kubo gets back came from Rust.
use super::dag_test::{start, Host};
use crate::helpers::kubo::Kubo;
use netget::server::libp2p::noise::Identity;
use netget::server::libp2p::{ipns, kad, wire};
use serde_json::{json, Value};
use std::time::Duration;

fn text(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap().trim().to_string()
}

const EMPTY_DIR: &str = "/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn";
const SMALL_FILE: &str = "/ipfs/bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

/// Wait until Kubo's routing table holds NetGet (it adds a DHT server once it has answered
/// FIND_NODE).
async fn in_table(kubo: &Kubo, netget: &str) {
    let ok = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let r = kubo.ipfs(&["stats", "dht"]).await;
            if r.text().contains(netget) {
                return;
            }
            // A lookup makes Kubo talk to its peers sooner than its own refresh would.
            let _ = kubo
                .ipfs(&["routing", "findpeer", "--timeout=2s", netget])
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await;
    assert!(
        ok.is_ok(),
        "NetGet never joined Kubo's routing table\n{}",
        kubo.log()
    );
}

/// One DHT message over go-libp2p: what NetGet wrote back, and whether it reset the stream.
async fn raw_kad(host: &Host, msg: &kad::Message) -> (Option<kad::Message>, String) {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(super::real_client_test::peer())
            .args([
                "raw",
                &host.addr(),
                kad::LAN_KAD,
                &hex::encode(wire::length_prefixed(&kad::encode(msg))),
                "0",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let step: Value = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|s| s["step"] == "raw")
        .unwrap_or_else(|| panic!("{text}"));
    let reply = hex::decode(step["reply_hex"].as_str().unwrap_or_default()).unwrap();
    if reply.is_empty() {
        return (None, text);
    }
    let (n, used) = wire::get_uvarint(&reply).unwrap();
    (
        Some(kad::decode(&reply[used..used + n as usize]).unwrap()),
        text,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kubo_publishes_a_name_into_netgets_dht_and_another_kubo_resolves_it() {
    let mut host = start(json!([]), None).await;
    let netget = host.addr().rsplit('/').next().unwrap().to_string();
    let a = Kubo::start("dhtclient").await;
    let b = Kubo::start("dhtclient").await;
    a.ok(&["swarm", "connect", &host.addr()]).await;
    b.ok(&["swarm", "connect", &host.addr()]).await;
    in_table(&a, &netget).await;
    in_table(&b, &netget).await;

    // A publishes; the only DHT server it knows is NetGet.
    let out = text(
        a.ok(&[
            "name",
            "publish",
            "--resolve=false",
            "--timeout=60s",
            EMPTY_DIR,
        ])
        .await,
    );
    assert!(out.contains(EMPTY_DIR), "{out}");
    host.wait_for(&format!(
        "request=PUT_VALUE decision=stored name={} sequence=0 value={EMPTY_DIR}",
        a.peer_id
    ))
    .await;
    // B, which has never spoken to A, resolves the name out of NetGet's DHT and checks the
    // record itself.
    let name = format!("/ipns/{}", a.peer_id);
    let resolved = text(
        b.ok(&["name", "resolve", "--nocache", "--timeout=60s", &name])
            .await,
    );
    assert_eq!(resolved, EMPTY_DIR);
    let first = b.ok(&["routing", "get", "--timeout=60s", &name]).await;

    // A publishes again: sequence 1 replaces sequence 0, and B sees the new value.
    a.ok(&[
        "name",
        "publish",
        "--resolve=false",
        "--timeout=60s",
        SMALL_FILE,
    ])
    .await;
    host.wait_for(&format!("name={} sequence=1 value={SMALL_FILE}", a.peer_id))
        .await;
    let resolved = text(
        b.ok(&["name", "resolve", "--nocache", "--timeout=60s", &name])
            .await,
    );
    assert_eq!(resolved, SMALL_FILE);
    // B may dial A (NetGet's FIND_NODE names it as a close peer), but A is a DHT client and
    // answers no DHT question: the record B validated came from NetGet's store.
    let log = host
        .wait_for(&format!(
            "request=GET_VALUE source=store name={} sequence=1",
            a.peer_id
        ))
        .await;
    assert!(
        log.contains(&format!(
            "request=GET_VALUE source=store name={} sequence=0",
            a.peer_id
        )),
        "{log}"
    );

    // Kubo's record verifies with NetGet's own checker; a byte changed anywhere does not.
    let key = ipns::key_for_name(&a.peer_id).unwrap();
    let rec = ipns::verify(&key, &first, ipns::now_unix_nanos()).unwrap();
    assert_eq!(
        (rec.sequence, rec.value.as_slice()),
        (0, EMPTY_DIR.as_bytes())
    );
    let mut tampered = first.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(ipns::verify(&key, &tampered, ipns::now_unix_nanos()).is_err());

    // Put to NetGet by hand: the older record (sequence 0) is refused, as is the tampered one;
    // both reset the stream, and the newer record stays.
    for (bytes, why) in [(first.clone(), "is newer"), (tampered, "")] {
        let put = kad::Message {
            record: Some((key.clone(), bytes)),
            ..kad::Message::request(kad::Kind::PutValue, key.clone())
        };
        let (reply, text) = raw_kad(&host, &put).await;
        assert!(reply.is_none(), "{text}");
        assert!(text.contains("reset"), "{text}");
        let log = host.wait_for("decision=refused_record").await;
        assert!(log.contains(why), "{log}");
    }
    let get = kad::Message::request(kad::Kind::GetValue, key.clone());
    let (reply, said) = raw_kad(&host, &get).await;
    let (_, value) = reply.unwrap().record.unwrap_or_else(|| panic!("{said}"));
    assert_eq!(
        ipns::verify(&key, &value, ipns::now_unix_nanos())
            .unwrap()
            .sequence,
        1
    );

    // Providers: A announces a file it adds; B finds A through NetGet's provider store.
    let cid = text(
        a.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            &a.file("mine.txt", b"a's own\n"),
        ])
        .await,
    );
    host.wait_for("request=ADD_PROVIDER decision=stored").await;
    let found = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let r = b
                .ipfs(&["routing", "findprovs", "--timeout=10s", "-n", "1", &cid])
                .await;
            if r.text().contains(&a.peer_id) {
                return r.text();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("B never found A as a provider\n{}", host.drain()));
    assert_eq!(found.trim(), a.peer_id);
    let log = host.drain().to_string();
    assert!(log.contains("request=GET_PROVIDERS source=store"), "{log}");
    // None of it needed the model, which could not have answered.
    assert!(
        !log.contains("operation=ipfs_kad_request decision=model_answer"),
        "{log}"
    );
}

#[test]
fn records_are_verified_before_they_are_kept() {
    let me = Identity::from_seed([3; 32]);
    let other = Identity::from_seed([4; 32]);
    let key = ipns::key_for_name(&me.peer_id_string()).unwrap();
    let later = "2099-01-01T00:00:00.000000000Z";
    let rec = ipns::sign_record(&me, b"/ipfs/x", later, 7, 60_000_000_000);
    let ok = ipns::verify(&key, &rec, ipns::now_unix_nanos()).unwrap();
    assert_eq!(
        (ok.sequence, ok.value.as_slice()),
        (7, b"/ipfs/x".as_slice())
    );
    // Signed by someone else, for this name.
    let forged = ipns::sign_record(&other, b"/ipfs/x", later, 8, 0);
    let e = ipns::verify(&key, &forged, ipns::now_unix_nanos()).unwrap_err();
    assert!(format!("{e:#}").contains("does not verify"), "{e:#}");
    // Expired.
    let old = ipns::sign_record(&me, b"/ipfs/x", "2001-01-01T00:00:00Z", 9, 0);
    let e = ipns::verify(&key, &old, ipns::now_unix_nanos()).unwrap_err();
    assert!(format!("{e:#}").contains("expired"), "{e:#}");
    // Another key type of name, and a key that is not /ipns/.
    assert!(ipns::verify(b"/pk/abc", &rec, 0).is_err());
    // Too big.
    let big = vec![0u8; ipns::MAX_RECORD + 1];
    assert!(ipns::verify(&key, &big, 0).is_err());
    // The store keeps the newest and refuses an older one; the same one again is fine.
    let dht = ipns::Dht::default();
    let newer = ipns::sign_record(&me, b"/ipfs/y", later, 8, 0);
    assert_eq!(dht.put(&key, &rec).unwrap().0, ipns::Put::Stored);
    assert_eq!(dht.put(&key, &newer).unwrap().0, ipns::Put::Stored);
    assert_eq!(dht.put(&key, &newer).unwrap().0, ipns::Put::Same);
    assert!(dht.put(&key, &rec).is_err());
    assert_eq!(dht.get(&key).unwrap().value, b"/ipfs/y");
    // A V1 field that disagrees with the signed data is refused.
    let mut v1 = newer.clone();
    v1.extend([0x28, 0x63]); // sequence (field 5) = 99
    assert!(ipns::verify(&key, &v1, ipns::now_unix_nanos()).is_err());
    // The fuzz corpus's records, signed in Python by RFC 8032's reference code, verify here;
    // its depth bomb gets past the signature and is refused by the CBOR reader.
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/ipns_record");
    for (seed, ok) in [
        ("put_v2", true),
        ("put_v1_and_v2", true),
        ("depth_bomb", false),
    ] {
        let m = kad::decode(&std::fs::read(corpus.join(seed)).unwrap()).unwrap();
        let (key, value) = m.record.unwrap();
        let r = ipns::verify(&key, &value, 0);
        assert_eq!(r.is_ok(), ok, "{seed}: {r:?}");
        if !ok {
            assert!(
                format!("{:#}", r.unwrap_err()).contains("not a scalar"),
                "{seed}"
            );
        }
    }
    // Provider records: bounded per key, newest kept.
    let peer = |i: u8| kad::Peer {
        id: Identity::from_seed([i; 32]).peer_id,
        addrs: vec![],
    };
    for i in 0..(ipns::MAX_PROVIDERS_PER_KEY as u8 + 5) {
        dht.add_provider(b"k", peer(i));
    }
    let list = dht.providers(b"k");
    assert_eq!(list.len(), ipns::MAX_PROVIDERS_PER_KEY);
    assert_eq!(
        list.last().unwrap().id,
        peer(ipns::MAX_PROVIDERS_PER_KEY as u8 + 4).id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_asks_a_kubo_dht_itself() {
    // The model answers every event with nothing; the questions are injected as the
    // dashboard would, and their answers become ipfs_kad_answer events.
    let mut host = start(
        json!([]),
        Some(vec![
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
    )
    .await;
    let kubo = Kubo::start("dhtserver").await;
    kubo.ok(&["swarm", "connect", &host.addr()]).await;
    let cid = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            &kubo.file("k.txt", b"kubo's\n"),
        ])
        .await,
    );
    kubo.ok(&[
        "name",
        "publish",
        "--resolve=false",
        "--allow-offline",
        "--timeout=60s",
        EMPTY_DIR,
    ])
    .await;
    let conn = host.connection().await;
    for q in [
        json!({"type": "ipfs_kad_query", "request": "FIND_NODE", "peer_id": kubo.peer_id, "protocol": kad::LAN_KAD}),
        json!({"type": "ipfs_kad_query", "request": "GET_PROVIDERS", "cid": cid, "protocol": kad::LAN_KAD}),
        json!({"type": "ipfs_kad_query", "request": "GET_VALUE", "name": kubo.peer_id, "protocol": kad::LAN_KAD}),
    ] {
        let detail = host.inject(conn, q.clone()).await;
        assert!(detail.contains("Executed"), "{q}: {detail}");
    }
    let answers = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let a = host.events("ipfs_kad_answer").await;
            if a.len() >= 3 {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fewer than 3 answers\n{}", host.drain()));
    let by = |r: &str| answers.iter().find(|a| a["request"] == r).unwrap().clone();
    let find = by("FIND_NODE");
    assert!(
        find["closer_peers"].to_string().contains(&kubo.peer_id),
        "{find}"
    );
    let provs = by("GET_PROVIDERS");
    assert!(
        provs["provider_peers"].to_string().contains(&kubo.peer_id),
        "{provs}"
    );
    let value = by("GET_VALUE");
    assert_eq!(value["record"]["valid"], true, "{value}");
    assert_eq!(value["record"]["value"], EMPTY_DIR, "{value}");
    assert_eq!(value["record"]["name"], kubo.peer_id.as_str(), "{value}");
    // A ninth question inside a minute is refused.
    for _ in 0..5 {
        host.inject(
            conn,
            json!({"type": "ipfs_kad_query", "request": "FIND_NODE", "peer_id": kubo.peer_id, "protocol": kad::LAN_KAD}),
        )
        .await;
    }
    let refused = host
        .inject(
            conn,
            json!({"type": "ipfs_kad_query", "request": "FIND_NODE", "peer_id": kubo.peer_id}),
        )
        .await;
    assert!(refused.contains("a minute"), "{refused}");
}
