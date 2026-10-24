//! NetGet's libp2p host as an IPFS peer (`ipfs: true`), against **Kubo 0.43.1** (`NETGET_KUBO`)
//! and the go-libp2p peer (`NETGET_LIBP2P_GO_PEER`), both installed by `install_peers.py`.
//! Both fail rather than skip when absent. No LLM calls: a python policy is the model.
//!
//! - Kubo connects, and `ipfs cat` / `ipfs block get` fetch content the model supplied over
//!   Bitswap; Kubo's own hash verification passes, and Kubo's `ipfs add --only-hash` agrees
//!   with NetGet about every CID.
//! - Kubo's DHT (LAN, loopback only) finds NetGet as a provider through GET_PROVIDERS.
//! - Over go-libp2p, bytes written by hand: a block the model claims under a CID it does not
//!   hash to is never sent (DONT_HAVE instead), go-cid recomputes the CID of what is sent, a
//!   failed model answers DONT_HAVE, and oversized, malformed and unknown-codec messages are
//!   refused before the model is asked.
use crate::helpers::kubo::Kubo;
use netget::cli::management::ServerForm;
use netget::server::libp2p::bitswap::{self, Entry, Message, Version, WantType};
use netget::server::libp2p::ipfs::{self, Cid};
use netget::server::libp2p::{kad, wire};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const SEED: &str = "netget-ipfs-test";
const SMALL: &str = "hello from netget over bitswap\n";

fn big() -> String {
    (0..200_000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect()
}

/// Supplies SMALL and BIG in both formats for any want; Rust sends only what matches.
/// "bad" content is offered under every want's CID, so a claim that does not hash is tried
/// every time. DHT: NetGet itself provides everything.
const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
S='hello from netget over bitswap\n'
B=''.join(chr(97+k%26) for k in range(200000))
if t=='ipfs_bitswap_want':
  blocks=[{'content':c,'format':f} for c in (S,B) for f in ('raw','unixfs')]
  blocks+=[{'content':'not what was asked for','cid':w['cid']} for w in e['wants']]
  a=[{'type':'ipfs_bitswap_blocks','blocks':blocks}]
elif t=='ipfs_kad_request' and e['request']=='GET_PROVIDERS':
  a=[{'type':'ipfs_kad_reply','provider_peers':[{'peer_id':'self'}]}]
print(json.dumps({'actions':a}))"#;

fn peer_id() -> String {
    netget::server::libp2p::identity_from_params(Some(SEED.into()))
        .unwrap()
        .peer_id_string()
}

async fn start(
    handlers: Option<Vec<Value>>,
) -> (AppState, ServerId, u16, mpsc::UnboundedReceiver<String>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "libp2p".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be an IPFS peer".into()),
        startup_params: Some(json!({"private_key_seed": SEED, "ipfs": true})),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port, rx)
}

fn policy() -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
    ])
}

async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

fn drain(rx: &mut mpsc::UnboundedReceiver<String>) -> String {
    let mut s = String::new();
    while let Ok(l) = rx.try_recv() {
        s.push_str(&l);
        s.push('\n');
    }
    s
}

fn text(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap().trim().to_string()
}

#[tokio::test]
async fn kubo_fetches_what_the_model_serves() {
    let (state, id, port, mut rx) = start(policy()).await;
    let kubo = Kubo::start("none").await;
    let big = big();

    // Kubo's own CIDs for the content, without storing it: the model's content is the only
    // place Kubo can get the blocks from.
    let small_file = kubo.file("small.txt", SMALL.as_bytes());
    let big_file = kubo.file("big.txt", big.as_bytes());
    let small_v0 = text(kubo.ok(&["add", "-Q", "-n", &small_file]).await);
    let small_v1 = text(
        kubo.ok(&["add", "-Q", "-n", "--cid-version=1", &small_file])
            .await,
    );
    let big_v0 = text(kubo.ok(&["add", "-Q", "-n", &big_file]).await);
    assert!(
        small_v0.starts_with("Qm") && big_v0.starts_with("Qm"),
        "{small_v0} {big_v0}"
    );
    assert!(small_v1.starts_with("bafkrei"), "{small_v1}");

    // NetGet's data model agrees with Kubo's about every one of them, in both directions.
    let pb = |c: &str| {
        let cid = Cid::v1(ipfs::DAG_PB, &ipfs::unixfs_file_block(c.as_bytes()));
        Cid { version: 0, ..cid }.to_string()
    };
    assert_eq!(pb(SMALL), small_v0);
    assert_eq!(pb(&big), big_v0);
    assert_eq!(Cid::v1(ipfs::RAW, SMALL.as_bytes()).to_string(), small_v1);
    for c in [&small_v0, &small_v1, &big_v0] {
        assert_eq!(&Cid::parse(c).unwrap().to_string(), c);
    }

    let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", peer_id());
    kubo.ok(&["swarm", "connect", &addr]).await;

    // Kubo fetches each from NetGet, checks it against its CID, and reassembles the file.
    assert_eq!(
        kubo.ok(&["cat", "--timeout=60s", &small_v1]).await,
        SMALL.as_bytes()
    );
    assert_eq!(
        kubo.ok(&["cat", "--timeout=60s", &small_v0]).await,
        SMALL.as_bytes()
    );
    assert_eq!(
        kubo.ok(&["cat", "--timeout=60s", &big_v0]).await,
        big.as_bytes()
    );
    assert_eq!(
        kubo.ok(&["block", "get", "--timeout=60s", &small_v0]).await,
        ipfs::unixfs_file_block(SMALL.as_bytes())
    );

    // What the model was asked.
    let wants = events(&state, id, "ipfs_bitswap_want").await;
    let asked: Vec<&str> = wants
        .iter()
        .flat_map(|w| w["wants"].as_array().unwrap())
        .map(|w| w["cid"].as_str().unwrap())
        .collect();
    for c in [&small_v1, &small_v0, &big_v0] {
        assert!(asked.contains(&c.as_str()), "{c} never asked: {wants:?}");
    }
    let first = wants
        .iter()
        .flat_map(|w| w["wants"].as_array().unwrap())
        .find(|w| w["cid"] == small_v1.as_str())
        .unwrap();
    assert_eq!(first["codec"], "raw");

    // Every block went out because it matched a want; the bad offers never did.
    let log = drain(&mut rx);
    assert!(log.contains("operation=bitswap blocks=1"), "{log}");
    assert!(log.contains("decision=refused_block"), "{log}");

    // Kubo spoke to NetGet and to nobody else, over loopback.
    let peers = kubo.swarm_peers().await;
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert!(
        peers[0].starts_with("/ip4/127.0.0.1/") && peers[0].ends_with(&peer_id()),
        "{peers:?}"
    );
}

#[tokio::test]
async fn kubo_finds_netget_as_a_provider_through_its_dht() {
    let (state, id, port, mut rx) = start(policy()).await;
    let kubo = Kubo::start("dhtclient").await;
    let cid = Cid::v1(ipfs::RAW, SMALL.as_bytes()).to_string();
    let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", peer_id());
    kubo.ok(&["swarm", "connect", &addr]).await;

    // NetGet joins Kubo's routing table once Kubo has checked it answers FIND_NODE for its
    // own id; until then the lookup finds nobody, so ask until it finds NetGet.
    let found = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let r = kubo
                .ipfs(&["routing", "findprovs", "--timeout=10s", "-n", "1", &cid])
                .await;
            if r.text().contains(&peer_id()) {
                return r.text();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Kubo's DHT never found NetGet\n{}", kubo.log()));
    assert_eq!(found.trim(), peer_id());

    let requests = events(&state, id, "ipfs_kad_request").await;
    let get = requests
        .iter()
        .find(|r| r["request"] == "GET_PROVIDERS")
        .unwrap_or_else(|| panic!("{requests:?}"));
    assert!(
        get["cids"].as_array().unwrap().contains(&json!(cid)),
        "{get}"
    );
    assert_eq!(get["peer_id"], kubo.peer_id.as_str());
    assert!(
        requests
            .iter()
            .all(|r| r["request"] == "GET_PROVIDERS" || r["request"] == "ADD_PROVIDER"),
        "routing questions are answered without the model: {requests:?}"
    );

    // Kubo announces what it adds to the DHT servers closest to it: NetGet hears ADD_PROVIDER
    // naming Kubo, with Kubo's own (loopback) address.
    let added = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            &kubo.file("mine.txt", b"kubo's own\n"),
        ])
        .await,
    );
    let announced = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let hit = events(&state, id, "ipfs_kad_request")
                .await
                .into_iter()
                .find(|r| {
                    r["request"] == "ADD_PROVIDER"
                        && r["cids"].as_array().unwrap().contains(&json!(added))
                });
            if let Some(r) = hit {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Kubo never announced {added} to NetGet\n{}", kubo.log()));
    let provider = &announced["providers"][0];
    assert_eq!(provider["peer_id"], kubo.peer_id.as_str(), "{announced}");
    assert!(
        provider["addrs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a.as_str().unwrap().starts_with("/ip4/127.0.0.1/")),
        "{announced}"
    );
    // NetGet is in Kubo's routing table: it advertised the DHT protocols and answered as a
    // DHT server (FIND_NODE in Rust, GET_PROVIDERS through the model).
    let table = String::from_utf8(kubo.ok(&["stats", "dht"]).await).unwrap();
    assert!(table.contains(&peer_id()), "{table}");
    let log = drain(&mut rx);
    assert!(
        log.contains("operation=kad request=GET_PROVIDERS closer=0 providers=1"),
        "{log}"
    );
}

// ---------------------------------------------------------------------------------------
// By hand, over go-libp2p.

fn want(cid: Cid, want_type: WantType) -> Entry {
    Entry {
        cid,
        priority: 1,
        cancel: false,
        want_type,
        send_dont_have: true,
    }
}

fn wantlist(entries: Vec<Entry>) -> Vec<u8> {
    bitswap::encode(
        &Message {
            entries,
            ..Default::default()
        },
        Version::V120,
    )
}

/// go-libp2p writes `bytes` on a `protocol` stream, then waits for `inbound` Bitswap
/// messages NetGet sends back: (what came back on the stream, the messages, all steps).
async fn raw(
    port: u16,
    protocol: &str,
    bytes: &[u8],
    inbound: usize,
) -> (Value, Vec<Value>, String) {
    let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", peer_id());
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new(super::real_client_test::peer())
            .args([
                "raw",
                &addr,
                protocol,
                &hex::encode(bytes),
                &inbound.to_string(),
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the go-libp2p peer did not finish")
    .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let steps: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let reply = steps
        .iter()
        .find(|s| s["step"] == "raw")
        .cloned()
        .unwrap_or_else(|| panic!("no raw step: {text}"));
    let inbound = steps
        .iter()
        .filter(|s| s["step"] == "bitswap_in")
        .cloned()
        .collect();
    (reply, inbound, text)
}

#[tokio::test]
async fn a_block_that_does_not_hash_is_never_sent() {
    // The model offers the right bytes for GOOD, and wrong bytes claimed as BAD (and the
    // policy's own bad offer under every want). go-cid recomputes the CID of whatever arrives.
    let good = Cid::v1(ipfs::RAW, SMALL.as_bytes());
    let bad = Cid::v1(ipfs::RAW, b"the bytes the model does not have");
    let (state, id, port, mut rx) = start(policy()).await;
    let (_, inbound, text) = raw(
        port,
        bitswap::BITSWAP_120,
        &wire::length_prefixed(&wantlist(vec![
            want(good, WantType::Block),
            want(bad, WantType::Have),
        ])),
        1,
    )
    .await;
    let m = inbound
        .first()
        .unwrap_or_else(|| panic!("no answer: {text}"));
    assert_eq!(
        m["blocks"],
        json!([{"cid": good.to_string(), "data": SMALL}]),
        "go-cid recomputed the CID of the one block sent: {text}"
    );
    assert_eq!(
        m["presences"],
        json!([{"cid": bad.to_string(), "type": "dont_have"}]),
        "{text}"
    );
    let log = drain(&mut rx);
    assert!(
        log.contains("decision=refused_block") && log.contains(&format!("claimed as {bad}")),
        "{log}"
    );
    assert_eq!(events(&state, id, "ipfs_bitswap_want").await.len(), 1);
}

#[tokio::test]
async fn a_failed_model_answers_dont_have() {
    let (_state, _id, port, mut rx) = start(None).await;
    let cid = Cid::v1(ipfs::RAW, SMALL.as_bytes());
    let (_, inbound, text) = raw(
        port,
        bitswap::BITSWAP_120,
        &wire::length_prefixed(&wantlist(vec![want(cid, WantType::Block)])),
        1,
    )
    .await;
    let m = inbound
        .first()
        .unwrap_or_else(|| panic!("no answer: {text}"));
    assert_eq!(m["blocks"], json!([]), "{text}");
    assert_eq!(
        m["presences"],
        json!([{"cid": cid.to_string(), "type": "dont_have"}]),
        "{text}"
    );
    assert!(drain(&mut rx).contains("decision=fail_closed_llm_error"));

    // A DHT question about providers claims nobody: the stream is reset at once.
    let get = kad::encode(&kad::Message::request(
        kad::Kind::GetProviders,
        cid.multihash(),
    ));
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&get), 0).await;
    assert!(
        r["error"].as_str().unwrap_or_default().contains("reset"),
        "{text}"
    );
    assert_eq!(r["reply_hex"], "", "{text}");
    assert!(drain(&mut rx).contains("decision=fail_closed_llm_error"));
}

#[tokio::test]
async fn refusals_before_the_model() {
    let (state, id, port, _rx) = start(policy()).await;
    let reset = |r: &Value| r["error"].as_str().unwrap_or_default().contains("reset");

    // A message announcing more than Bitswap's 4 MiB is reset before it is read.
    let mut over = Vec::new();
    wire::put_uvarint(&mut over, bitswap::MAX_MESSAGE as u64 + 1);
    over.extend([0u8; 64]);
    let (r, _, text) = raw(port, bitswap::BITSWAP_120, &over, 0).await;
    assert!(reset(&r), "oversized: {text}");

    // Malformed protobuf: a field running past the message.
    let (r, _, text) = raw(
        port,
        bitswap::BITSWAP_120,
        &wire::length_prefixed(&[0x0a, 0x7f, 0x01]),
        0,
    )
    .await;
    assert!(reset(&r), "malformed: {text}");

    // One entry past the wantlist bound.
    let cid = Cid::v1(ipfs::RAW, b"x");
    let many = (0..=bitswap::MAX_WANTLIST_ENTRIES)
        .map(|_| want(cid, WantType::Have))
        .collect();
    let (r, _, text) = raw(
        port,
        bitswap::BITSWAP_120,
        &wire::length_prefixed(&wantlist(many)),
        0,
    )
    .await;
    assert!(reset(&r), "too many wants: {text}");

    // A dag-cbor CID is not something NetGet can build: DONT_HAVE, without asking.
    let cbor = Cid {
        codec: 0x71,
        ..Cid::v1(ipfs::RAW, b"{}")
    };
    let (_, inbound, text) = raw(
        port,
        bitswap::BITSWAP_120,
        &wire::length_prefixed(&wantlist(vec![want(cbor, WantType::Block)])),
        1,
    )
    .await;
    assert_eq!(
        inbound.first().map(|m| m["presences"].clone()),
        Some(json!([{"cid": cbor.to_string(), "type": "dont_have"}])),
        "{text}"
    );

    // ADD_PROVIDER naming a peer other than the sender is dropped (a peer announces itself).
    let other = netget::server::libp2p::noise::Identity::from_seed([5; 32]);
    let add = kad::encode(&kad::Message {
        providers: vec![kad::Peer {
            id: other.peer_id.clone(),
            addrs: vec![wire::multiaddr_from_text("/ip4/127.0.0.1/tcp/1").unwrap()],
        }],
        ..kad::Message::request(kad::Kind::AddProvider, cid.multihash())
    });
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&add), 0).await;
    assert_eq!(r["reply_hex"], "", "ADD_PROVIDER has no answer: {text}");

    // DHT: malformed, and PUT_VALUE (records are not stored), are reset; PING is answered.
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&[0x08]), 0).await;
    assert!(reset(&r), "malformed DHT message: {text}");
    let put = kad::encode(&kad::Message {
        record: Some((b"/ipns/x".to_vec(), b"not a record".to_vec())),
        ..kad::Message::request(kad::Kind::PutValue, b"/ipns/x".to_vec())
    });
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&put), 0).await;
    assert!(reset(&r), "PUT_VALUE: {text}");
    let ping = kad::encode(&kad::Message::request(kad::Kind::Ping, Vec::new()));
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&ping), 0).await;
    let reply = hex::decode(r["reply_hex"].as_str().unwrap()).unwrap();
    let (n, used) = wire::get_uvarint(&reply).unwrap_or_else(|e| panic!("{e}: {text}"));
    assert_eq!(
        kad::decode(&reply[used..used + n as usize]).unwrap().kind,
        kad::Kind::Ping
    );

    // None of it reached the model.
    assert!(events(&state, id, "ipfs_bitswap_want").await.is_empty());
    assert!(events(&state, id, "ipfs_kad_request").await.is_empty());
}

/// One DHT request over go-libp2p, and the answer NetGet wrote back on the same stream.
async fn kad_exchange(port: u16, req: &kad::Message) -> kad::Message {
    let (r, _, text) = raw(port, kad::KAD, &wire::length_prefixed(&kad::encode(req)), 0).await;
    let reply = hex::decode(r["reply_hex"].as_str().unwrap()).unwrap();
    let (n, used) = wire::get_uvarint(&reply).unwrap_or_else(|e| panic!("{e}: {text}"));
    kad::decode(&reply[used..used + n as usize]).unwrap()
}

#[tokio::test]
async fn find_node_is_answered_from_what_netget_knows() {
    let (state, id, port, _rx) = start(policy()).await;
    let me = netget::server::libp2p::identity_from_params(Some(SEED.into()))
        .unwrap()
        .peer_id;

    // Asked for its own id, a DHT server names itself, with the address it listens on.
    let own = kad_exchange(
        port,
        &kad::Message::request(kad::Kind::FindNode, me.clone()),
    )
    .await;
    assert_eq!(own.kind, kad::Kind::FindNode);
    assert_eq!(own.key, me);
    assert_eq!(own.closer.len(), 1, "{own:?}");
    assert_eq!(own.closer[0].id, me);
    assert_eq!(
        own.closer[0].to_json()["addrs"],
        json!([format!("/ip4/127.0.0.1/tcp/{port}")])
    );

    // Asked for anyone else, with nobody but the asker connected, it knows nobody: it never
    // names the asker back to itself, and invents no one.
    let other = netget::server::libp2p::noise::Identity::from_seed([9; 32]).peer_id;
    let none = kad_exchange(port, &kad::Message::request(kad::Kind::FindNode, other)).await;
    assert!(none.closer.is_empty(), "{none:?}");

    // Any other key asks for the peers closest to it (Kubo looks up `/ipns/…` record keys
    // this way): answered, with nobody. Only an empty key is refused.
    let record_key = kad_exchange(
        port,
        &kad::Message::request(kad::Kind::FindNode, b"/ipns/not a peer id".to_vec()),
    )
    .await;
    assert!(record_key.closer.is_empty(), "{record_key:?}");
    let (r, _, text) = raw(
        port,
        kad::KAD,
        &wire::length_prefixed(&kad::encode(&kad::Message::request(
            kad::Kind::FindNode,
            Vec::new(),
        ))),
        0,
    )
    .await;
    assert!(r["error"].as_str().unwrap().contains("reset"), "{text}");

    // Routing facts never cost a model call.
    assert!(events(&state, id, "ipfs_kad_request").await.is_empty());
}

#[test]
fn the_data_model_round_trips() {
    let raw = Cid::v1(ipfs::RAW, b"hello");
    let text = raw.to_string();
    assert!(text.starts_with("bafkrei"), "{text}");
    assert_eq!(Cid::parse(&text).unwrap(), raw);
    assert_eq!(Cid::from_bytes(&raw.to_bytes()).unwrap(), raw);
    assert_eq!(
        Cid::from_prefix(&raw.prefix(), b"hello").unwrap(),
        raw,
        "a prefix and the bytes name the CID"
    );
    assert_ne!(Cid::from_prefix(&raw.prefix(), b"hellO").unwrap(), raw);
    let v0 = Cid {
        version: 0,
        codec: ipfs::DAG_PB,
        ..raw
    };
    assert!(v0.to_string().starts_with("Qm"));
    assert_eq!(Cid::parse(&v0.to_string()).unwrap(), v0);
    // Only sha2-256: a sha2-512 multihash is refused by name.
    let mut sha512 = vec![0x01, 0x55, 0x13, 0x40];
    sha512.extend([0u8; 64]);
    assert!(format!("{:#}", Cid::from_bytes(&sha512).unwrap_err()).contains("sha2-512"));
    assert!(Cid::parse("not a cid").is_err());
    for s in ["", "a", "ab", "abcdefghij"] {
        assert_eq!(
            ipfs::base32_decode(&ipfs::base32_encode(s.as_bytes())).unwrap(),
            s.as_bytes()
        );
    }
    // A dag-pb node with links decodes to what was encoded.
    let node = ipfs::PbNode {
        links: vec![ipfs::Link {
            cid: raw,
            name: "a".into(),
            size: 5,
        }],
        data: Some(ipfs::encode_unixfs(&ipfs::UnixFs {
            kind: "file".into(),
            data: Vec::new(),
            file_size: Some(5),
            block_sizes: vec![5],
        })),
    };
    let d = ipfs::describe(
        &Cid::v1(ipfs::DAG_PB, &ipfs::encode_pb_node(&node)),
        &ipfs::encode_pb_node(&node),
    )
    .unwrap();
    assert_eq!(
        (d.unixfs_type.as_deref(), d.file_size),
        (Some("file"), Some(5))
    );
    assert_eq!(d.links, node.links);
}

#[test]
fn a_block_over_two_mib_is_refused_both_ways() {
    use bitswap::{Format, Supplied};
    let over = vec![b'x'; ipfs::MAX_BLOCK + 1];
    // The model cannot supply one...
    assert!(Supplied::new(&over, Format::Raw, None).is_err());
    assert!(Supplied::new(&over[..ipfs::MAX_BLOCK], Format::Raw, None).is_ok());
    // ...and a peer cannot deliver one, whatever its prefix says.
    let cid = Cid::v1(ipfs::RAW, &over);
    let message = |data: &[u8]| {
        bitswap::encode(
            &Message {
                blocks: vec![bitswap::Block {
                    cid,
                    data: data.to_vec(),
                }],
                ..Default::default()
            },
            Version::V120,
        )
    };
    let e = bitswap::decode(&message(&over)).unwrap_err();
    assert!(format!("{e:#}").contains("block over"), "{e:#}");
    assert_eq!(
        bitswap::decode(&message(&over[..ipfs::MAX_BLOCK]))
            .unwrap()
            .blocks
            .len(),
        1
    );
}
