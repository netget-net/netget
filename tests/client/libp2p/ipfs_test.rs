//! NetGet's libp2p dialler as an IPFS peer (`ipfs: true`), against **Kubo 0.43.1**
//! (`NETGET_KUBO`) and the go-libp2p peer lying about blocks (`NETGET_LIBP2P_GO_PEER
//! bitswap-liar`). Both are installed by `tests/server/libp2p/install_peers.py`, and the tests
//! fail rather than skip without them. No LLM calls: a python chain is the model.
//!
//! - Kubo `ipfs add`s files; NetGet fetches them by CID over Bitswap, a chunked file root
//!   first and then the leaves its links name, and the model receives verified content.
//! - NetGet asks Kubo's DHT FIND_NODE and GET_PROVIDERS.
//! - A peer answering a want with bytes that do not hash to the CID is refused before the
//!   model hears of it.
use crate::helpers::kubo::Kubo;
use netget::cli::management::ClientForm;
use netget::server::libp2p::ipfs::{self, Cid};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

async fn client(
    addr: &str,
    handlers: Vec<Value>,
) -> (AppState, ClientId, mpsc::UnboundedReceiver<String>) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "libp2p".into(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Fetch blocks".into()),
        startup_params: Some(json!({"ipfs": true})),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect");
    (state, id, rx)
}

async fn logged(state: &AppState, id: ClientId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

/// Wait until `n` events of a type have been raised; all of them.
async fn wait_for(state: &AppState, id: ClientId, event_type: &str, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let got = logged(state, id, event_type).await;
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fewer than {n} {event_type} events"))
}

fn text(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap().trim().to_string()
}

#[tokio::test]
async fn netget_fetches_what_kubo_added() {
    let kubo = Kubo::start("none").await;
    let small = "a small file kubo added\n";
    let other = "another, added as CIDv1 with raw leaves\n";
    let chunked: String = (0..3000)
        .map(|i| char::from(b'A' + (i % 26) as u8))
        .collect();
    let v0 = text(
        kubo.ok(&["add", "-Q", &kubo.file("a.txt", small.as_bytes())])
            .await,
    );
    let v1 = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            &kubo.file("b.txt", other.as_bytes()),
        ])
        .await,
    );
    let root = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            "--chunker=size-1024",
            &kubo.file("c.txt", chunked.as_bytes()),
        ])
        .await,
    );
    assert!(v0.starts_with("Qm") && v1.starts_with("bafkrei") && root.starts_with("bafybei"));

    // Want the three; want every link of a dag-pb block that arrives.
    let chain = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='libp2p_connected':
  a=[{{'type':'ipfs_bitswap_want','cids':{cids}}}]
elif t=='ipfs_block_received' and e['links']:
  a=[{{'type':'ipfs_bitswap_want','cids':[l['cid'] for l in e['links']]}}]
print(json.dumps({{'actions':a}}))"#,
        cids = json!([v0, v1, root])
    );
    let (state, id, mut rx) = client(
        &kubo.swarm_addr,
        vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}})],
    )
    .await;

    // Three files, plus the chunked file's three leaves.
    let blocks = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let got = logged(&state, id, "ipfs_block_received").await;
            if got.len() >= 6 {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let mut log = String::new();
        while let Ok(l) = rx.try_recv() {
            log.push_str(&l);
            log.push('\n');
        }
        panic!("not every block arrived\n{log}")
    });
    assert_eq!(blocks.len(), 6, "each block is reported once: {blocks:?}");
    let block = |cid: &str| {
        blocks
            .iter()
            .find(|b| b["cid"] == cid)
            .unwrap_or_else(|| panic!("no block {cid}: {blocks:?}"))
            .clone()
    };
    let a = block(&v0);
    assert_eq!(
        (
            a["codec"].as_str(),
            a["unixfs_type"].as_str(),
            a["data"].as_str()
        ),
        (Some("dag-pb"), Some("file"), Some(small))
    );
    let b = block(&v1);
    assert_eq!(
        (b["codec"].as_str(), b["data"].as_str()),
        (Some("raw"), Some(other))
    );
    let r = block(&root);
    assert_eq!(r["file_size"], 3000, "{r}");
    let links: Vec<String> = r["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["cid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(links.len(), 3, "{r}");
    let assembled: String = links
        .iter()
        .map(|l| block(l)["data"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        assembled, chunked,
        "the leaves, in link order, are the file"
    );

    // Kubo's bytes hash, in NetGet's data model too, to what Kubo called them.
    let raw = Cid::v1(ipfs::RAW, other.as_bytes()).to_string();
    assert_eq!(raw, v1);

    // Kubo talked to NetGet alone, over loopback.
    let peers = kubo.swarm_peers().await;
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert!(peers[0].starts_with("/ip4/127.0.0.1/"), "{peers:?}");
}

#[tokio::test]
async fn netget_asks_kubos_dht() {
    let kubo = Kubo::start("dhtserver").await;
    let cid = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            &kubo.file("p.txt", b"provided\n"),
        ])
        .await,
    );
    let (state, id, _rx) = client(
        &kubo.swarm_addr,
        vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})],
    )
    .await;
    let ask = |action: Value| {
        let state = state.clone();
        async move {
            match state
                .send_to_client(id, action, Duration::from_secs(30))
                .await
                .unwrap()
            {
                ClientSendOutcome::Executed { detail } => {
                    serde_json::from_str::<Value>(&detail).unwrap()
                }
                other => panic!("{other:?}"),
            }
        }
    };

    // FIND_NODE for Kubo's own id: Kubo names itself.
    let found = ask(json!({"type":"ipfs_kad_find_node","peer_id": kubo.peer_id})).await;
    assert_eq!(found["ok"], true, "{found}");
    assert!(
        found["closer_peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["peer_id"] == kubo.peer_id.as_str()),
        "{found}"
    );
    // GET_PROVIDERS for what Kubo added: Kubo provides it.
    let providers = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            // Kubo's WAN DHT is inactive with no public peers, so its own record is in the LAN
            // DHT's store.
            let r = ask(json!({"type":"ipfs_kad_get_providers","cid": cid,
                               "protocol": "/ipfs/lan/kad/1.0.0"}))
            .await;
            if r["provider_peers"]
                .as_array()
                .is_some_and(|p| p.iter().any(|p| p["peer_id"] == kubo.peer_id.as_str()))
            {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Kubo never named itself a provider of {cid}"));
    assert_eq!(providers["request"], "GET_PROVIDERS");

    // A malformed request is refused before anything is sent.
    let bad = state
        .send_to_client(
            id,
            json!({"type":"ipfs_kad_find_node","peer_id":"not-a-peer-id"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(matches!(bad, ClientSendOutcome::Rejected { .. }), "{bad:?}");
    let responses = logged(&state, id, "libp2p_response").await;
    assert!(responses.len() >= 2, "{responses:?}");
}

#[tokio::test]
async fn a_block_that_does_not_hash_is_refused() {
    let good = "the bytes that were asked for";
    let mut liar = tokio::process::Command::new(crate::client::libp2p::real_server_test::peer())
        .args(["bitswap-liar", good])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(liar.stdout.take().unwrap()).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    let addr = first["addr"].as_str().unwrap().to_string();
    let (state, id, mut rx) = client(
        &addr,
        vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})],
    )
    .await;

    let good_cid = Cid::v1(ipfs::RAW, good.as_bytes()).to_string();
    let bad_cid = Cid::v1(ipfs::RAW, b"bytes the liar does not have").to_string();
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"ipfs_bitswap_want","cids":[good_cid, bad_cid]}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );

    // The liar answered both in one message; the good block is reported and the other is not.
    let blocks = wait_for(&state, id, "ipfs_block_received", 1).await;
    assert_eq!(blocks.len(), 1, "{blocks:?}");
    assert_eq!(
        (blocks[0]["cid"].as_str(), blocks[0]["data"].as_str()),
        (Some(good_cid.as_str()), Some(good))
    );
    let mut log = String::new();
    while let Ok(l) = rx.try_recv() {
        log.push_str(&l);
        log.push('\n');
    }
    assert!(
        log.contains("decision=refused_block") && log.contains("matches nothing that was wanted"),
        "{log}"
    );
    // A CID NetGet cannot verify is refused before anything is sent.
    let cbor = Cid {
        codec: 0x71,
        ..Cid::v1(ipfs::RAW, b"{}")
    };
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"ipfs_bitswap_want","cids":[cbor.to_string()]}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("dag-cbor")),
        "{outcome:?}"
    );
    drop(liar);
}
