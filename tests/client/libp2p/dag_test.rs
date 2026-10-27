//! NetGet's dialler fetching whole DAGs with `ipfs_fetch`: files of many blocks and directory
//! trees that **Kubo 0.43.1** (`NETGET_KUBO`) and **Helia** (`NETGET_HELIA`) added and serve,
//! and a go-libp2p peer that tampers with blocks (`NETGET_LIBP2P_GO_PEER bitswap-liar`). All
//! installed by `tests/server/libp2p/install_peers.py`; the tests fail rather than skip
//! without them. No LLM calls: a python chain is the model, and it is the model's own
//! `ipfs_fetch` actions that start every walk.
//!
//! What is checked is the content, against the bytes on disk: a file's size and SHA-256, its
//! first bytes, a directory's names, kinds and sizes, and a symlink's target.
use crate::helpers::ipfs_fixtures::{noise, tree, write_tree};
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
        instruction: Some("Fetch what you are told to".into()),
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

async fn fetched(state: &AppState, id: ClientId) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "ipfs_fetched")
        .map(|e| e["request"].clone())
        .collect()
}

async fn wait_fetched(
    state: &AppState,
    id: ClientId,
    n: usize,
    rx: &mut mpsc::UnboundedReceiver<String>,
) -> Vec<Value> {
    let got = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let got = fetched(state, id).await;
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    got.unwrap_or_else(|_| panic!("fewer than {n} ipfs_fetched events\n{}", drain(rx)))
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

fn sha(b: &[u8]) -> String {
    hex::encode(ipfs::sha256(b))
}

/// On connect, fetch each CID in turn (the model's own actions; the client performs them in
/// order).
fn fetch_all(cids: &[(&str, Value)]) -> Vec<Value> {
    let actions: Vec<Value> = cids
        .iter()
        .map(|(cid, extra)| {
            let mut a = json!({"type": "ipfs_fetch", "cid": cid});
            for (k, v) in extra.as_object().unwrap() {
                a[k] = v.clone();
            }
            a
        })
        .collect();
    let code = format!(
        "import json,sys\ni=json.load(sys.stdin)\na={}\nprint(json.dumps({{'actions': a if i['event_type_id']=='libp2p_connected' else []}}))",
        serde_json::to_string(&actions).unwrap()
    );
    vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}})]
}

fn find<'a>(events: &'a [Value], cid: &str) -> &'a Value {
    events
        .iter()
        .find(|e| e["cid"] == cid)
        .unwrap_or_else(|| panic!("no ipfs_fetched for {cid}: {events:?}"))
}

/// A listing's (name, kind, size), in order.
fn listing(e: &Value) -> Vec<(String, String, Option<u64>)> {
    e["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["name"].as_str().unwrap().to_string(),
                x["kind"].as_str().unwrap_or("?").to_string(),
                x["size"].as_u64(),
            )
        })
        .collect()
}

fn expected_listing() -> Vec<(String, String, Option<u64>)> {
    [
        ("a.txt", "file", Some(23)),
        ("big.bin", "file", Some(700_000)),
        ("empty.txt", "file", Some(0)),
        ("emptydir", "directory", None),
        ("link", "symlink", Some(5)),
        ("sub", "directory", None),
        ("ünïcode name.txt", "file", Some(16)),
    ]
    .into_iter()
    .map(|(n, k, s)| (n.to_string(), k.to_string(), s))
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_fetches_trees_and_files_kubo_added() {
    let kubo = Kubo::start("none").await;
    let (_, disk) = tree();
    let site = kubo.path().join("site");
    write_tree(&site, &disk);
    let site = site.to_string_lossy().to_string();
    let v0 = text(kubo.ok(&["add", "-Q", "-r", &site]).await);
    let v1 = text(
        kubo.ok(&["add", "-Q", "-r", "--cid-version=1", &site])
            .await,
    );
    let big = noise(5, 2_200_000);
    let big_cid = text(kubo.ok(&["add", "-Q", &kubo.file("big.bin", &big)]).await);
    let deep = noise(6, 7168);
    let deep_cid = text(
        kubo.ok(&[
            "add",
            "-Q",
            "--cid-version=1",
            "--chunker=size-256",
            "--max-file-links=3",
            &kubo.file("deep.bin", &deep),
        ])
        .await,
    );
    let link_cid = text(
        kubo.ok(&["resolve", "-r", &format!("/ipfs/{v0}/link")])
            .await,
    )
    .trim_start_matches("/ipfs/")
    .to_string();
    let missing = Cid::v1(ipfs::RAW, b"nobody added this").to_string();

    let (state, id, mut rx) = client(
        &kubo.swarm_addr,
        fetch_all(&[
            (&v0, json!({})),
            (&v1, json!({})),
            (&big_cid, json!({"max_bytes": 100})),
            (&deep_cid, json!({})),
            (&link_cid, json!({})),
            (&missing, json!({"timeout_secs": 30})),
        ]),
    )
    .await;
    let events = wait_fetched(&state, id, 6, &mut rx).await;
    let log = drain(&mut rx);

    for root in [&v0, &v1] {
        let e = find(&events, root);
        assert_eq!(
            (e["ok"].as_bool(), e["kind"].as_str()),
            (Some(true), Some("directory")),
            "{e}"
        );
        assert_eq!(listing(e), expected_listing(), "{e}");
    }
    let b = find(&events, &big_cid);
    assert_eq!(b["ok"], true, "{b}");
    assert_eq!(b["size"], 2_200_000);
    assert_eq!(
        b["sha256"],
        sha(&big),
        "the whole file, every block verified"
    );
    assert_eq!(
        (b["encoding"].as_str(), b["truncated"].as_bool()),
        (Some("hex"), Some(true))
    );
    assert_eq!(b["data"], hex::encode(&big[..100]));
    assert_eq!(
        (b["blocks"].as_u64(), b["depth"].as_u64()),
        (Some(10), Some(1)),
        "{b}"
    );
    let d = find(&events, &deep_cid);
    assert_eq!(d["data"], hex::encode(&deep), "{d}");
    assert_eq!(d["depth"], 4, "{d}");
    let l = find(&events, &link_cid);
    assert_eq!(
        (l["kind"].as_str(), l["target"].as_str()),
        (Some("symlink"), Some("a.txt"))
    );
    let m = find(&events, &missing);
    assert_eq!(m["ok"], false, "{m}");
    assert!(
        m["error"].as_str().unwrap().contains("does not have"),
        "{m}"
    );

    // What passed, by NetGet's count and by Kubo's.
    for l in log.lines().filter(|l| l.contains("operation=ipfs_fetch")) {
        println!("NetGet: {l}");
    }
    println!(
        "Kubo bitswap stat:\n{}",
        text(kubo.ok(&["bitswap", "stat"]).await)
    );
    let peers = kubo.swarm_peers().await;
    assert_eq!(peers.len(), 1, "Kubo spoke to NetGet alone: {peers:?}");
    let netget = peers[0].rsplit('/').next().unwrap();
    println!(
        "Kubo bitswap ledger for NetGet:\n{}",
        text(kubo.ok(&["bitswap", "ledger", netget]).await)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_fetches_a_tree_helia_serves() {
    let dir = tempfile::Builder::new()
        .prefix("netget-helia-")
        .tempdir()
        .unwrap();
    let (_, disk) = tree();
    // The importer takes files and directories only.
    let disk: Vec<_> = disk.into_iter().filter(|(p, _, _)| p != "link").collect();
    let site = dir.path().join("site");
    write_tree(&site, &disk);
    let helia =
        crate::helpers::helia::Serving::start(&site.to_string_lossy(), &["--cid-version=1"]).await;
    // Fetch the root; then, from its listing, the big file.
    let code = format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='libp2p_connected':
  a=[{{'type':'ipfs_fetch','cid':'{root}'}}]
elif t=='ipfs_fetched' and e.get('kind')=='directory':
  a=[{{'type':'ipfs_fetch','cid':x['cid'],'max_bytes':16}} for x in e['entries'] if x['name'] in ('big.bin','sub')]
print(json.dumps({{'actions':a}}))"#,
        root = helia.cid
    );
    let (state, id, mut rx) = client(
        &helia.addr,
        vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}})],
    )
    .await;
    let events = wait_fetched(&state, id, 3, &mut rx).await;
    let root = find(&events, &helia.cid);
    let expected: Vec<_> = expected_listing()
        .into_iter()
        .filter(|(n, _, _)| n != "link")
        .collect();
    assert_eq!(listing(root), expected, "{root}");
    let big_cid = root["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "big.bin")
        .unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();
    let big = find(&events, &big_cid);
    assert_eq!(big["sha256"], sha(&noise(42, 700_000)), "{big}");
    assert_eq!(big["data"], hex::encode(noise(42, 16)));
    let sub = events
        .iter()
        .find(|e| e["kind"] == "directory" && e["cid"] != helia.cid.as_str())
        .unwrap();
    assert_eq!(
        listing(sub),
        vec![
            ("deeper".to_string(), "directory".to_string(), None),
            ("nested.txt".to_string(), "file".to_string(), Some(7)),
        ]
    );
    for l in drain(&mut rx)
        .lines()
        .filter(|l| l.contains("operation=ipfs_fetch"))
    {
        println!("NetGet: {l}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_block_never_completes_a_fetch() {
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
    let fetch = |cid: String| {
        let state = state.clone();
        async move {
            state
                .send_to_client(
                    id,
                    json!({"type": "ipfs_fetch", "cid": cid, "timeout_secs": 8}),
                    Duration::from_secs(30),
                )
                .await
                .unwrap()
        }
    };
    // The block it has: fetched and verified.
    let good_cid = Cid::v1(ipfs::RAW, good.as_bytes()).to_string();
    let outcome = fetch(good_cid.clone()).await;
    let ClientSendOutcome::Executed { detail } = &outcome else {
        panic!("{outcome:?}")
    };
    let r: Value = serde_json::from_str(detail).unwrap();
    assert_eq!(
        (r["ok"].as_bool(), r["data"].as_str()),
        (Some(true), Some(good)),
        "{r}"
    );
    // A block it lies about: the tampered bytes hash to another CID, so the walk never gets
    // the block it asked for and gives up.
    let bad_cid = Cid::v1(ipfs::RAW, b"bytes the liar does not have").to_string();
    let outcome = fetch(bad_cid).await;
    let ClientSendOutcome::Executed { detail } = &outcome else {
        panic!("{outcome:?}")
    };
    let r: Value = serde_json::from_str(detail).unwrap();
    assert_eq!(r["ok"], false, "{r}");
    assert!(
        r["error"].as_str().unwrap().contains("longer than 8s"),
        "{r}"
    );
    let log = drain(&mut rx);
    assert!(log.contains("decision=refused_block"), "{log}");
    // A fetch the model gives badly is refused before anything is sent.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "ipfs_fetch", "cid": good_cid, "max_bytes": 1 << 30}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("max_bytes")),
        "{outcome:?}"
    );
    drop(liar);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_reads_an_ipns_record_from_kubos_dht() {
    let kubo = Kubo::start("dhtserver").await;
    let target = "/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn";
    kubo.ok(&[
        "name",
        "publish",
        "--resolve=false",
        "--allow-offline",
        "--timeout=60s",
        target,
    ])
    .await;
    let (state, id, _rx) = client(
        &kubo.swarm_addr,
        vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})],
    )
    .await;
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "ipfs_kad_get_value", "name": kubo.peer_id,
                   "protocol": "/ipfs/lan/kad/1.0.0"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let ClientSendOutcome::Executed { detail } = &outcome else {
        panic!("{outcome:?}")
    };
    let r: Value = serde_json::from_str(detail).unwrap();
    let rec = &r["record"];
    assert_eq!(rec["valid"], true, "{r}");
    assert_eq!(rec["value"], target, "{r}");
    assert_eq!(rec["name"], kubo.peer_id.as_str(), "{r}");
    // A name that is not a peer id is refused before anything is sent.
    let outcome = state
        .send_to_client(
            id,
            json!({"type": "ipfs_kad_get_value", "name": "not-a-name"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { .. }),
        "{outcome:?}"
    );
}
