//! Multi-block files, directories and remembered wants, served by NetGet's libp2p host from
//! descriptions (`ipfs_content`, `ipfs_add`), against **Kubo 0.43.1** (`NETGET_KUBO`),
//! **Helia** (`NETGET_HELIA`) and the go-libp2p peer (`NETGET_LIBP2P_GO_PEER`), all installed
//! by `install_peers.py`. Each fails rather than skips when absent.
//!
//! Every root CID NetGet builds is first checked against `ipfs add --only-hash` on the same
//! bytes, so Kubo has nowhere to get a block from but NetGet; then Kubo's `ls`, `cat`, `get`,
//! `dag get` and `refs -r`, and Helia's `ls`/`cat`, read the content back over Bitswap and
//! verify every block themselves. The model is unreachable in these tests: what the store
//! holds costs no model call, and anything that reached the model would show as
//! `fail_closed_llm_error`.
//!
//! No pcap oracle: the streams are Noise-encrypted, so tshark sees only ciphertext.
use super::unixfs_test::kubo_hash;
use crate::helpers::helia;
use crate::helpers::ipfs_fixtures::{noise, tree, write_tree};
use crate::helpers::kubo::Kubo;
use netget::cli::management::ServerForm;
use netget::server::libp2p::bitswap::{self, Entry, Message, Version, WantType};
use netget::server::libp2p::ipfs::{self, Cid};
use netget::server::libp2p::{unixfs, wire};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::sync::mpsc;

const SEED: &str = "netget-dag-test";

fn peer_id() -> String {
    netget::server::libp2p::identity_from_params(Some(SEED.into()))
        .unwrap()
        .peer_id_string()
}

pub struct Host {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub rx: mpsc::UnboundedReceiver<String>,
    pub log: String,
}

impl Host {
    pub fn addr(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", self.port, peer_id())
    }
    /// Everything logged so far (kept, so a later look still sees it).
    pub fn drain(&mut self) -> &str {
        while let Ok(l) = self.rx.try_recv() {
            self.log.push_str(&l);
            self.log.push('\n');
        }
        &self.log
    }
    pub async fn wait_for(&mut self, needle: &str) -> String {
        let found = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if self.drain().contains(needle) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(found.is_ok(), "never logged {needle:?}:\n{}", self.log);
        self.log.clone()
    }
    pub async fn events(&self, event_type: &str) -> Vec<Value> {
        self.state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == event_type)
            .map(|e| e["request"].clone())
            .collect()
    }
    /// The one connection's id, once it exists.
    pub async fn connection(&self) -> u32 {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(s) = self.state.get_server(self.id).await {
                    if let Some(c) = s.connections.keys().next() {
                        return c.as_u32();
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("no connection")
    }
    /// Inject an action on a connection as the dashboard would.
    pub async fn inject(&self, conn: u32, action: Value) -> String {
        let outcome = self
            .state
            .send_to_peer(self.id, conn, action, Duration::from_secs(60))
            .await
            .unwrap();
        format!("{outcome:?}")
    }
}

/// NetGet with ipfs on, serving `content`, and `handlers` as its model (None: an unreachable
/// model, so anything asked fails closed).
pub async fn start(content: Value, handlers: Option<Vec<Value>>) -> Host {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "libp2p".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Serve IPFS content".into()),
        startup_params: Some(
            json!({"private_key_seed": SEED, "ipfs": true, "ipfs_content": content}),
        ),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    Host {
        state,
        id,
        port,
        rx,
        log: String::new(),
    }
}

/// The roots NetGet logged as added, in order.
fn added_roots(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.contains("operation=ipfs_add decision=added"))
        .filter_map(|l| l.split("root=").nth(1))
        .filter_map(|r| r.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn text(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap().trim().to_string()
}

fn sha(b: &[u8]) -> String {
    hex::encode(ipfs::sha256(b))
}

/// Print and return NetGet's per-connection Bitswap ledger lines.
fn ledgers(log: &str) -> Vec<String> {
    let lines: Vec<String> = log
        .lines()
        .filter(|l| l.contains("operation=bitswap_ledger"))
        .map(str::to_string)
        .collect();
    for l in &lines {
        println!("NetGet ledger: {l}");
    }
    lines
}

fn sparse() -> (Value, Vec<u8>) {
    let mut bytes = vec![0u8; 3_000_000];
    bytes[1_500_000..1_500_010].copy_from_slice(b"middle!!!!");
    (
        json!({"name": "sparse.bin", "size": 3_000_000, "extents": [
            {"offset": 1_500_000, "text": "middle!!!!"}
        ]}),
        bytes,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kubo_reads_trees_and_large_files_from_descriptions() {
    let (site, disk) = tree();
    let mut site_v1 = site.clone();
    site_v1["cid_version"] = json!(1);
    let (sparse_desc, sparse_bytes) = sparse();
    let deep_bytes = noise(7, 7168);
    let deep = json!({"name": "deep.bin", "hex": hex::encode(&deep_bytes),
                      "chunk_size": 256, "max_links": 3});
    let mut host = start(json!([site, site_v1, sparse_desc, deep]), None).await;
    let roots = added_roots(host.drain());
    assert_eq!(roots.len(), 4, "{}", host.log);

    let kubo = Kubo::start("none").await;
    let local = kubo.path().join("site");
    write_tree(&local, &disk);
    let local = local.to_string_lossy().to_string();
    // Kubo's importer, on the same bytes, names the same roots: nothing is stored, so the
    // blocks can only come from NetGet.
    let expect = [
        kubo_hash(&kubo, &[], &local, true).await,
        kubo_hash(&kubo, &["--cid-version=1"], &local, true).await,
        kubo_hash(&kubo, &[], &kubo.file("sparse.bin", &sparse_bytes), false).await,
        kubo_hash(
            &kubo,
            &["--chunker=size-256", "--max-file-links=3"],
            &kubo.file("deep.bin", &deep_bytes),
            false,
        )
        .await,
    ];
    assert_eq!(roots, expect, "NetGet and Kubo disagree about a root");
    let (v0, v1, sparse_root, deep_root) = (&roots[0], &roots[1], &roots[2], &roots[3]);

    kubo.ok(&["swarm", "connect", &host.addr()]).await;

    // ipfs ls: the root's entries, with Kubo's own view of their kind and size.
    let ls = text(kubo.ok(&["ls", "--timeout=60s", v0]).await);
    // Each line is `<cid> <size> <name>`, padded; a name may hold spaces.
    let listed: Vec<(String, String)> = ls
        .lines()
        .map(|l| {
            let rest = l.split_once(' ').unwrap().1.trim_start();
            let (size, name) = rest.split_once(' ').unwrap();
            (
                size.to_string(),
                name.trim().trim_end_matches('/').to_string(),
            )
        })
        .collect();
    let names: Vec<&str> = listed.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "a.txt",
            "big.bin",
            "empty.txt",
            "emptydir",
            "link",
            "sub",
            "ünïcode name.txt"
        ],
        "{ls}"
    );
    assert!(
        listed.contains(&("700000".into(), "big.bin".into())),
        "{ls}"
    );

    // ipfs cat through a path, and of the multi-block files.
    assert_eq!(
        kubo.ok(&["cat", "--timeout=60s", &format!("{v0}/sub/deeper/z")])
            .await,
        b"z"
    );
    let big = kubo
        .ok(&["cat", "--timeout=60s", &format!("{v1}/big.bin")])
        .await;
    assert_eq!(sha(&big), sha(&noise(42, 700_000)));
    let s = kubo.ok(&["cat", "--timeout=60s", sparse_root]).await;
    assert_eq!(
        sha(&s),
        sha(&sparse_bytes),
        "the 3 MB file of repeated leaves"
    );
    assert_eq!(
        kubo.ok(&["cat", "--timeout=60s", deep_root]).await,
        deep_bytes,
        "the depth-4 file"
    );

    // ipfs get: the whole tree, files, empty directory and symlink, byte for byte.
    for root in [v0, v1] {
        let out = kubo.path().join(format!("got-{root}"));
        kubo.ok(&["get", "--timeout=60s", "-o", &out.to_string_lossy(), root])
            .await;
        for (path, content, target) in &disk {
            let p = out.join(path);
            match (content, target) {
                (Some(c), _) => assert_eq!(&std::fs::read(&p).unwrap(), c, "{path}"),
                (None, Some(t)) => {
                    assert_eq!(std::fs::read_link(&p).unwrap().to_string_lossy(), *t)
                }
                (None, None) => assert!(p.is_dir(), "{path}"),
            }
        }
    }

    // ipfs dag get: the directory node as Kubo decoded it — names and Tsizes as NetGet
    // wrote them.
    let dag: Value =
        serde_json::from_slice(&kubo.ok(&["dag", "get", "--timeout=60s", v0]).await).unwrap();
    let built = unixfs::add(&tree().0).unwrap();
    let root_bytes = built
        .blocks
        .iter()
        .find(|(c, _)| c.to_string() == *v0)
        .unwrap()
        .1
        .bytes();
    let node = ipfs::decode_pb_node(&root_bytes).unwrap();
    let links = dag["Links"].as_array().unwrap();
    assert_eq!(links.len(), node.links.len());
    for (k, n) in links.iter().zip(&node.links) {
        assert_eq!(k["Name"], n.name.as_str());
        assert_eq!(k["Tsize"], n.size);
        assert_eq!(k["Hash"]["/"], n.cid.to_string());
    }

    // ipfs refs -r: every block under the root, which is every block NetGet built for it.
    let refs: BTreeSet<String> = text(
        kubo.ok(&["refs", "-r", "--unique", "--timeout=60s", v0])
            .await,
    )
    .lines()
    .map(str::to_string)
    .collect();
    let ours: BTreeSet<String> = built
        .blocks
        .iter()
        .map(|(c, _)| c.to_string())
        .filter(|c| c != v0)
        .collect();
    assert_eq!(refs, ours);
    println!(
        "Kubo read {} blocks under {v0} and they are NetGet's {}",
        refs.len() + 1,
        ours.len() + 1
    );

    // Kubo's own account, then NetGet's, of what passed.
    println!(
        "Kubo bitswap stat:\n{}",
        text(kubo.ok(&["bitswap", "stat"]).await)
    );
    println!(
        "Kubo bitswap ledger for NetGet:\n{}",
        text(kubo.ok(&["bitswap", "ledger", &peer_id()]).await)
    );
    kubo.ok(&["swarm", "disconnect", &host.addr()]).await;
    let log = host.wait_for("operation=bitswap_ledger").await;
    let ledger = ledgers(&log).join("\n");
    assert!(ledger.contains("sent messages="), "{ledger}");

    // Not one want reached the model, which could not have answered: the store did it all.
    // (The control: the connect event did go to it, and failed closed.)
    assert!(
        log.contains("operation=libp2p_peer_connected decision=fail_closed_llm_error"),
        "{log}"
    );
    assert!(host.events("ipfs_bitswap_want").await.is_empty());
    assert!(
        !log.contains("operation=ipfs_bitswap_want decision=fail_closed"),
        "{log}"
    );
    assert!(log.contains("from_store="), "{log}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn helia_reads_trees_from_descriptions() {
    let (site, disk) = tree();
    let mut site_v1 = site.clone();
    site_v1["cid_version"] = json!(1);
    let (sparse_desc, sparse_bytes) = sparse();
    let mut host = start(json!([site, site_v1, sparse_desc]), None).await;
    let roots = added_roots(host.drain());
    for root in &roots[..2] {
        let (lines, out) = helia::run(&["get", &host.addr(), root]).await;
        let got = helia::step(&lines, "get", &out);
        let entries = got["entries"].as_array().unwrap();
        for (path, content, _) in disk.iter().filter(|(p, _, _)| p != "link") {
            let e = entries
                .iter()
                .find(|e| e["path"] == path.as_str())
                .unwrap_or_else(|| panic!("Helia did not list {path}: {got}"));
            if let Some(c) = content {
                assert_eq!(e["sha256"], sha(c), "{path}");
                assert_eq!(e["size"], c.len(), "{path}");
            } else {
                assert_eq!(e["type"], "directory", "{path}");
            }
        }
        let link = entries.iter().find(|e| e["path"] == "link").unwrap();
        assert_eq!(link["type"], "symlink", "{got}");
    }
    let (lines, out) = helia::run(&["cat", &host.addr(), &roots[2]]).await;
    let cat = helia::step(&lines, "cat", &out);
    assert_eq!(cat["sha256"], sha(&sparse_bytes), "{cat}");
    let log = host.wait_for("operation=bitswap_ledger").await;
    let ledger = ledgers(&log);
    assert_eq!(ledger.len(), 3, "one ledger per Helia connection");
    assert!(host.events("ipfs_bitswap_want").await.is_empty());
    assert!(
        !log.contains("operation=ipfs_bitswap_want decision=fail_closed"),
        "{log}"
    );
}

// ---------------------------------------------------------------------------------------
// Remembered wants, over go-libp2p: bytes written by hand.

fn want(cid: Cid, want_type: WantType) -> Entry {
    Entry {
        cid,
        priority: 1,
        cancel: false,
        want_type,
        send_dont_have: true,
    }
}

fn message(entries: Vec<Entry>) -> Vec<u8> {
    wire::length_prefixed(&bitswap::encode(
        &Message {
            entries,
            ..Default::default()
        },
        Version::V120,
    ))
}

/// The model answers every wantlist with nothing (it declines).
fn declines() -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_want_is_remembered_until_content_arrives_and_forgotten_on_cancel() {
    let mut host = start(json!([]), declines()).await;
    let alpha = Cid::v1(ipfs::RAW, b"alpha");
    let gamma = Cid::v1(ipfs::RAW, b"gamma");
    let beta_text: String = "beta ".repeat(600);
    let beta = Cid {
        version: 0,
        ..Cid::v1(ipfs::DAG_PB, &ipfs::unixfs_file_block(beta_text.as_bytes()))
    };
    // One stream, two messages: want alpha (block), beta (have) and gamma (block); then
    // cancel gamma.
    let mut bytes = message(vec![
        want(alpha, WantType::Block),
        want(beta, WantType::Have),
        want(gamma, WantType::Block),
    ]);
    bytes.extend(message(vec![Entry {
        cancel: true,
        ..want(gamma, WantType::Block)
    }]));
    let addr = host.addr();
    let go = tokio::spawn(async move {
        tokio::process::Command::new(super::real_client_test::peer())
            .args([
                "raw",
                &addr,
                bitswap::BITSWAP_120,
                &hex::encode(&bytes),
                "3",
            ])
            .kill_on_drop(true)
            .output()
            .await
            .unwrap()
    });
    host.wait_for("cancel=1").await;
    let conn = host.connection().await;
    assert_eq!(
        host.events("ipfs_bitswap_want").await.len(),
        1,
        "asked once"
    );
    // The model adds alpha and gamma (raw leaves, CIDv1), then beta (CIDv0, 3000 bytes:
    // too big to answer a want-have with, so HAVE).
    let added = host
        .inject(
            conn,
            json!({"type": "ipfs_add", "cid_version": 1, "entries": [
                {"name": "a", "text": "alpha"}, {"name": "g", "text": "gamma"}]}),
        )
        .await;
    assert!(added.contains("decision=added"), "{added}");
    host.wait_for("source=tracked blocks=1 have=0").await;
    host.inject(conn, json!({"type": "ipfs_add", "text": beta_text}))
        .await;
    host.wait_for("source=tracked blocks=0 have=1").await;
    let out = go.await.unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let inbound: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|s| s["step"] == "bitswap_in")
        .collect();
    assert_eq!(inbound.len(), 3, "{text}");
    // First: DONT_HAVE for all three, as the model declined.
    let first: BTreeSet<String> = inbound[0]["presences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            format!(
                "{} {}",
                p["type"].as_str().unwrap(),
                p["cid"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        first,
        [alpha, beta, gamma]
            .iter()
            .map(|c| format!("dont_have {c}"))
            .collect(),
        "{text}"
    );
    // Then alpha's block (go-cid recomputed its CID) — and never gamma's, which was cancelled.
    assert_eq!(
        inbound[1]["blocks"],
        json!([{"cid": alpha.to_string(), "data": "alpha"}]),
        "{text}"
    );
    assert_eq!(
        inbound[2]["presences"],
        json!([{"cid": beta.to_string(), "type": "have"}]),
        "{text}"
    );
    assert!(
        !text.contains(&format!("\"cid\":\"{gamma}\",\"data\"")),
        "{text}"
    );
    println!("go-libp2p received: {inbound:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kubo_cat_completes_when_the_model_adds_the_content_later() {
    let mut host = start(json!([]), declines()).await;
    let kubo = Kubo::start("none").await;
    let bytes = noise(9, 600_000);
    let cid = kubo_hash(&kubo, &[], &kubo.file("later.bin", &bytes), false).await;
    kubo.ok(&["swarm", "connect", &host.addr()]).await;
    let conn = host.connection().await;
    // Kubo asks; the model has nothing yet.
    let cat = {
        let repo = kubo.path().to_path_buf();
        let cid = cid.clone();
        tokio::spawn(async move {
            tokio::process::Command::new(crate::helpers::kubo::kubo_bin())
                .args(["cat", "--timeout=90s", &cid])
                .env("IPFS_PATH", repo)
                .env("IPFS_TELEMETRY", "off")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap()
        })
    };
    let asked = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let wants = host.events("ipfs_bitswap_want").await;
            if wants
                .iter()
                .flat_map(|w| w["wants"].as_array().unwrap().clone())
                .any(|w| w["cid"] == cid.as_str())
            {
                return wants;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Kubo's want never reached the model\n{}", kubo.log()));
    println!("Kubo's want reached the model: {asked:?}");
    // Now the model adds it, and the want Kubo is still holding is answered.
    let added = host
        .inject(
            conn,
            json!({"type": "ipfs_add", "hex": hex::encode(&bytes)}),
        )
        .await;
    assert!(added.contains(&cid), "{added}");
    let out = cat.await.unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        host.drain()
    );
    assert_eq!(sha(&out.stdout), sha(&bytes));
    let log = host.drain().to_string();
    assert!(log.contains("source=tracked"), "{log}");
    // The model was asked about the root once; the leaves came from the store.
    let asked_cids: Vec<String> = host
        .events("ipfs_bitswap_want")
        .await
        .iter()
        .flat_map(|w| w["wants"].as_array().unwrap().clone())
        .map(|w| w["cid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        asked_cids.iter().filter(|c| **c == cid).count(),
        1,
        "{asked_cids:?}"
    );
    println!(
        "Kubo bitswap ledger for NetGet:\n{}",
        text(kubo.ok(&["bitswap", "ledger", &peer_id()]).await)
    );
    kubo.ok(&["swarm", "disconnect", &host.addr()]).await;
    ledgers(&host.wait_for("operation=bitswap_ledger").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kubo_finds_described_content_through_netgets_dht_without_the_model() {
    let site = tree().0;
    let mut host = start(json!([site]), None).await;
    let root = added_roots(host.drain())[0].clone();
    let kubo = Kubo::start("dhtclient").await;
    kubo.ok(&["swarm", "connect", &host.addr()]).await;
    let found = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let r = kubo
                .ipfs(&["routing", "findprovs", "--timeout=10s", "-n", "1", &root])
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
    let log = host.drain().to_string();
    assert!(log.contains("request=GET_PROVIDERS source=store"), "{log}");
    assert!(host
        .events("ipfs_kad_request")
        .await
        .iter()
        .all(|r| r["request"] != "GET_PROVIDERS"));
}

#[test]
fn an_add_is_refused_whole_when_it_breaks_a_bound() {
    // Too many roots for one host.
    let mut store = unixfs::Store::default();
    for i in 0..unixfs::MAX_STORE_ROOTS {
        store
            .insert(unixfs::add(&json!({"text": format!("{i}")})).unwrap())
            .unwrap();
    }
    assert!(store
        .insert(unixfs::add(&json!({"text": "one more"})).unwrap())
        .is_err());
    assert_eq!(store.roots().len(), unixfs::MAX_STORE_ROOTS);
}
