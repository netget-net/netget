//! NetGet's Stratum V2 mining device against **SRI's `pool_sv2`** (sv2-apps v0.8.0) building
//! its work from **Bitcoin Core 31.0** in regtest over the node's IPC socket. NetGet pins SRI's
//! authority key, sets up the connection, opens a standard channel, and the handler mines each
//! job; the pool verifies every share with its own code and, because on regtest every share
//! below the network target is a block, submits it to Bitcoin Core. The test asserts that the
//! block Bitcoin Core accepted has the exact hash NetGet computed for its share — which only
//! happens when NetGet and both peers agree on every header byte — and that a key the pool's
//! certificate was not signed with is refused before anything is sent.
//! `tests/server/stratum_v2/install_peers.py` prints `NETGET_SV2_POOL`,
//! `NETGET_SV2_BITCOIN_NODE` and `NETGET_SV2_BITCOIN_CLI`; the test fails rather than skips
//! without them. No LLM calls: a python chain is the model.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

/// SRI's example authority pair; the pool is configured with both halves.
const SRI_SECRET: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const SRI_PUBLIC: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

/// Every job is mined until a share meets the channel's target.
const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[{'type':'stratum_v2_mine','max_hashes':20000000}] if t=='stratum_v2_job' else []
print(json.dumps({'actions':a}))"#;

fn env(var: &str) -> String {
    let v = std::env::var(var).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{var} is required: python3 tests/server/stratum_v2/install_peers.py <dir> and export what it prints"
    );
    v
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    _node: tokio::process::Child,
    _pool: tokio::process::Child,
    dir: PathBuf,
    rpc: u16,
    pool_port: u16,
    pool_log: PathBuf,
    _tmp: tempfile::TempDir,
}

async fn cli(dir: &Path, rpc: u16, args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new(env("NETGET_SV2_BITCOIN_CLI"))
        .arg("-regtest")
        .arg(format!("-datadir={}", dir.display()))
        .args(["-rpcuser=netget", "-rpcpassword=netget"])
        .arg(format!("-rpcport={rpc}"))
        .args(args)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}

/// bitcoin-node in regtest with its IPC socket, and SRI's pool taking templates from it.
async fn node() -> Node {
    // The node's IPC socket path must fit a sockaddr_un.
    let tmp = tempfile::Builder::new()
        .prefix("sv2")
        .tempdir_in("/tmp")
        .unwrap();
    let dir = tmp.path().join("btc");
    std::fs::create_dir_all(&dir).unwrap();
    let (rpc, p2p, pool_port) = (free_port(), free_port(), free_port());
    let node = tokio::process::Command::new(env("NETGET_SV2_BITCOIN_NODE"))
        .arg("-regtest")
        .arg(format!("-datadir={}", dir.display()))
        .args([
            "-ipcbind=unix",
            "-server",
            "-listen=0",
            "-rpcuser=netget",
            "-rpcpassword=netget",
            "-printtoconsole=0",
        ])
        .arg(format!("-rpcport={rpc}"))
        .arg(format!("-port={p2p}"))
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("bitcoin-node");
    tokio::time::timeout(Duration::from_secs(60), async {
        while cli(&dir, rpc, &["getblockchaininfo"]).await.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("bitcoin-node never answered RPC");
    // Out of initial block download, which the IPC template interface waits for.
    cli(&dir, rpc, &["generatetodescriptor", "16", "raw(51)"])
        .await
        .unwrap();
    let sock = dir.join("regtest").join("node.sock");
    tokio::time::timeout(Duration::from_secs(30), async {
        while !sock.exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("bitcoin-node never created its IPC socket");

    let conf = tmp.path().join("pool.toml");
    std::fs::write(
        &conf,
        format!(
            r#"authority_public_key = "{SRI_PUBLIC}"
authority_secret_key = "{SRI_SECRET}"
cert_validity_sec = 3600
listen_address = "127.0.0.1:{pool_port}"
coinbase_reward_script = "raw(51)"
server_id = 1
pool_signature = "SRI Pool for NetGet"
shares_per_minute = 60.0
share_batch_size = 1

[template_provider_type.BitcoinCoreIpc]
version = 31
network = "regtest"
data_dir = "{}"
fee_threshold = 0
min_interval = 5
"#,
            dir.display()
        ),
    )
    .unwrap();
    let pool_log = tmp.path().join("pool.out");
    let out = std::fs::File::create(&pool_log).unwrap();
    let pool = tokio::process::Command::new(env("NETGET_SV2_POOL"))
        .arg("-c")
        .arg(&conf)
        .current_dir(tmp.path())
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .kill_on_drop(true)
        .spawn()
        .expect("pool_sv2");
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let log = std::fs::read_to_string(&pool_log).unwrap_or_default();
            if log.contains("ready to accept connections")
                && tokio::net::TcpStream::connect(("127.0.0.1", pool_port))
                    .await
                    .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "pool_sv2 never came up:\n{}",
            std::fs::read_to_string(&pool_log).unwrap_or_default()
        )
    });
    Node {
        _node: node,
        _pool: pool,
        dir,
        rpc,
        pool_port,
        pool_log,
        _tmp: tmp,
    }
}

async fn wait_event(state: &AppState, id: ClientId, pred: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| pred(e))
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no matching event")
}

fn client(port: u16, key: &str, handlers: Value) -> ClientForm {
    ClientForm {
        protocol: "stratum_v2".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Mine every job".into()),
        startup_params: Some(
            json!({"authority_public_key": key, "user_identity": "netget.miner",
                                    "nominal_hash_rate": 100000}),
        ),
        event_handlers: Some(vec![handlers]),
        ..Default::default()
    }
}

#[tokio::test]
async fn netget_mines_blocks_on_sri_pool_work() {
    let node = node().await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = client(
        node.pool_port,
        SRI_PUBLIC,
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
    )
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect");

    let channel = wait_event(&state, id, |e| e["event_type"] == "stratum_v2_channel").await;
    assert_eq!(
        channel["ok"], true,
        "the pool refused the channel: {channel}"
    );
    assert_eq!(channel["channel_kind"], "standard");
    let job = wait_event(&state, id, |e| e["event_type"] == "stratum_v2_job").await;
    assert_eq!(job["nbits"], "207fffff", "regtest work: {job}");
    // The job's prev hash is a block the node has.
    cli(
        &node.dir,
        node.rpc,
        &["getblockheader", job["prev_hash"].as_str().unwrap()],
    )
    .await
    .unwrap_or_else(|e| panic!("the pool's prev hash is not a block the node knows: {e}"));

    // The handler mined and submitted; the pool credited it.
    let share = wait_event(&state, id, |e| {
        e["event_type"] == "stratum_v2_share_result" && e["request"]["accepted"] == true
    })
    .await;
    let hash = share["hash"].as_str().unwrap().to_string();
    assert_eq!(share["new_submits_accepted_count"], 1, "{share}");
    // On regtest the share was a block: Bitcoin Core has it, by the hash NetGet computed.
    let header = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(h) = cli(&node.dir, node.rpc, &["getblockheader", &hash]).await {
                return h;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "Bitcoin Core has no block {hash}; pool log:\n{}",
            std::fs::read_to_string(&node.pool_log).unwrap_or_default()
        )
    });
    let header: Value = serde_json::from_str(&header).unwrap();
    assert!(header["confirmations"].as_i64().unwrap() >= 1, "{header}");
    assert!(header["height"].as_u64().unwrap() > 16, "{header}");

    // By hand: nonce 0 on the active job almost certainly misses the target; the pool says why.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"stratum_v2_submit","nonce":0}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let ClientSendOutcome::Executed { detail } = outcome else {
        panic!("{outcome:?}");
    };
    let detail: Value = serde_json::from_str(&detail).unwrap();
    if detail["accepted"] == false {
        assert!(
            !detail["error_code"].as_str().unwrap().is_empty(),
            "{detail}"
        );
    }

    // Refused before the wire: a job that does not exist.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"stratum_v2_submit","job_id":999999,"nonce":1}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("no such job")),
        "{outcome:?}"
    );

    // A key the pool's certificate was not signed with: no connection at all.
    let (tx, _) = mpsc::unbounded_channel();
    let err = client(
        node.pool_port,
        "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh",
        json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
    )
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect_err("NetGet accepted a pool its pinned key did not certify");
    assert!(format!("{err:#}").contains("not signed"), "{err:#}");
}
