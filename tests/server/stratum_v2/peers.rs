//! Real peers for the Template Distribution and Job Declaration tests: Bitcoin Core 31.0 in
//! regtest, SRI's pool_sv2, mining_device and jd_client_sv2 (sv2-apps v0.8.0), each in a temp
//! dir of its own with its own ports, logging to a file the test prints when it fails.
//! `install_peers.py` prints the paths; every helper fails, naming the variable, without them.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// SRI's example authority pair: every SRI peer and NetGet's servers use it.
pub const SECRET: &str = super::support::SECRET;
pub const PUBLIC: &str = super::support::PUBLIC;

pub fn env(var: &str) -> String {
    let v = std::env::var(var).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{var} is required: python3 tests/server/stratum_v2/install_peers.py <dir> and export what it prints"
    );
    v
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A log line without terminal colours.
pub fn plain(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn read(path: &Path) -> String {
    plain(&std::fs::read_to_string(path).unwrap_or_default())
}

/// Wait until `path` contains `needle`; false on timeout.
pub async fn wait_log(path: &Path, needle: &str, secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !read(path).contains(needle) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .is_ok()
}

/// A process whose stdout and stderr go to `log`, killed when dropped.
pub fn spawn(bin: &str, args: &[String], cwd: &Path, log: &Path) -> tokio::process::Child {
    let out = std::fs::File::create(log).unwrap();
    tokio::process::Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "info")
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("{bin}: {e}"))
}

/// bitcoin-node in regtest, in a temp dir short enough for its IPC socket path.
pub struct Regtest {
    _node: tokio::process::Child,
    pub dir: PathBuf,
    pub rpc: u16,
    pub tmp: tempfile::TempDir,
}

impl Regtest {
    /// Start the node and mine `blocks` blocks paying `OP_TRUE`, so the first coinbases are
    /// spendable with an empty scriptSig once 100 deep.
    pub async fn start(ipc: bool, blocks: u32) -> Regtest {
        let tmp = tempfile::Builder::new()
            .prefix("sv2")
            .tempdir_in("/tmp")
            .unwrap();
        let dir = tmp.path().join("btc");
        std::fs::create_dir_all(&dir).unwrap();
        let (rpc, p2p) = (free_port(), free_port());
        let mut args = vec![
            "-regtest".to_string(),
            format!("-datadir={}", dir.display()),
            "-server".into(),
            "-listen=0".into(),
            "-rpcuser=netget".into(),
            "-rpcpassword=netget".into(),
            "-printtoconsole=0".into(),
            format!("-rpcport={rpc}"),
            format!("-port={p2p}"),
        ];
        if ipc {
            args.push("-ipcbind=unix".into());
        }
        let node = tokio::process::Command::new(env("NETGET_SV2_BITCOIN_NODE"))
            .args(&args)
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("bitcoin-node");
        let me = Regtest {
            _node: node,
            dir,
            rpc,
            tmp,
        };
        tokio::time::timeout(Duration::from_secs(60), async {
            while me.cli(&["getblockchaininfo"]).await.is_err() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("bitcoin-node never answered RPC");
        me.cli(&["generatetodescriptor", &blocks.to_string(), "raw(51)"])
            .await
            .unwrap();
        if ipc {
            let sock = me.dir.join("regtest").join("node.sock");
            tokio::time::timeout(Duration::from_secs(30), async {
                while !sock.exists() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("bitcoin-node never created its IPC socket");
        }
        me
    }

    pub async fn cli(&self, args: &[&str]) -> Result<String, String> {
        let out = tokio::process::Command::new(env("NETGET_SV2_BITCOIN_CLI"))
            .arg("-regtest")
            .arg(format!("-datadir={}", self.dir.display()))
            .args(["-rpcuser=netget", "-rpcpassword=netget"])
            .arg(format!("-rpcport={}", self.rpc))
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

    pub async fn json(&self, args: &[&str]) -> serde_json::Value {
        let text = self
            .cli(args)
            .await
            .unwrap_or_else(|e| panic!("bitcoin-cli {args:?}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::String(text))
    }

    /// The tip: hash, height, and the time a new block may not be earlier than.
    pub async fn tip(&self) -> (String, u64, u64) {
        let info = self.json(&["getblockchaininfo"]).await;
        (
            info["bestblockhash"].as_str().unwrap().to_string(),
            info["blocks"].as_u64().unwrap(),
            info["mediantime"].as_u64().unwrap() + 1,
        )
    }

    /// The coinbase txid of the block at `height` and what its first output pays.
    pub async fn coinbase(&self, height: u64) -> (String, u64) {
        let hash = self
            .cli(&["getblockhash", &height.to_string()])
            .await
            .unwrap();
        let block = self.json(&["getblock", &hash, "2"]).await;
        let tx = &block["tx"][0];
        let sats = (tx["vout"][0]["value"].as_f64().unwrap() * 1e8).round() as u64;
        (tx["txid"].as_str().unwrap().to_string(), sats)
    }
}

/// SRI's pool_sv2 with `extra` (its template provider and any JDS) appended to the base config.
pub async fn pool(dir: &Path, extra: &str) -> (tokio::process::Child, u16, PathBuf) {
    let port = free_port();
    let conf = dir.join("pool.toml");
    std::fs::write(
        &conf,
        format!(
            r#"authority_public_key = "{PUBLIC}"
authority_secret_key = "{SECRET}"
cert_validity_sec = 3600
listen_address = "127.0.0.1:{port}"
coinbase_reward_script = "raw(51)"
server_id = 1
pool_signature = "SRI Pool for NetGet"
shares_per_minute = 60.0
share_batch_size = 1

{extra}
"#
        ),
    )
    .unwrap();
    let log = dir.join("pool.log");
    let child = spawn(
        &env("NETGET_SV2_POOL"),
        &["-c".into(), conf.display().to_string()],
        dir,
        &log,
    );
    (child, port, log)
}

pub async fn wait_listening(port: u16, log: &Path, what: &str, secs: u64) {
    let up = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        up.is_ok(),
        "{what} never listened on {port}:\n{}",
        read(log)
    );
}

pub fn mining_device(port: u16, dir: &Path, log: &Path) -> tokio::process::Child {
    spawn(
        &env("NETGET_SV2_MINING_DEVICE"),
        &[
            "--address-pool".into(),
            format!("127.0.0.1:{port}"),
            "--pubkey-pool".into(),
            PUBLIC.into(),
            "--id-user".into(),
            "netget.device".into(),
            "--cores".into(),
            "1".into(),
        ],
        dir,
        log,
    )
}

/// Everything NetGet printed to the operator, collected while the test runs.
#[derive(Clone, Default)]
pub struct Status(pub Arc<Mutex<Vec<String>>>);

impl Status {
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
    pub async fn wait(&self, needle: &str, secs: u64) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(secs), async {
            loop {
                if let Some(l) = self.lines().into_iter().find(|l| l.contains(needle)) {
                    return l;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .ok()
    }
}
