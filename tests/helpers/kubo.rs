//! Kubo (go-ipfs), the independent IPFS peer for the libp2p suites, run as a daemon in a
//! repository of its own and confined to loopback.
//!
//! The binary is `NETGET_KUBO` (Kubo 0.43.1, installed and sha256-checked by
//! `tests/server/libp2p/install_peers.py`). Without it the test **fails**, naming how to get
//! it: a skipped interop test is a silent pass.
//!
//! Confinement, all of it set in the repository's own config before the daemon starts:
//! `ipfs init --profile=test` (loopback swarm, API and gateway on port 0, no bootstrap peers,
//! no MDNS, no AutoConf fetch, loopback addresses allowed on the LAN DHT); every transport but
//! TCP off; `Swarm.AddrFilters` refusing every IPv4 range but 127.0.0.0/8 and all of IPv6, so
//! a dial elsewhere is refused by Kubo itself; no relay, AutoNAT, NAT port mapping or HTTP
//! routers; and `IPFS_TELEMETRY=off`. `Routing.Type` is the test's choice: `none` for
//! Bitswap alone, `dhtclient` or `dhtserver` for the DHT.
// Compiled into every test binary that declares `helpers`; only the libp2p suites use it.
#![allow(dead_code)]
use super::child_guard::{tie_child, untie_child};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

pub fn kubo_bin() -> String {
    let p = std::env::var("NETGET_KUBO").unwrap_or_default();
    assert!(
        !p.is_empty() && Path::new(&p).exists(),
        "NETGET_KUBO must name Kubo 0.43.1's ipfs binary: python3 tests/server/libp2p/install_peers.py <dir> \
         downloads and checks it (or brew install kubo and point NETGET_KUBO at it)"
    );
    p
}

/// Every IPv4 range except 127.0.0.0/8, and all of IPv6: Kubo will dial nothing else.
const NOT_LOOPBACK: &[&str] = &[
    "/ip4/0.0.0.0/ipcidr/2",
    "/ip4/64.0.0.0/ipcidr/3",
    "/ip4/96.0.0.0/ipcidr/4",
    "/ip4/112.0.0.0/ipcidr/5",
    "/ip4/120.0.0.0/ipcidr/6",
    "/ip4/124.0.0.0/ipcidr/7",
    "/ip4/126.0.0.0/ipcidr/8",
    "/ip4/128.0.0.0/ipcidr/1",
    "/ip6/::/ipcidr/0",
];

pub struct Kubo {
    dir: tempfile::TempDir,
    child: Option<tokio::process::Child>,
    pub peer_id: String,
    /// The swarm address, `/ip4/127.0.0.1/tcp/<port>/p2p/<id>`.
    pub swarm_addr: String,
    log: Arc<Mutex<String>>,
}

pub struct Run {
    pub ok: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Run {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }
}

impl Kubo {
    /// A fresh repository with no daemon, for commands that need none (`ipfs add
    /// --only-hash`, `ipfs version`).
    pub async fn offline() -> Kubo {
        let dir = tempfile::Builder::new()
            .prefix("netget-kubo-")
            .tempdir()
            .unwrap();
        let init = run_in(dir.path(), &["init", "--profile=test", "-e"]).await;
        assert!(init.ok, "ipfs init failed: {}", init.stderr);
        Kubo {
            dir,
            child: None,
            peer_id: String::new(),
            swarm_addr: String::new(),
            log: Default::default(),
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The daemon's own log so far, for failure messages.
    pub fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// A fresh repository, confined as the module says, and its daemon running.
    pub async fn start(routing: &str) -> Kubo {
        let dir = tempfile::Builder::new()
            .prefix("netget-kubo-")
            .tempdir()
            .unwrap();
        let init = run_in(dir.path(), &["init", "--profile=test", "-e"]).await;
        assert!(init.ok, "ipfs init failed: {}", init.stderr);
        let cfg_path = dir.path().join("config");
        let mut cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
        cfg["Routing"]["Type"] = json!(routing);
        cfg["Routing"]["DelegatedRouters"] = json!([]);
        cfg["Swarm"]["Transports"]["Network"] = json!({
            "TCP": true, "QUIC": false, "Websocket": false, "WebTransport": false,
            "WebRTCDirect": false, "Relay": false,
        });
        cfg["Swarm"]["AddrFilters"] = json!(NOT_LOOPBACK);
        cfg["Swarm"]["DisableNatPortMap"] = json!(true);
        cfg["Swarm"]["RelayClient"] = json!({"Enabled": false});
        cfg["Swarm"]["RelayService"] = json!({"Enabled": false});
        cfg["AutoNAT"] = json!({"ServiceMode": "disabled"});
        cfg["AutoConf"] = json!({"Enabled": false});
        cfg["Bootstrap"] = json!([]);
        cfg["Discovery"] = json!({"MDNS": {"Enabled": false}});
        std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        let mut child = tokio::process::Command::new(kubo_bin())
            .args(["daemon"])
            .env("IPFS_PATH", dir.path())
            .env("IPFS_TELEMETRY", "off")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        if let Some(pid) = child.id() {
            tie_child(pid);
        }
        let log = Arc::new(Mutex::new(String::new()));
        for out in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let log = log.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(out).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let mut g = log.lock().unwrap();
                    g.push_str(&l);
                    g.push('\n');
                }
            });
        }
        let mut kubo = Kubo {
            dir,
            child: Some(child),
            peer_id: String::new(),
            swarm_addr: String::new(),
            log,
        };
        let ready = tokio::time::timeout(Duration::from_secs(90), async {
            while !kubo.log().contains("Daemon is ready") {
                if let Some(c) = kubo.child.as_mut() {
                    if let Ok(Some(status)) = c.try_wait() {
                        return Err(format!("the daemon exited: {status}"));
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(())
        })
        .await;
        match ready {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("Kubo did not start: {e}\n{}", kubo.log()),
            Err(_) => panic!("Kubo never said it was ready:\n{}", kubo.log()),
        }
        let id: Value = serde_json::from_slice(&kubo.ok(&["id"]).await).unwrap();
        kubo.peer_id = id["ID"].as_str().unwrap().to_string();
        kubo.swarm_addr = id["Addresses"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .find(|a| a.starts_with("/ip4/127.0.0.1/tcp/"))
            .unwrap_or_else(|| panic!("Kubo has no loopback TCP address: {id}"))
            .to_string();
        kubo
    }

    /// Run `ipfs <args>` against this repository's daemon.
    pub async fn ipfs(&self, args: &[&str]) -> Run {
        run_in(self.dir.path(), args).await
    }

    /// Run it and return stdout, failing the test (with Kubo's words) if it fails.
    pub async fn ok(&self, args: &[&str]) -> Vec<u8> {
        let r = self.ipfs(args).await;
        assert!(
            r.ok,
            "ipfs {} failed: {}\n--- daemon log ---\n{}",
            args.join(" "),
            r.stderr,
            self.log()
        );
        r.stdout
    }

    /// Write `content` to a file in the repository's directory, for `ipfs add`.
    pub fn file(&self, name: &str, content: &[u8]) -> String {
        let p = self.dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }

    /// The peers the daemon is connected to, as `ipfs swarm peers` lists them.
    pub async fn swarm_peers(&self) -> Vec<String> {
        String::from_utf8(self.ok(&["swarm", "peers"]).await)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

async fn run_in(repo: &Path, args: &[&str]) -> Run {
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(kubo_bin())
            .args(args)
            .env("IPFS_PATH", repo)
            .env("IPFS_TELEMETRY", "off")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("ipfs {} did not finish", args.join(" ")))
    .unwrap();
    Run {
        ok: out.status.success(),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

impl Drop for Kubo {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let pid = c.id();
            let _ = c.start_kill();
            if let Some(pid) = pid {
                untie_child(pid);
            }
            if std::thread::panicking() {
                eprintln!("--- Kubo daemon log ---\n{}", self.log());
            }
        }
    }
}
