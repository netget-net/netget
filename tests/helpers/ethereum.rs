//! go-ethereum and reth on private development chains, for the devp2p suites.
//!
//! Both peers stay on loopback with discovery off: geth with `--nodiscover --netrestrict
//! 127.0.0.0/8 --nat extip:127.0.0.1`, reth with `--disable-discovery --addr 127.0.0.1 --nat
//! extip:127.0.0.1`. Nothing here reaches a public network: the chains are created locally and
//! peers are added by enode URL (`admin_addPeer`).
//!
//! **geth** cannot be a dev chain and a network node at once (`--dev` forces `--maxpeers 0`), so
//! [`geth_chain`] runs `geth --dev --dev.period 1` under its JavaScript console until it has
//! sealed the blocks asked for, prints their hashes and exits; [`Geth::start`] then starts an
//! ordinary node on that data directory, which serves the chain over devp2p and never advances
//! it (there is no consensus client). **reth**'s `--dev` mode keeps its network, so it runs as
//! one process and keeps sealing a block a second.
//!
//! Every binary is required: a missing one fails the test naming how to install it.
#![allow(dead_code)]

use super::real_server::{find_binary, missing_binary, InstallHint, RealServer};
use super::E2EResult;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

pub const GETH: InstallHint = InstallHint {
    brew: "ethereum",
    apt: "(no usable package: fetch go-ethereum's geth-alltools release tarball, as \
          .github/workflows/protocol-pairs.yml's devp2p job does)",
};
pub const DEVP2P_TOOL: InstallHint = GETH;
pub const RETH: InstallHint = InstallHint {
    brew: "(no formula: fetch reth's release tarball from github.com/paradigmxyz/reth, as \
           .github/workflows/protocol-pairs.yml's devp2p job does, and put `reth` on PATH)",
    apt: "(no package: the reth release tarball, as the devp2p job does)",
};

/// The binary for `name`: `$NETGET_<NAME>` when set (the devp2p pair job installs the release
/// tarballs and names them this way), else `name` from `PATH`.
pub fn binary(name: &str) -> String {
    std::env::var(format!("NETGET_{}", name.to_ascii_uppercase()))
        .unwrap_or_else(|_| name.to_string())
}

/// The network id both dev chains use.
pub const DEV_NETWORK_ID: u64 = 1337;

/// JSON-RPC over HTTP to a local node.
pub async fn rpc(port: u16, method: &str, params: Value) -> E2EResult<Value> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    let reply: Value = client
        .post(format!("http://127.0.0.1:{port}"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await?
        .json()
        .await?;
    if let Some(e) = reply.get("error") {
        return Err(format!("{method}: {e}").into());
    }
    Ok(reply["result"].clone())
}

/// A geth data directory holding a dev chain of `blocks` blocks past genesis, and the hashes
/// of blocks 0..=blocks as geth itself reports them.
pub struct GethChain {
    pub dir: tempfile::TempDir,
    pub hashes: Vec<String>,
}

impl GethChain {
    pub fn datadir(&self) -> PathBuf {
        self.dir.path().join("chain")
    }
}

/// Seal a dev chain with geth and stop.
pub async fn geth_chain(blocks: u64) -> E2EResult<GethChain> {
    let geth = find_binary(&binary("geth")).ok_or_else(|| {
        missing_binary(
            "geth",
            GETH,
            "not found on PATH or in the usual install directories",
        )
    })?;
    let dir = tempfile::Builder::new().prefix("netget-geth-").tempdir()?;
    let datadir = dir.path().join("chain");
    let script = format!(
        "admin.sleepBlocks({blocks}); var h = []; for (var i = 0; i <= {blocks}; i++) {{ h.push(eth.getBlock(i).hash); }} JSON.stringify(h)"
    );
    let authrpc = probe_port()?;
    let mut command = tokio::process::Command::new(geth);
    command
        .args(["--dev", "--dev.period", "1", "--datadir"])
        .arg(&datadir)
        .args([
            "--authrpc.port",
            &authrpc.to_string(),
            "--nat",
            "none",
            "--verbosity",
            "1",
            "--exec",
            &script,
            "console",
        ])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| "geth --dev did not seal the chain within 120s")?
        .map_err(|e| missing_binary("geth", GETH, e))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!(
            "geth --dev exited with {}:\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    // The console prints the expression's value: a JSON string holding the JSON array.
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('"'))
        .ok_or_else(|| format!("no hashes in geth's console output:\n{stdout}"))?;
    let inner: String = serde_json::from_str(line.trim())?;
    let hashes: Vec<String> = serde_json::from_str(&inner)?;
    if hashes.len() as u64 != blocks + 1 {
        return Err(format!("geth reported {} hashes for {blocks} blocks", hashes.len()).into());
    }
    Ok(GethChain { dir, hashes })
}

fn probe_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// A geth node serving a [`GethChain`] over devp2p, with its HTTP JSON-RPC on loopback.
pub struct Geth {
    pub server: RealServer,
}

impl Geth {
    /// `extra` is appended to the command line (`--eth.requiredblocks`, for one).
    pub async fn start(chain: &GethChain, extra: &[String]) -> E2EResult<Geth> {
        let datadir = chain.datadir().to_string_lossy().to_string();
        let mut args: Vec<String> = [
            "--datadir",
            &datadir,
            "--networkid",
            &DEV_NETWORK_ID.to_string(),
            "--nodiscover",
            "--nat",
            "extip:127.0.0.1",
            "--netrestrict",
            "127.0.0.0/8",
            "--maxpeers",
            "10",
            "--port",
            "{port}",
            "--http",
            "--http.addr",
            "127.0.0.1",
            "--http.port",
            "{port1}",
            "--http.api",
            "admin,eth,net,web3",
            "--authrpc.port",
            "{port2}",
            "--ipcdisable",
            "--verbosity",
            "4",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.extend(extra.iter().cloned());
        let server = RealServer::builder(&binary("geth"), GETH)
            .extra_ports(2)
            .args(args)
            .ready_when_log_matches("HTTP server started")
            .startup_timeout(Duration::from_secs(60))
            .start()
            .await?;
        Ok(Geth { server })
    }

    pub fn http_port(&self) -> u16 {
        self.server.extra_ports[0]
    }

    pub async fn rpc(&self, method: &str, params: Value) -> E2EResult<Value> {
        self.server
            .with_log(rpc(self.http_port(), method, params).await)
    }

    /// geth's own enode URL, pointed at loopback.
    pub async fn enode(&self) -> E2EResult<String> {
        let info = self.rpc("admin_nodeInfo", json!([])).await?;
        let enode = info["enode"]
            .as_str()
            .ok_or("admin_nodeInfo has no enode")?;
        Ok(loopback_enode(enode, self.server.port))
    }

    pub async fn block(&self, n: u64) -> E2EResult<Value> {
        self.rpc("eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))
            .await
    }
}

/// `enode://<id>@…` with its host and port replaced by 127.0.0.1 and `port`.
pub fn loopback_enode(enode: &str, port: u16) -> String {
    let id = enode
        .trim_start_matches("enode://")
        .split('@')
        .next()
        .unwrap_or_default();
    format!("enode://{id}@127.0.0.1:{port}")
}

/// A reth dev node: its own chain, a block a second, devp2p on loopback.
pub struct Reth {
    pub server: RealServer,
}

impl Reth {
    pub async fn start() -> E2EResult<Reth> {
        let server = RealServer::builder(&binary("reth"), RETH)
            .extra_ports(2)
            .args([
                "node",
                "--dev",
                "--dev.block-time",
                "1s",
                "--datadir",
                "{dir}/data",
                "--addr",
                "127.0.0.1",
                "--port",
                "{port}",
                "--nat",
                "extip:127.0.0.1",
                "--disable-discovery",
                "--no-persist-peers",
                "--http",
                "--http.addr",
                "127.0.0.1",
                "--http.port",
                "{port1}",
                "--http.api",
                "admin,eth,net,web3",
                "--authrpc.port",
                "{port2}",
                "--ipcdisable",
                "--color",
                "never",
            ])
            .ready_when_log_matches("RPC HTTP server started")
            .startup_timeout(Duration::from_secs(60))
            .start()
            .await?;
        Ok(Reth { server })
    }

    pub fn http_port(&self) -> u16 {
        self.server.extra_ports[0]
    }

    pub async fn rpc(&self, method: &str, params: Value) -> E2EResult<Value> {
        self.server
            .with_log(rpc(self.http_port(), method, params).await)
    }

    pub async fn enode(&self) -> E2EResult<String> {
        let info = self.rpc("admin_nodeInfo", json!([])).await?;
        let enode = info["enode"]
            .as_str()
            .ok_or("admin_nodeInfo has no enode")?;
        Ok(loopback_enode(enode, self.server.port))
    }

    /// Wait until the chain is at least `n` blocks long.
    pub async fn wait_for_block(&self, n: u64) -> E2EResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let head = self.rpc("eth_blockNumber", json!([])).await?;
            let head =
                u64::from_str_radix(head.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
            if head >= n {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("reth reached only block {head} in 60s").into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn block(&self, n: u64) -> E2EResult<Value> {
        self.rpc("eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))
            .await
    }
}

/// `admin_peers` until one whose id is `node_id` shows up; returns its entry.
pub async fn wait_for_peer(port: u16, node_id: &str, timeout: Duration) -> E2EResult<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let peers = rpc(port, "admin_peers", json!([])).await?;
        if let Some(p) = peers.as_array().and_then(|a| {
            a.iter().find(|p| {
                p["id"].as_str() == Some(node_id)
                    || p["enode"].as_str().is_some_and(|e| e.contains(node_id))
            })
        }) {
            if !p["protocols"]["eth"].is_null() && p["protocols"]["eth"] != json!("handshake") {
                return Ok(p.clone());
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("{node_id} never appeared in admin_peers: {peers}").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
