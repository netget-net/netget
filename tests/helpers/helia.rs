//! Helia (js-libp2p, @helia/unixfs and ipfs-unixfs-importer), the second independent IPFS
//! implementation for the libp2p suites: `tests/server/libp2p/helia/helia_peer.mjs`, run by
//! Node with the package-lock-pinned modules `install_peers.py` installs.
//!
//! `NETGET_HELIA` names the installed script. Without it (or without `node`) the test
//! **fails**, naming how to install it.
// Compiled into every test binary that declares `helpers`; only the libp2p suites use it.
#![allow(dead_code)]
use super::child_guard::{tie_child, untie_child};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

pub fn helia_script() -> String {
    let p = std::env::var("NETGET_HELIA").unwrap_or_default();
    assert!(
        !p.is_empty() && Path::new(&p).exists(),
        "NETGET_HELIA must name the installed helia_peer.mjs: python3 tests/server/libp2p/install_peers.py <dir> \
         installs Helia's pinned modules with npm ci (needs Node 22 or newer) and prints the export"
    );
    p
}

/// Run one Helia command to completion: every JSON line it printed, and its stderr.
pub async fn run(args: &[&str]) -> (Vec<Value>, String) {
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("node")
            .arg(helia_script())
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("helia {} did not finish", args.join(" ")))
    .expect("node must be on PATH for the Helia peer");
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (
        lines,
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The one line of `step`, failing with everything Helia printed when it is missing.
pub fn step(lines: &[Value], step: &str, text: &str) -> Value {
    lines
        .iter()
        .find(|l| l["step"] == step)
        .cloned()
        .unwrap_or_else(|| panic!("Helia printed no {step} line:\n{text}"))
}

/// A Helia node serving a file or tree it added, until dropped.
pub struct Serving {
    child: tokio::process::Child,
    pub cid: String,
    pub addr: String,
}

impl Serving {
    pub async fn start(path: &str, opts: &[&str]) -> Serving {
        let mut child = tokio::process::Command::new("node")
            .arg(helia_script())
            .arg("serve")
            .arg(path)
            .args(opts)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("node must be on PATH for the Helia peer");
        if let Some(pid) = child.id() {
            tie_child(pid);
        }
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let serving = tokio::time::timeout(Duration::from_secs(60), async {
            while let Ok(Some(l)) = lines.next_line().await {
                let v: Value = serde_json::from_str(&l).unwrap_or_default();
                if v["step"] == "serving" || v["step"] == "error" {
                    return v;
                }
            }
            Value::Null
        })
        .await
        .expect("Helia never said it was serving");
        assert_eq!(serving["step"], "serving", "Helia failed: {serving}");
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Serving {
            child,
            cid: serving["cid"].as_str().unwrap().to_string(),
            addr: serving["addr"].as_str().unwrap().to_string(),
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        let pid = self.child.id();
        let _ = self.child.start_kill();
        if let Some(pid) = pid {
            untie_child(pid);
        }
    }
}
