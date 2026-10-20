//! NetGet's NVMe/TCP host against SPDK's `nvmf_tgt` — a second target implementation,
//! independent of the Linux kernel's — configured through its JSON-RPC socket with
//! `scripts/rpc.py`: a TCP transport, a subsystem whose namespace is an AIO bdev over a file the
//! test wrote, and listeners for the subsystem and the discovery service. What the model reads
//! must be the file's bytes, and what it writes must land in the file. Without hugepages
//! (`--no-huge`), so no root is needed.
//!
//! Linux, in the `nvme-tcp` pair job, with SPDK built by `scripts/test-peers/build-spdk.sh`.
//! `NETGET_SPDK_DIR` names the SPDK tree (with `build/bin` and `scripts/rpc.py`). The test
//! fails, never skips, when SPDK is missing.
#[cfg(target_os = "linux")]
mod spdk_target {
    use super::super::support::*;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn spdk_dir() -> PathBuf {
        let dir = std::env::var_os("NETGET_SPDK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "NETGET_SPDK_DIR is not set. SPDK's nvmf_tgt is the second independent target \
                 this test exists for. Build SPDK with scripts/test-peers/build-spdk.sh <dir> and \
                 set NETGET_SPDK_DIR=<dir>/spdk"
                )
            });
        assert!(
            dir.join("build/bin/nvmf_tgt").is_file() && dir.join("scripts/rpc.py").is_file(),
            "NETGET_SPDK_DIR={} has no build/bin/nvmf_tgt or scripts/rpc.py",
            dir.display()
        );
        dir
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A running nvmf_tgt, killed (and its log printed on failure) when dropped.
    struct NvmfTgt {
        _child: tokio::process::Child,
        spdk: PathBuf,
        sock: PathBuf,
        log: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl NvmfTgt {
        async fn start() -> Self {
            let spdk = spdk_dir();
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("spdk.sock");
            let log = dir.path().join("nvmf_tgt.log");
            let child = tokio::process::Command::new(spdk.join("build/bin/nvmf_tgt"))
                .args(["--no-huge", "-s", "1024", "-m", "0x1", "-r"])
                .arg(&sock)
                .stdout(std::fs::File::create(&log).unwrap())
                .stderr(std::fs::File::create(dir.path().join("stderr.log")).unwrap())
                .kill_on_drop(true)
                .spawn()
                .expect("starting nvmf_tgt");
            let me = Self {
                _child: child,
                spdk,
                sock,
                log,
                _dir: dir,
            };
            // Ready when its RPC socket answers.
            let started = std::time::Instant::now();
            loop {
                if me.sock.exists() && me.rpc(&["spdk_get_version"]).await.is_ok() {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(60),
                    "nvmf_tgt did not come up in 60 s:\n{}",
                    me.logs()
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            me
        }

        async fn rpc(&self, args: &[&str]) -> Result<String, String> {
            let out = tokio::process::Command::new("python3")
                .arg(self.spdk.join("scripts/rpc.py"))
                .arg("-s")
                .arg(&self.sock)
                .args(args)
                .env("PYTHONPATH", self.spdk.join("python"))
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let o = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() {
                Ok(o)
            } else {
                Err(o)
            }
        }

        async fn must(&self, args: &[&str]) {
            if let Err(e) = self.rpc(args).await {
                panic!("rpc.py {args:?}: {e}\n{}", self.logs());
            }
        }

        fn logs(&self) -> String {
            let mut s = std::fs::read_to_string(&self.log).unwrap_or_default();
            if let Some(d) = self.log.parent() {
                s.push_str(&std::fs::read_to_string(d.join("stderr.log")).unwrap_or_default());
            }
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(60)..].join("\n")
        }
    }

    const NQN: &str = "nqn.2026-10.io.spdk:netget-host-test";

    #[tokio::test]
    async fn spdk_nvmf_tgt_serves_the_models_session_from_its_backing_file() {
        let tgt = NvmfTgt::start().await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("disk.img");
        let mut d = vec![0u8; 4 * 1024 * 1024];
        d[..15].copy_from_slice(b"hello from spdk");
        std::fs::write(&file, d).unwrap();
        let port = free_port().to_string();
        tgt.must(&["nvmf_create_transport", "-t", "TCP"]).await;
        tgt.must(&[
            "bdev_aio_create",
            &file.display().to_string(),
            "Aio0",
            "512",
        ])
        .await;
        tgt.must(&[
            "nvmf_create_subsystem",
            NQN,
            "-a",
            "-s",
            "SPDK0001",
            "-d",
            "SPDK_Controller",
        ])
        .await;
        tgt.must(&["nvmf_subsystem_add_ns", NQN, "Aio0"]).await;
        tgt.must(&[
            "nvmf_subsystem_add_listener",
            NQN,
            "-t",
            "tcp",
            "-a",
            "127.0.0.1",
            "-s",
            &port,
        ])
        .await;
        tgt.must(&[
            "nvmf_subsystem_add_listener",
            "nqn.2014-08.org.nvmexpress.discovery",
            "-t",
            "tcp",
            "-a",
            "127.0.0.1",
            "-s",
            &port,
        ])
        .await;

        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"host_nqn": "nqn.2026-10.net.netget:host-for-spdk"}),
            chain(SESSION_POLICY),
        )
        .await
        .unwrap();
        let log = wait_event(&state, id, "nvme_tcp_discovery_log", 0).await;
        assert!(
            log["entries"]
                .as_array()
                .is_some_and(|a| a.iter().any(|e| e["subsystem_nqn"] == NQN)),
            "nvmf_tgt's discovery log lists the subsystem: {log}\n{}",
            tgt.logs()
        );
        let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(connected["connected"], true, "{connected}\n{}", tgt.logs());
        assert_eq!(connected["subsystem_nqn"], NQN);
        assert_eq!(connected["controller"]["serial"], "SPDK0001");
        assert_eq!(connected["controller"]["model"], "SPDK_Controller");
        let r = results(&state, id, 6).await;
        assert_eq!(r[0]["namespace"]["blocks"], 8192, "{}", r[0]);
        assert_eq!(r[1]["data"], "hello from spdk", "{}", r[1]);
        assert_eq!(r[2]["status"], "SUCCESS", "{}\n{}", r[2], tgt.logs());
        assert_eq!(r[3]["data"], WRITE_TEXT, "{}", r[3]);
        assert_eq!(r[4]["status"], "SUCCESS", "the SMART log: {}", r[4]);
        assert_eq!(r[5]["status"], "SUCCESS", "Flush: {}", r[5]);
        let out = wait_event(&state, id, "nvme_tcp_disconnected", 0).await;
        assert_eq!(out["reason"], "shut down by this host", "{out}");
        let back = wait_for(&file, 51200, WRITE_TEXT.as_bytes()).await;
        assert!(back, "the model's write reached nvmf_tgt's backing file");
    }

    async fn wait_for(path: &Path, at: usize, want: &[u8]) -> bool {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let d = std::fs::read(path).unwrap();
                if d[at..at + want.len()] == *want {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .is_ok()
    }
}
