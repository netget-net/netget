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
                // No core lock: the tests start several nvmf_tgt at once on the same core.
                .args([
                    "--no-huge",
                    "--disable-cpumask-locks",
                    "-s",
                    "1024",
                    "-m",
                    "0x1",
                    "-r",
                ])
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

    /// A DH-HMAC-CHAP secret from nvme-cli's `gen-dhchap-key`, in a file only its owner may
    /// read (SPDK's file keyring refuses any other): (path, the secret).
    fn key_file(dir: &Path, name: &str, hmac: u8, len: u32, nqn: &str) -> (String, String) {
        use std::os::unix::fs::PermissionsExt;
        let nvme = ["/usr/sbin/nvme", "/usr/bin/nvme", "/sbin/nvme"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect(
                "nvme (nvme-cli) is not installed; it generates the secrets nvmf_tgt is \
                 configured with: apt-get install nvme-cli",
            );
        let out = std::process::Command::new(nvme)
            .args([
                "gen-dhchap-key",
                "-m",
                &hmac.to_string(),
                "-l",
                &len.to_string(),
                "-n",
                nqn,
            ])
            .output()
            .unwrap();
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(key.starts_with("DHHC-1:"), "nvme gen-dhchap-key: {key}");
        let path = dir.join(name);
        std::fs::write(&path, &key).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (path.display().to_string(), key)
    }

    /// nvmf_tgt with a TCP transport and one subsystem over a 4 MiB AIO file: (target, port,
    /// backing file, its directory).
    async fn subsystem(
        nqn: &str,
        marker: &[u8],
        any_host: bool,
    ) -> (NvmfTgt, String, PathBuf, tempfile::TempDir) {
        let tgt = NvmfTgt::start().await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("disk.img");
        let mut d = vec![0u8; 4 * 1024 * 1024];
        d[..marker.len()].copy_from_slice(marker);
        d[4096..4608].fill(0xAB);
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
        let mut create = vec![
            "nvmf_create_subsystem",
            nqn,
            "-s",
            "SPDK0002",
            "-d",
            "SPDK_Auth",
        ];
        if any_host {
            create.push("-a");
        }
        tgt.must(&create).await;
        tgt.must(&["nvmf_subsystem_add_ns", nqn, "Aio0"]).await;
        tgt.must(&[
            "nvmf_subsystem_add_listener",
            nqn,
            "-t",
            "tcp",
            "-a",
            "127.0.0.1",
            "-s",
            &port,
        ])
        .await;
        (tgt, port, file, dir)
    }

    const LOGIN_ONLY: &str = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;

    async fn send(
        state: &netget::state::app_state::AppState,
        id: netget::state::ClientId,
        action: serde_json::Value,
    ) -> serde_json::Value {
        match state
            .send_to_client(id, action.clone(), Duration::from_secs(30))
            .await
            .unwrap()
        {
            netget::state::client_handles::ClientSendOutcome::Executed { detail } => {
                let r: serde_json::Value = serde_json::from_str(&detail).unwrap();
                println!("{} -> {r}", action["type"]);
                r
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn spdk_nvmf_tgt_and_the_host_authenticate_each_other() {
        const AUTH_NQN: &str = "nqn.2026-10.io.spdk:netget-auth-test";
        const HOST: &str = "nqn.2026-10.net.netget:host-for-spdk-auth";
        let (tgt, port, file, dir) = subsystem(AUTH_NQN, b"authenticated by spdk", false).await;
        let (host_path, host_key) = key_file(dir.path(), "host.key", 2, 48, HOST);
        let (ctrl_path, ctrl_key) = key_file(dir.path(), "ctrl.key", 0, 64, AUTH_NQN);
        tgt.must(&["keyring_file_add_key", "key0", &host_path])
            .await;
        tgt.must(&["keyring_file_add_key", "ckey0", &ctrl_path])
            .await;
        tgt.must(&[
            "nvmf_subsystem_add_host",
            AUTH_NQN,
            HOST,
            "--dhchap-key",
            "key0",
            "--dhchap-ctrlr-key",
            "ckey0",
        ])
        .await;
        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"host_nqn": HOST, "subsystem_nqn": AUTH_NQN,
                   "dhchap_secret": host_key, "dhchap_ctrl_secret": ctrl_key}),
            chain(&connect_first_policy()),
        )
        .await
        .unwrap();
        let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        println!("connect: {c}");
        assert_eq!(c["connected"], true, "{c}\n{}", tgt.logs());
        assert_eq!(c["authentication"]["bidirectional"], true, "{c}");
        assert_eq!(c["authentication"]["protocol"], "DH-HMAC-CHAP");
        let r = results(&state, id, 6).await;
        assert_eq!(r[1]["data"], "authenticated by spdk", "{}", r[1]);
        assert!(
            wait_for(&file, 51200, WRITE_TEXT.as_bytes()).await,
            "the authenticated host's write reached the file"
        );
        // The wrong host secret, and a controller secret nvmf_tgt does not hold.
        for (params, expect) in [
            (
                json!({"dhchap_secret": key_file(dir.path(), "wrong.key", 2, 48, HOST).1}),
                "refused this host's response",
            ),
            (
                json!({"dhchap_secret": host_key, "dhchap_ctrl_secret": key_file(dir.path(), "wrongc.key", 0, 64, AUTH_NQN).1}),
                "controller authentication failed",
            ),
        ] {
            let mut p = params.clone();
            p["host_nqn"] = json!(HOST);
            p["subsystem_nqn"] = json!(AUTH_NQN);
            let (state, id) = client(format!("127.0.0.1:{port}"), p, chain(LOGIN_ONLY))
                .await
                .unwrap();
            let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
            println!("{expect}: {c}");
            assert_eq!(c["connected"], false, "{c}");
            assert!(
                c["status"].as_str().is_some_and(|s| s.contains(expect)),
                "{c}\n{}",
                tgt.logs()
            );
        }
        println!("nvmf_tgt:\n{}", tgt.logs());
    }

    #[tokio::test]
    async fn spdk_nvmf_tgt_compares_verifies_copies_and_reserves() {
        const CMD_NQN: &str = "nqn.2026-10.io.spdk:netget-cmds-test";
        let (tgt, port, file, _dir) = subsystem(CMD_NQN, b"hello from spdk", true).await;
        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"host_nqn": "nqn.2026-10.net.netget:host-for-spdk-cmds", "subsystem_nqn": CMD_NQN}),
            chain(LOGIN_ONLY),
        )
        .await
        .unwrap();
        let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(c["connected"], true, "{c}\n{}", tgt.logs());
        let r = send(&state, id, json!({"type": "nvme_tcp_identify_controller"})).await;
        println!("nvmf_tgt's controller: {r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_compare", "nsid": 1, "lba": 0, "data": "hello from spdk"}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}\n{}", tgt.logs());
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_compare", "nsid": 1, "lba": 0, "data": "hello from SPDK"}),
        )
        .await;
        assert_eq!(r["status"], "COMPARE FAILURE", "{r}");
        // nvmf_tgt's own Copy limits, from Identify Namespace: the host stays within them, and
        // one range past MSRC is nvmf_tgt's COMMAND SIZE LIMIT EXCEEDED.
        let ns = send(
            &state,
            id,
            json!({"type": "nvme_tcp_identify_namespace", "nsid": 1}),
        )
        .await;
        let limits = ns["namespace"]["copy_limits"].clone();
        println!(
            "nvmf_tgt's copy limits: {limits}; reservation types: {}",
            ns["namespace"]["reservation_types"]
        );
        let max_ranges = limits["max_source_ranges"].as_u64().unwrap();
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 300,
            "ranges": [{"lba": 0, "blocks": 1}]}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}\n{}", tgt.logs());
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 301,
            "ranges": [{"lba": 8, "blocks": 1}]}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        assert!(
            wait_for(&file, 300 * 512, b"hello from spdk").await,
            "the copy is in the file"
        );
        assert!(wait_for(&file, 301 * 512, &[0xAB; 512]).await);
        if max_ranges < 128 {
            let over: Vec<serde_json::Value> = (0..=max_ranges)
                .map(|i| json!({"lba": i, "blocks": 1}))
                .collect();
            let r = send(
                &state,
                id,
                json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 400,
                "ranges": over}),
            )
            .await;
            assert_eq!(r["status"], "COMMAND SIZE LIMIT EXCEEDED", "{r}");
        }
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_verify", "nsid": 1, "lba": 0, "blocks": 8}),
        )
        .await;
        println!("verify against nvmf_tgt: {}", r["status"]);
        assert!(
            matches!(
                r["status"].as_str(),
                Some("SUCCESS" | "INVALID COMMAND OPCODE")
            ),
            "{r}"
        );
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_register", "nsid": 1, "new_key": 291}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}\n{}", tgt.logs());
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1,
            "reservation_type": "exclusive_access_registrants_only", "current_key": 291}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_report", "nsid": 1}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        assert_eq!(
            r["reservation"]["type"], "exclusive_access_registrants_only",
            "{r}"
        );
        assert_eq!(r["reservation"]["registrants"], 1, "{r}");
        assert_eq!(r["reservation"]["entries"][0]["key"], 291, "{r}");
        assert_eq!(
            r["reservation"]["entries"][0]["holds_reservation"], true,
            "{r}"
        );
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_release", "nsid": 1,
            "reservation_type": "write_exclusive", "current_key": 291}),
        )
        .await;
        println!("release with the wrong type: {}", r["status"]);
        assert_ne!(r["status"], "SUCCESS", "{r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_release", "nsid": 1,
            "action": "clear", "current_key": 291}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_report", "nsid": 1}),
        )
        .await;
        assert_eq!(r["reservation"]["registrants"], 0, "{r}");
        let _ = send(&state, id, json!({"type": "nvme_tcp_disconnect"})).await;
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
