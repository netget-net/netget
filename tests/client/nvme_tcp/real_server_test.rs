//! NetGet's NVMe/TCP host against the Linux kernel's NVMe/TCP target (`nvmet` with
//! `nvmet-tcp`), configured through configfs: a subsystem with a file-backed namespace the test
//! wrote, an allowed host, and a TCP port on loopback. What the model reads must be the file's
//! bytes, and what it writes must land in the file.
//!
//! Linux, as root, with `nvmet` and `nvmet-tcp` loaded and configfs mounted: the `nvme-tcp`
//! pair job runs this binary through sudo. The test fails, never skips, when root, the modules
//! or configfs are missing.
#[cfg(target_os = "linux")]
mod kernel_target {
    use super::super::support::*;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const CONFIGFS: &str = "/sys/kernel/config/nvmet";
    const HOST: &str = "nqn.2026-10.net.netget:host-for-nvmet";

    /// A host NQN of this test's own, so no two tests share a configfs host entry.
    fn host(tag: &str) -> String {
        format!("{HOST}-{tag}")
    }

    fn require_root() {
        assert!(
            unsafe { libc::geteuid() } == 0, // SAFETY: geteuid has no preconditions.
            "the kernel target is configured through configfs, which needs root: the nvme-tcp \
             pair job runs this binary through sudo"
        );
    }

    fn require_nvmet() {
        if !Path::new(CONFIGFS).exists() {
            // Loading the modules is the job's; try once, then say what is missing.
            let _ = std::process::Command::new("modprobe")
                .args(["nvmet-tcp"])
                .output();
        }
        assert!(
            Path::new(CONFIGFS).exists() && Path::new("/sys/module/nvmet_tcp").exists(),
            "the kernel NVMe target is not available ({CONFIGFS} or /sys/module/nvmet_tcp \
             missing): modprobe nvmet nvmet-tcp (linux-modules-extra-$(uname -r) on Ubuntu), \
             with configfs mounted at /sys/kernel/config"
        );
    }

    fn write(path: &Path, value: &str) {
        std::fs::write(path, value)
            .unwrap_or_else(|e| panic!("writing {value:?} to {}: {e}", path.display()));
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A subsystem, its namespace and a port in configfs, torn down in reverse on drop.
    struct Nvmet {
        subsys: PathBuf,
        port: PathBuf,
        host: PathBuf,
        links: Vec<PathBuf>,
        ns: Vec<PathBuf>,
        pub nqn: String,
        pub tcp_port: u16,
        _dir: tempfile::TempDir,
        pub backing: Vec<PathBuf>,
    }

    impl Nvmet {
        /// `files`: (NSID, backing file contents).
        fn new(tag: &str, files: &[(u32, Vec<u8>)], allow: &[&str]) -> Self {
            Self::build(tag, files, allow, false)
        }

        /// As [`Nvmet::new`], with persistent reservations enabled on every namespace
        /// (`resv_enable`, which nvmet takes only before a namespace is enabled).
        fn build(tag: &str, files: &[(u32, Vec<u8>)], allow: &[&str], resv: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = PathBuf::from(CONFIGFS);
            let nqn = format!("nqn.2026-10.org.linux:nvmet-{tag}-{}", std::process::id());
            let subsys = base.join("subsystems").join(&nqn);
            std::fs::create_dir(&subsys)
                .unwrap_or_else(|e| panic!("mkdir {}: {e}", subsys.display()));
            let mut me = Self {
                subsys: subsys.clone(),
                port: PathBuf::new(),
                host: PathBuf::new(),
                links: vec![],
                ns: vec![],
                nqn: nqn.clone(),
                tcp_port: 0,
                _dir: dir,
                backing: vec![],
            };
            write(&subsys.join("attr_allow_any_host"), "0");
            for h in allow {
                let host = base.join("hosts").join(h);
                if !host.exists() {
                    std::fs::create_dir(&host).unwrap();
                    me.host = host.clone();
                }
                let link = subsys.join("allowed_hosts").join(h);
                std::os::unix::fs::symlink(&host, &link).unwrap();
                me.links.push(link);
            }
            for (nsid, content) in files {
                let file = me._dir.path().join(format!("ns{nsid}.img"));
                std::fs::write(&file, content).unwrap();
                let ns = subsys.join("namespaces").join(nsid.to_string());
                std::fs::create_dir(&ns).unwrap();
                write(&ns.join("device_path"), &file.display().to_string());
                if resv {
                    write(&ns.join("resv_enable"), "1");
                }
                write(&ns.join("enable"), "1");
                me.ns.push(ns);
                me.backing.push(file);
            }
            // A port id no other run is using.
            let mut id = 1000 + std::process::id() % 50000;
            let port = loop {
                let p = base.join("ports").join(id.to_string());
                match std::fs::create_dir(&p) {
                    Ok(()) => break p,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => id += 1,
                    Err(e) => panic!("mkdir {}: {e}", p.display()),
                }
            };
            me.port = port.clone();
            let tcp_port = free_port();
            write(&port.join("addr_trtype"), "tcp");
            write(&port.join("addr_adrfam"), "ipv4");
            write(&port.join("addr_traddr"), "127.0.0.1");
            write(&port.join("addr_trsvcid"), &tcp_port.to_string());
            let link = port.join("subsystems").join(&nqn);
            std::os::unix::fs::symlink(&subsys, &link).unwrap();
            me.links.push(link);
            me.tcp_port = tcp_port;
            me
        }
    }

    impl Nvmet {
        /// DH-HMAC-CHAP for an allowed host: its secret, the controller's (bidirectional), and
        /// the hash and DH group nvmet challenges with.
        fn dhchap(&self, host: &str, key: &str, ctrl_key: Option<&str>, hash: &str, group: &str) {
            let h = PathBuf::from(CONFIGFS).join("hosts").join(host);
            write(&h.join("dhchap_key"), key);
            if let Some(c) = ctrl_key {
                write(&h.join("dhchap_ctrl_key"), c);
            }
            write(&h.join("dhchap_hash"), hash);
            write(&h.join("dhchap_dhgroup"), group);
        }
    }

    /// A secret from nvme-cli's `gen-dhchap-key`, the tool an administrator configures nvmet
    /// with: `-m` the transformation hash, `-l` the key length, `-n` the NQN.
    fn gen_key(hmac: u8, len: u32, nqn: &str) -> String {
        let nvme = ["/usr/sbin/nvme", "/usr/bin/nvme", "/sbin/nvme"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect(
                "nvme (nvme-cli) is not installed; it generates the DH-HMAC-CHAP secrets nvmet \
                 is configured with: apt-get install nvme-cli",
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
        key
    }

    fn mark(tag: &str) -> String {
        let marker = format!("netget-nvme-client-test {tag} {}", std::process::id());
        let _ = std::fs::write("/dev/kmsg", format!("{marker}\n"));
        marker
    }

    fn since(marker: &str) -> String {
        let all = std::process::Command::new("dmesg")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        all.rfind(marker)
            .map_or(String::new(), |at| all[at..].to_string())
    }

    const CONNECT_ONLY: &str = r#"import json,sys
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
                println!("{} -> {}", action["type"], r);
                r
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_host_authenticates_to_the_kernel_target() {
        require_root();
        require_nvmet();
        for (i, (hash, group, bidirectional)) in [
            ("sha256", "null", false),
            ("sha512", "ffdhe4096", true),
            ("sha384", "ffdhe8192", true),
        ]
        .into_iter()
        .enumerate()
        {
            let tag = format!("auth{i}");
            let host = host(&tag);
            let t = Nvmet::new(&tag, &[(1, disk("authenticated by nvmet"))], &[&host]);
            let key = gen_key(1, 32, &host);
            let ctrl_key = gen_key(2, 48, &t.nqn);
            t.dhchap(
                &host,
                &key,
                bidirectional.then_some(ctrl_key.as_str()),
                &format!("hmac({hash})"),
                group,
            );
            let mut params =
                json!({"host_nqn": host, "subsystem_nqn": t.nqn, "dhchap_secret": key});
            if bidirectional {
                params["dhchap_ctrl_secret"] = json!(ctrl_key);
            }
            let (state, id) = client(
                format!("127.0.0.1:{}", t.tcp_port),
                params,
                chain(&connect_first_policy()),
            )
            .await
            .unwrap();
            let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
            assert_eq!(c["connected"], true, "{c}\n{}", diagnostics(&t));
            assert_eq!(
                c["authentication"],
                json!({"protocol": "DH-HMAC-CHAP", "hash": hash, "dh_group": group, "bidirectional": bidirectional}),
                "nvmet chose what it was configured with"
            );
            // Authenticated: nvmet runs the session, and the write lands in its backing file.
            let r = results(&state, id, 6).await;
            assert_eq!(r[1]["data"], "authenticated by nvmet", "{}", r[1]);
            let block = r[0]["namespace"]["block_size"].as_u64().unwrap() as usize;
            wait_for_write(&t.backing[0], block).await;
            wait_event(&state, id, "nvme_tcp_disconnected", 0).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_kernel_target_refuses_a_wrong_secret_and_the_host_refuses_a_wrong_controller() {
        require_root();
        require_nvmet();
        let host = host("wrongkey");
        let t = Nvmet::new("wrongkey", &[(1, disk("never read"))], &[&host]);
        let key = gen_key(1, 32, &host);
        let ctrl_key = gen_key(0, 32, &t.nqn);
        t.dhchap(&host, &key, Some(&ctrl_key), "hmac(sha256)", "ffdhe2048");
        for (i, (params, expect, kernel)) in [
            (
                json!({"dhchap_secret": gen_key(1, 32, &host)}),
                "refused this host's response",
                "host response mismatch",
            ),
            (
                json!({"dhchap_secret": key, "dhchap_ctrl_secret": gen_key(0, 32, &t.nqn)}),
                "controller authentication failed",
                // nvmet takes the host's AUTH_Failure2 as a fatal controller error.
                "fatal error occurred",
            ),
            (json!({}), "no dhchap_secret", ""),
        ]
        .into_iter()
        .enumerate()
        {
            let mut p = params.clone();
            p["host_nqn"] = json!(host);
            p["subsystem_nqn"] = json!(t.nqn);
            let marker = mark(&format!("wrongkey-case-{i}"));
            let (state, id) = client(format!("127.0.0.1:{}", t.tcp_port), p, chain(CONNECT_ONLY))
                .await
                .unwrap();
            let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
            let log = since(&marker);
            println!("{expect}: {c}\nkernel:\n{log}");
            assert_eq!(c["connected"], false, "{c}");
            assert!(
                c["status"].as_str().is_some_and(|s| s.contains(expect)),
                "{c}\n{}",
                diagnostics(&t)
            );
            assert!(log.contains(kernel), "nvmet logged {kernel:?}:\n{log}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_host_reserves_on_the_kernel_target_which_has_no_compare_verify_or_copy() {
        require_root();
        require_nvmet();
        let host = host("resv");
        let t = Nvmet::build("resv", &[(1, disk("reserved by netget"))], &[&host], true);
        let (state, id) = client(
            format!("127.0.0.1:{}", t.tcp_port),
            json!({"host_nqn": host, "subsystem_nqn": t.nqn}),
            chain(CONNECT_ONLY),
        )
        .await
        .unwrap();
        let c = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(c["connected"], true, "{c}\n{}", diagnostics(&t));
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_register", "nsid": 1, "new_key": 161}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}\n{}", diagnostics(&t));
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1,
            "reservation_type": "write_exclusive", "current_key": 162}),
        )
        .await;
        assert_eq!(r["status"], "RESERVATION CONFLICT", "the wrong key: {r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_acquire", "nsid": 1,
            "reservation_type": "write_exclusive", "current_key": 161}),
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
        assert_eq!(r["reservation"]["type"], "write_exclusive", "{r}");
        assert_eq!(r["reservation"]["registrants"], 1);
        assert_eq!(r["reservation"]["entries"][0]["key"], 161);
        assert_eq!(r["reservation"]["entries"][0]["holds_reservation"], true);
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_register", "nsid": 1,
            "action": "replace", "current_key": 161, "new_key": 177}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_release", "nsid": 1,
            "reservation_type": "write_exclusive", "current_key": 177}),
        )
        .await;
        assert_eq!(r["status"], "SUCCESS", "{r}");
        let r = send(
            &state,
            id,
            json!({"type": "nvme_tcp_reservation_release", "nsid": 1,
            "action": "clear", "current_key": 177}),
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
        // nvmet's file and block backends implement neither Compare, Verify nor Copy: the host
        // reports the target's refusal by name rather than inventing an answer.
        for a in [
            json!({"type": "nvme_tcp_compare", "nsid": 1, "lba": 0, "data": "reserved by netget"}),
            json!({"type": "nvme_tcp_verify", "nsid": 1, "lba": 0, "blocks": 8}),
            json!({"type": "nvme_tcp_copy", "nsid": 1, "destination_lba": 100, "ranges": [{"lba": 0, "blocks": 1}]}),
        ] {
            let r = send(&state, id, a).await;
            assert_eq!(r["status"], "INVALID COMMAND OPCODE", "{r}");
        }
        let _ = send(&state, id, json!({"type": "nvme_tcp_disconnect"})).await;
    }

    impl Drop for Nvmet {
        fn drop(&mut self) {
            for l in self.links.iter().rev() {
                let _ = std::fs::remove_file(l);
            }
            for ns in &self.ns {
                let _ = std::fs::write(ns.join("enable"), "0");
                let _ = std::fs::remove_dir(ns);
            }
            if !self.port.as_os_str().is_empty() {
                let _ = std::fs::remove_dir(&self.port);
            }
            let _ = std::fs::remove_dir(&self.subsys);
            if !self.host.as_os_str().is_empty() {
                let _ = std::fs::remove_dir(&self.host);
            }
        }
    }

    /// The kernel's own account, for a failure message.
    fn diagnostics(t: &Nvmet) -> String {
        let mut s = String::new();
        for p in [&t.subsys, &t.port] {
            s.push_str(&format!("{}:\n", p.display()));
            for e in walk(p, 2) {
                s.push_str(&format!("  {e}\n"));
            }
        }
        let dmesg = std::process::Command::new("dmesg")
            .output()
            .map(|o| {
                let all = String::from_utf8_lossy(&o.stdout).into_owned();
                let lines: Vec<&str> = all.lines().collect();
                lines[lines.len().saturating_sub(40)..].join("\n")
            })
            .unwrap_or_default();
        format!("{s}dmesg:\n{dmesg}")
    }

    fn walk(p: &Path, depth: usize) -> Vec<String> {
        let mut out = vec![];
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_file() {
                let v = std::fs::read_to_string(&path).unwrap_or_default();
                out.push(format!("{} = {}", path.display(), v.trim()));
            } else if depth > 0 {
                out.extend(walk(&path, depth - 1));
            }
        }
        out
    }

    fn disk(marker: &str) -> Vec<u8> {
        let mut d = vec![0u8; 4 * 1024 * 1024];
        d[..marker.len()].copy_from_slice(marker.as_bytes());
        d
    }

    /// Wait until the backing file holds `WRITE_TEXT` at block 100 (of `block` bytes).
    async fn wait_for_write(path: &Path, block: usize) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let d = std::fs::read(path).unwrap();
                if d[100 * block..100 * block + WRITE_TEXT.len()] == *WRITE_TEXT.as_bytes() {
                    return d;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the model's write reached the kernel target's backing file")
    }

    #[tokio::test]
    async fn the_kernel_target_serves_the_models_session_from_its_backing_file() {
        require_root();
        require_nvmet();
        let host = host("session");
        let t = Nvmet::new("session", &[(1, disk("hello from nvmet"))], &[&host]);
        let (state, id) = client(
            format!("127.0.0.1:{}", t.tcp_port),
            json!({"host_nqn": host}),
            chain(SESSION_POLICY),
        )
        .await
        .unwrap();
        let log = wait_event(&state, id, "nvme_tcp_discovery_log", 0).await;
        let listed: Vec<&str> = log["entries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e["subsystem_nqn"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            listed.contains(&t.nqn.as_str()),
            "nvmet's discovery log lists the subsystem: {log}\n{}",
            diagnostics(&t)
        );
        // SESSION_POLICY connects to the first entry, which is ours: nvmet lists only the
        // subsystems this host may use on this port.
        let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(
            connected["connected"],
            true,
            "{connected}\n{}",
            diagnostics(&t)
        );
        assert_eq!(connected["subsystem_nqn"], t.nqn.as_str());
        assert_eq!(connected["namespaces"], json!([1]));
        assert_eq!(connected["controller"]["controller_type"], "io");
        let r = results(&state, id, 6).await;
        // nvmet's file backend takes the backing file system's block size.
        let block = r[0]["namespace"]["block_size"].as_u64().unwrap() as usize;
        assert!(block == 512 || block == 4096, "{}", r[0]);
        assert_eq!(
            r[0]["namespace"]["blocks"].as_u64().unwrap() as usize * block,
            4 * 1024 * 1024,
            "{}",
            r[0]
        );
        assert_eq!(r[1]["data"], "hello from nvmet", "{}", r[1]);
        assert_eq!(r[2]["status"], "SUCCESS", "{}", r[2]);
        assert_eq!(r[3]["data"], WRITE_TEXT, "{}", r[3]);
        assert_eq!(r[4]["status"], "SUCCESS", "the SMART log: {}", r[4]);
        assert_eq!(r[5]["status"], "SUCCESS", "Flush: {}", r[5]);
        let out = wait_event(&state, id, "nvme_tcp_disconnected", 0).await;
        assert_eq!(out["reason"], "shut down by this host", "{out}");
        let d = wait_for_write(&t.backing[0], block).await;
        assert_eq!(&d[..16], b"hello from nvmet");
    }

    #[tokio::test]
    async fn the_kernel_target_with_digests_and_a_large_write() {
        require_root();
        require_nvmet();
        let host = host("digests");
        let t = Nvmet::new("digests", &[(1, disk("digested"))], &[&host]);
        let login_only = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;
        let (state, id) = client(
            format!("127.0.0.1:{}", t.tcp_port),
            json!({"host_nqn": host, "subsystem_nqn": t.nqn, "digests": "crc32c", "keep_alive_ms": 5000}),
            chain(login_only),
        )
        .await
        .unwrap();
        let connected = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(
            connected["connected"],
            true,
            "{connected}\n{}",
            diagnostics(&t)
        );
        assert_eq!(connected["controller"]["digests"], true);
        let send = |action: serde_json::Value| {
            let state = state.clone();
            async move {
                match state
                    .send_to_client(id, action, Duration::from_secs(30))
                    .await
                    .unwrap()
                {
                    netget::state::client_handles::ClientSendOutcome::Executed { detail } => {
                        serde_json::from_str::<serde_json::Value>(&detail).unwrap()
                    }
                    other => panic!("{other:?}"),
                }
            }
        };
        // 8 KiB: nvmet's in-capsule limit decides whether it rides in the capsule or by R2T.
        let r = send(json!({"type": "nvme_tcp_identify_namespace", "nsid": 1})).await;
        let block = r["namespace"]["block_size"].as_u64().unwrap() as usize;
        let r = send(json!({"type": "nvme_tcp_write", "nsid": 1, "lba": 64, "data": "5a".repeat(8192), "encoding": "hex"})).await;
        assert_eq!(r["status"], "SUCCESS", "{r}\n{}", diagnostics(&t));
        let r = send(
            json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 64, "blocks": 8192 / block, "encoding": "hex"}),
        )
        .await;
        assert!(
            r["data"] == "5a".repeat(8192),
            "the 8 KiB read back: {}",
            r["status"]
        );
        let r = send(json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 9000})).await;
        // nvmet's file backend answers a read past the end with CAPACITY EXCEEDED (its
        // -ENOSPC), its block-device backend with LBA OUT OF RANGE; either reaches the model by
        // name, and no data comes with it.
        assert!(
            matches!(
                r["status"].as_str(),
                Some("LBA OUT OF RANGE" | "CAPACITY EXCEEDED")
            ) && r["data"].is_null(),
            "{r}"
        );
        let r = send(json!({"type": "nvme_tcp_identify_controller"})).await;
        assert_eq!(r["controller"]["subsystem_nqn"], t.nqn.as_str(), "{r}");
        // Idle past nvmet's keep-alive timeout: Keep Alive holds the association.
        tokio::time::sleep(Duration::from_millis(7000)).await;
        let r = send(json!({"type": "nvme_tcp_read", "nsid": 1, "lba": 0})).await;
        assert_eq!(r["data"], "digested", "{r}");
        let _ = send(json!({"type": "nvme_tcp_disconnect"})).await;
        let d = std::fs::read(&t.backing[0]).unwrap();
        assert!(d[64 * block..64 * block + 8192].iter().all(|b| *b == 0x5a));
    }

    #[tokio::test]
    async fn the_kernel_target_refuses_a_host_it_does_not_allow() {
        require_root();
        require_nvmet();
        let t = Nvmet::new("refuse", &[(1, disk("private"))], &[&host("refuse")]);
        let login_only = r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'nvme_tcp_connect'}] if i['event_type_id']=='nvme_tcp_connected' else []}))"#;
        let (state, id) = client(
            format!("127.0.0.1:{}", t.tcp_port),
            json!({"host_nqn": "nqn.2026-10.net.netget:stranger", "subsystem_nqn": t.nqn}),
            chain(login_only),
        )
        .await
        .unwrap();
        let refused = wait_event(&state, id, "nvme_tcp_connect_result", 0).await;
        assert_eq!(refused["connected"], false, "{refused}");
        assert!(
            refused["status"]
                .as_str()
                .is_some_and(|s| s.starts_with("CONNECT INVALID HOST")),
            "{refused}\n{}",
            diagnostics(&t)
        );
    }
}
