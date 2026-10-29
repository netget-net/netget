//! NetGet's NVMe/TCP target against SPDK's userspace NVMe/TCP host — a second host
//! implementation, independent of the Linux kernel's: `spdk_nvme_identify` reads the discovery
//! log and identifies the controller and namespaces, `spdk_dd` reads the namespace through
//! SPDK's bdev layer (`bdev_nvme_attach_controller` over TCP) and the bytes are compared with
//! what the model described, and `spdk_nvme_perf` runs a mixed read/write load with several
//! commands outstanding. All without hugepages (`--no-huge`), so no root is needed.
//!
//! Linux, in the `nvme-tcp` pair job, with SPDK built by `scripts/test-peers/build-spdk.sh`.
//! `NETGET_SPDK_DIR` names the SPDK tree (with `build/bin`). The test fails, never skips,
//! when SPDK is missing.
#[cfg(target_os = "linux")]
mod spdk_host {
    use super::super::support::*;
    use std::path::{Path, PathBuf};
    use std::process::Output;
    use std::time::Duration;

    const SPDK_HOST: &str = "nqn.2026-10.net.netget:spdk-host";

    /// The model: disk0 with one writable namespace of 4 MiB (text at 0, a fill at 4096) and
    /// one read-only namespace; the discovery log lists disk0.
    const SPDK_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='nvme_tcp_discovery':
  a=[{'type':'nvme_tcp_discovery_entries','subsystems':[{'nqn':'nqn.2026-10.net.netget:disk0'}]}]
elif e['subsystem_nqn']=='nqn.2026-10.net.netget:disk0':
  a=[{'type':'nvme_tcp_accept_connect','model':'NETGET-BOOT','serial':'SER0001','namespaces':[
    {'nsid':1,'size':4194304,'writable':True,
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}]},
    {'nsid':2,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]}]}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

    /// An SPDK binary, or a failure that says how to get it.
    pub fn spdk_bin(name: &str) -> PathBuf {
        if let Some(dir) = std::env::var_os("NETGET_SPDK_DIR") {
            let p = PathBuf::from(dir).join("build/bin").join(name);
            assert!(p.is_file(), "NETGET_SPDK_DIR has no build/bin/{name}");
            return p;
        }
        for d in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            if d.join(name).is_file() {
                return d.join(name);
            }
        }
        panic!(
            "{name} (SPDK) is not available. It is the second independent host this test exists \
             for. Build SPDK with scripts/test-peers/build-spdk.sh <dir> and set \
             NETGET_SPDK_DIR=<dir>/spdk"
        );
    }

    async fn run(bin: &Path, args: &[&str]) -> Output {
        tokio::time::timeout(
            Duration::from_secs(180),
            tokio::process::Command::new(bin)
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap_or_else(|_| panic!("{} {args:?} did not finish in 180 s", bin.display()))
        .unwrap_or_else(|e| panic!("running {}: {e}", bin.display()))
    }

    fn text(o: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    fn trid(port: u16, subnqn: &str) -> String {
        format!(
            "trtype:tcp adrfam:IPv4 traddr:127.0.0.1 trsvcid:{port} subnqn:{subnqn} hostnqn:{SPDK_HOST}"
        )
    }

    /// One line's value from `spdk_nvme_identify`'s output: `Label: value`.
    fn field<'a>(out: &'a str, label: &str) -> Vec<&'a str> {
        out.lines()
            .filter_map(|l| l.trim().strip_prefix(label))
            .map(|v| v.trim_start_matches(':').trim())
            .collect()
    }

    const SECURE: &str = "nqn.2026-10.net.netget:spdk-secure";

    /// The model for SPDK's authenticated runs: SECURE requires DH-HMAC-CHAP.
    const SPDK_AUTH_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='nvme_tcp_connect' and e['subsystem_nqn']=='nqn.2026-10.net.netget:spdk-secure':
  a=[{'type':'nvme_tcp_accept_connect','require_authentication':True,'namespaces':[
    {'nsid':1,'size':4194304,'writable':True,'extents':[{'offset':0,'text':'authenticated by spdk'}]}]}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

    /// A DH-HMAC-CHAP secret from nvme-cli's `gen-dhchap-key`, in a file only its owner may
    /// read (SPDK's file keyring refuses any other): (path, the secret).
    fn key_file(dir: &Path, name: &str, hmac: u8, len: u32, nqn: &str) -> (String, String) {
        use std::os::unix::fs::PermissionsExt;
        let nvme = ["/usr/sbin/nvme", "/usr/bin/nvme", "/sbin/nvme"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect(
                "nvme (nvme-cli) is not installed; it generates the secrets SPDK is given: \
                 apt-get install nvme-cli",
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

    /// spdk_nvme_perf authenticates (`--dhchap-key`, and `--dhchap-ctrlr-key` to make NetGet
    /// prove itself) before its load runs; a key NetGet does not hold is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spdk_perf_authenticates_to_netget_one_way_and_both_ways() {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter("netget=info")
            .try_init();
        let perf = spdk_bin("spdk_nvme_perf");
        let dir = tempfile::tempdir().unwrap();
        let (host_path, host_key) = key_file(dir.path(), "host.key", 1, 32, SPDK_HOST);
        let (ctrl_path, ctrl_key) = key_file(dir.path(), "ctrl.key", 3, 64, SECURE);
        let (wrong_path, _) = key_file(dir.path(), "wrong.key", 1, 32, SPDK_HOST);
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(SPDK_AUTH_POLICY),
            Some(serde_json::json!({
                "dhchap_secret": host_key,
                "dhchap_ctrl_secret": ctrl_key,
                "dhchap_hashes": "sha512,sha256",
                "dhchap_dhgroups": "ffdhe3072,null",
            })),
        )
        .await;
        for (keys, ok, expect) in [
            (vec!["--dhchap-key", host_path.as_str()], true, "checks out"),
            (
                vec![
                    "--dhchap-key",
                    host_path.as_str(),
                    "--dhchap-ctrlr-key",
                    ctrl_path.as_str(),
                ],
                true,
                "authenticated both ways",
            ),
            (
                vec!["--dhchap-key", wrong_path.as_str()],
                false,
                "does not match the configured secret",
            ),
        ] {
            let mut args = vec![
                "--no-huge".to_string(),
                "-s".into(),
                "512".into(),
                "-r".into(),
                format!("{} ns:1", trid(srv.port, SECURE)),
                "-q".into(),
                "4".into(),
                "-o".into(),
                "4096".into(),
                "-w".into(),
                "randread".into(),
                "-t".into(),
                "1".into(),
            ];
            args.extend(keys.iter().map(|s| s.to_string()));
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = run(&perf, &a).await;
            let o = text(&out);
            println!("spdk_nvme_perf {keys:?}:\n{o}");
            assert_eq!(out.status.success(), ok, "{o}\n{:#?}", srv.logs());
            if ok {
                assert!(o.contains("Total"), "{o}");
            }
            assert!(
                srv.logs()
                    .iter()
                    .any(|l| l.contains("operation=authenticate") && l.contains(expect)),
                "NetGet logged {expect:?}: {:#?}",
                srv.logs()
            );
        }
        for line in srv.commands() {
            println!("SPDK sent: {line}");
        }
        let admin: Vec<String> = srv
            .commands()
            .into_iter()
            .filter(|l| l.contains("queue 0 of"))
            .collect();
        assert!(
            admin
                .iter()
                .filter(|l| l.contains("Authentication Send x3"))
                .count()
                == 1
                && admin.iter().any(|l| l.contains("Authentication Send x2")),
            "SPDK's one-way exchange is two sends, its two-way three: {admin:#?}"
        );
        let secrets = [host_key, ctrl_key];
        for l in srv.logs() {
            for s in &secrets {
                assert!(
                    !l.contains(s.split(':').nth(2).unwrap()),
                    "a secret in the log: {l}"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spdk_identifies_reads_and_loads_the_described_namespaces() {
        // The target's own decisions on stderr, so a failure here shows both sides.
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter("netget=info")
            .try_init();
        let identify = spdk_bin("spdk_nvme_identify");
        let dd = spdk_bin("spdk_dd");
        let perf = spdk_bin("spdk_nvme_perf");
        let srv = start_on("127.0.0.1", 0, policy(SPDK_POLICY), None).await;

        // The discovery log, through SPDK's discovery controller code.
        let out = run(
            &identify,
            &["--no-huge", "-s", "256", "-r", &trid(srv.port, DISCOVERY)],
        )
        .await;
        let o = text(&out);
        assert!(out.status.success(), "{o}");
        assert!(
            field(&o, "NVM Subsystem Qualified Name").contains(&DISK0),
            "SPDK reads the discovery log: {o}"
        );

        // Identify Controller and both namespaces.
        let out = run(
            &identify,
            &["--no-huge", "-s", "256", "-r", &trid(srv.port, DISK0)],
        )
        .await;
        let o = text(&out);
        assert!(out.status.success(), "{o}");
        assert_eq!(field(&o, "Model Number"), ["NETGET-BOOT"], "{o}");
        assert_eq!(field(&o, "Serial Number"), ["SER0001"], "{o}");
        assert!(field(&o, "Subsystem NQN").contains(&DISK0), "{o}");
        let sizes: Vec<&str> = field(&o, "Size (in LBAs)")
            .into_iter()
            .map(|v| v.split_whitespace().next().unwrap_or(""))
            .collect();
        assert_eq!(sizes, ["8192", "512"], "{o}");
        let connects = events(&srv.state, srv.id, "nvme_tcp_connect").await;
        // spdk_nvme_identify connects under its own host NQN, whatever the transport ID says.
        assert_eq!(connects.len(), 1, "one model call for SPDK's association");
        println!(
            "spdk_nvme_identify connected as {}",
            connects[0]["host_nqn"]
        );

        // The first 8 KiB of namespace 1 through SPDK's bdev layer.
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("bdev.json");
        std::fs::write(
            &conf,
            serde_json::json!({"subsystems": [{"subsystem": "bdev", "config": [
                {"method": "bdev_nvme_attach_controller", "params": {
                    "name": "Nvme0", "trtype": "tcp", "adrfam": "ipv4", "traddr": "127.0.0.1",
                    "trsvcid": srv.port.to_string(), "subnqn": DISK0, "hostnqn": SPDK_HOST}}]}]})
            .to_string(),
        )
        .unwrap();
        let file = dir.path().join("ns1.bin");
        let out = run(
            &dd,
            &[
                "--no-huge",
                "-s",
                "512",
                "--json",
                &conf.display().to_string(),
                "--ib",
                "Nvme0n1",
                "--of",
                &file.display().to_string(),
                "--bs",
                "4096",
                "--count",
                "2",
            ],
        )
        .await;
        assert!(out.status.success(), "{}", text(&out));
        let d = std::fs::read(&file).unwrap();
        assert_eq!(d.len(), 8192, "{}", text(&out));
        assert_eq!(&d[..17], b"hello from netget");
        assert!(d[17..4096].iter().all(|b| *b == 0));
        assert!(d[4096..4608].iter().all(|b| *b == 0xAB));
        assert!(d[4608..].iter().all(|b| *b == 0));

        // A mixed random read/write load, 16 commands outstanding, for two seconds.
        let out = run(
            &perf,
            &[
                "--no-huge",
                "-s",
                "512",
                "-r",
                &format!("{} ns:1", trid(srv.port, DISK0)),
                "-q",
                "16",
                "-o",
                "8192",
                "-w",
                "randrw",
                "-M",
                "50",
                "-t",
                "2",
            ],
        )
        .await;
        let o = text(&out);
        assert!(out.status.success(), "{o}");
        assert!(
            o.contains("Total"),
            "spdk_nvme_perf reports its totals: {o}"
        );
        // Nothing failed while the load ran. After the totals, SPDK logs "CQ transport error
        // -6" for its own I/O qpair as it frees it: a capture shows SPDK sending its FIN first
        // and the target answering with its own, so that line is SPDK's teardown, not a fault.
        let (during, after) = o.split_at(o.find("Total").unwrap_or(o.len()));
        assert!(
            !during.to_ascii_lowercase().contains("error"),
            "no command failed under load: {o}"
        );
        assert!(
            after
                .lines()
                .filter(|l| l.to_ascii_lowercase().contains("error"))
                .all(|l| l.contains("qid:1") && l.contains("CQ transport error -6")),
            "nothing failed but SPDK's own I/O qpair teardown: {o}"
        );
    }

    /// spdk_nvme_perf runs its load inside a TLS 1.3 secure channel: SPDK parses the
    /// interchange key itself (`--psk-path`), derives the retained and TLS PSKs and offers a
    /// version 0 identity through its OpenSSL socket — none of it NetGet's code. A key NetGet does
    /// not hold never gets past the handshake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spdk_perf_runs_inside_a_tls_secure_channel() {
        use netget::server::nvme_tcp::auth::Hash;
        use netget::server::nvme_tcp::tls_psk::ConfiguredKey;
        use std::os::unix::fs::PermissionsExt;
        let perf = spdk_bin("spdk_nvme_perf");
        let dir = tempfile::tempdir().unwrap();
        let mut raw = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
        let key = ConfiguredKey::text(&raw, Some(Hash::Sha256));
        let wrong = ConfiguredKey::text(&[raw[0] ^ 1; 32], Some(Hash::Sha256));
        // SPDK's file keyring refuses a key file anyone but its owner can read.
        let write_key = |name: &str, text: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p.display().to_string()
        };
        let good = write_key("tls.key", &key);
        let bad = write_key("wrong.key", &wrong);
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(SPDK_POLICY),
            Some(serde_json::json!({"tls_key": key})),
        )
        .await;
        for (path, ok) in [(&good, true), (&bad, false)] {
            let args = [
                "--no-huge",
                "-s",
                "512",
                "-r",
                &format!("{} ns:1", trid(srv.port, DISK0)),
                "-q",
                "4",
                "-o",
                "4096",
                "-w",
                "randrw",
                "-M",
                "50",
                "-t",
                "1",
                "-S",
                "ssl",
                "--psk-path",
                path,
            ];
            let out = run(&perf, &args).await;
            let o = text(&out);
            println!("spdk_nvme_perf --psk-path {path}:\n{o}");
            assert_eq!(out.status.success(), ok, "{o}\n{:#?}", srv.logs());
            if ok {
                assert!(o.contains("Total"), "{o}");
            }
        }
        let logs = srv.logs();
        assert!(
            logs.iter().any(|l| l.contains(&format!(
                "operation=tls decision=protocol_accept TLS 1.3 secure channel, PSK identity NVMe0R01 {SPDK_HOST} {DISK0}"
            ))),
            "SPDK's version 0 identity was accepted: {logs:#?}"
        );
        assert!(
            logs.iter()
                .any(|l| l.contains("decision=fail_closed_tls")),
            "the wrong key was refused at the handshake: {logs:#?}"
        );
    }
}
