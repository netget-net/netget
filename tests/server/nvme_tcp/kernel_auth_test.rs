//! NetGet's NVMe/TCP target against the Linux kernel's NVMe/TCP host for what came after the
//! first landing: DH-HMAC-CHAP in-band authentication (unidirectional with every hash and DH
//! group, bidirectional, and the failures each side must refuse), and nvme-cli's Compare,
//! Verify, Copy and reservation commands on a connected namespace, with a second host — the raw
//! host of `support.rs` — holding a reservation the kernel then runs into.
//!
//! The secrets are made by nvme-cli's own `gen-dhchap-key`, so NetGet parses what the kernel's
//! tooling writes. What the kernel concluded is read from its log (`qid 0: authenticated with
//! hash … dhgroup …`, `qid 0: controller authenticated`, `authentication failed`) after a marker
//! this test writes to /dev/kmsg, and what each queue sent from the target's own count.
//!
//! Linux, as root, with `nvme-tcp` loaded (the kernel's DH-HMAC-CHAP needs CONFIG_NVME_AUTH):
//! the `nvme-tcp` pair job runs this binary through sudo. Every test fails, never skips, when
//! nvme-cli, root or the module is missing. Each test has its own subsystem NQNs, host NQN and
//! target, so they run in parallel.
#[cfg(target_os = "linux")]
mod kernel_host_auth {
    use super::super::real_client_test::kernel_host::*;
    use super::super::support::*;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const AUTH_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
ns=[{'nsid':1,'size':4194304,'writable':True,
     'extents':[{'offset':0,'text':'authenticated by the kernel'},{'offset':4096,'length':512,'fill':171}]}]
if ':kcmd-' in e.get('subsystem_nqn',''):
  ns[0]['errors']=[{'offset':2097152,'length':4096,'error':'medium_error'}]
if t=='nvme_tcp_connect' and ':kauth-' in e['subsystem_nqn']:
  a=[{'type':'nvme_tcp_accept_connect','require_authentication':True,'namespaces':ns}]
elif t=='nvme_tcp_connect' and ':kcmd-' in e['subsystem_nqn']:
  a=[{'type':'nvme_tcp_accept_connect','namespaces':ns}]
elif t=='nvme_tcp_reservation' and e['operation']=='preempt_and_abort':
  a=[{'type':'nvme_tcp_refuse_reservation'}]
elif t=='nvme_tcp_reservation':
  a=[{'type':'nvme_tcp_allow_reservation'}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

    fn host_nqn(tag: &str) -> String {
        format!("nqn.2026-10.net.netget:khost-{tag}-{}", std::process::id())
    }

    /// A host ID of the test's own: the kernel refuses one host ID under two host NQNs, and the
    /// tests run at once.
    fn host_id(host_nqn: &str) -> String {
        let h = crc32(host_nqn.as_bytes());
        format!(
            "4e0c7b55-2d71-4f3a-9a64-{:04x}{h:08x}",
            std::process::id() & 0xFFFF
        )
    }

    fn subsys(kind: &str, tag: &str) -> String {
        format!("nqn.2026-10.net.netget:{kind}-{tag}-{}", std::process::id())
    }

    /// A secret from nvme-cli's own generator: `-m` the transformation hash, `-l` the key
    /// length, `-n` the NQN it is transformed with.
    async fn gen_key(nvme: &Path, hmac: u8, len: u32, nqn: &str) -> String {
        let out = run(
            nvme,
            &[
                "gen-dhchap-key",
                "-m",
                &hmac.to_string(),
                "-l",
                &len.to_string(),
                "-n",
                nqn,
            ],
        )
        .await;
        let key = text(&out.stdout).trim().to_string();
        assert!(
            out.status.success() && key.starts_with("DHHC-1:"),
            "nvme gen-dhchap-key: {key}{}",
            text(&out.stderr)
        );
        key
    }

    /// Write a marker into the kernel log; [`since`] returns what the kernel logged after it.
    fn mark(tag: &str) -> String {
        let marker = format!("netget-nvme-test {tag} {}", std::process::id());
        std::fs::write("/dev/kmsg", format!("{marker}\n")).expect("writing /dev/kmsg");
        marker
    }

    fn since(marker: &str) -> String {
        let all = std::process::Command::new("dmesg")
            .output()
            .map(|o| text(&o.stdout))
            .unwrap_or_default();
        match all.rfind(marker) {
            Some(at) => all[at..].to_string(),
            None => String::new(),
        }
    }

    /// Disconnects a subsystem when the test ends, however it ends.
    struct Gone(PathBuf, String);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::process::Command::new(&self.0)
                .args(["disconnect", "-n", &self.1])
                .output();
        }
    }

    async fn connect(
        nvme: &Path,
        port: u16,
        subnqn: &str,
        host: &str,
        extra: &[&str],
    ) -> std::process::Output {
        let port = port.to_string();
        let hostid = host_id(host);
        let mut args = vec![
            "connect",
            "-t",
            "tcp",
            "-a",
            "127.0.0.1",
            "-s",
            &port,
            "-n",
            subnqn,
            "-q",
            host,
            "-I",
            &hostid,
        ];
        args.extend_from_slice(extra);
        run(nvme, &args).await
    }

    /// The namespace block device of a connected subsystem, once the kernel made it.
    async fn namespace(nvme: &Path, subnqn: &str) -> (String, PathBuf) {
        settle().await;
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            let (ctrls, ns) = devices(subnqn);
            if !ctrls.is_empty() && !ns.is_empty() {
                return (ctrls[0].clone(), PathBuf::from(format!("/dev/{}", ns[0].1)));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("no namespace for {subnqn}\n{}", diagnostics(nvme).await);
    }

    async fn disconnect(nvme: &Path, subnqn: &str) {
        let out = run(nvme, &["disconnect", "-n", subnqn]).await;
        assert!(
            out.status.success(),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        let started = std::time::Instant::now();
        while subsystem_dir(subnqn).is_some() && started.elapsed() < Duration::from_secs(20) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn print_commands(srv: &Started, what: &str) {
        for line in srv.commands() {
            println!("{what}: {line}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_kernel_host_authenticates_with_every_hash_and_dh_group() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let host = host_nqn("every");
        for (i, (hash, group, len, hmac)) in [
            ("sha256", "null", 32u32, 1u8),
            ("sha384", "ffdhe2048", 48, 2),
            ("sha512", "ffdhe3072", 64, 3),
            ("sha256", "ffdhe4096", 48, 0),
            ("sha384", "ffdhe6144", 32, 1),
            ("sha512", "ffdhe8192", 64, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let secret = gen_key(&nvme, hmac, len, &host).await;
            let srv = start_on(
                "127.0.0.1",
                0,
                policy(AUTH_POLICY),
                Some(serde_json::json!({
                    "dhchap_secret": secret,
                    "dhchap_hashes": hash,
                    "dhchap_dhgroups": group,
                })),
            )
            .await;
            let nqn = subsys("kauth", &format!("every{i}"));
            let _gone = Gone(nvme.clone(), nqn.clone());
            let marker = mark(&nqn);
            let dhchap = format!("--dhchap-secret={secret}");
            let out = connect(&nvme, srv.port, &nqn, &host, &[&dhchap]).await;
            if !out.status.success() {
                panic!(
                    "nvme connect with {hash}/{group}: {}{}\ntarget: {:#?}\nkernel since the marker:\n{}",
                    text(&out.stdout),
                    text(&out.stderr),
                    srv.logs(),
                    since(&marker)
                );
            }
            let (ctrl, ns) = namespace(&nvme, &nqn).await;
            let p = ns.clone();
            let data = until_ok("reading the namespace", move || read_direct(&p, 0, 4096))
                .await
                .unwrap();
            assert_eq!(&data[..27], b"authenticated by the kernel");
            let kernel = since(&marker);
            println!("kernel ({hash}, {group}, key {len} bytes, transform {hmac}):\n{kernel}");
            let expect =
                format!("{ctrl}: qid 0: authenticated with hash hmac({hash}) dhgroup {group}");
            assert!(
                kernel.contains(&expect),
                "the kernel says {expect:?}:\n{kernel}"
            );
            assert!(
                kernel.contains(&format!("{ctrl}: qid 0: authenticated\n"))
                    || kernel.contains(&format!("{ctrl}: qid 0: authenticated"))
            );
            let decisions: Vec<String> = srv
                .logs()
                .into_iter()
                .filter(|l| l.contains("operation=authenticate"))
                .collect();
            assert!(
                decisions
                    .iter()
                    .any(|l| l.contains("checks out") && l.contains(hash)),
                "{decisions:#?}"
            );
            disconnect(&nvme, &nqn).await;
            print_commands(&srv, &format!("{hash}/{group}"));
            let all = srv.commands_once_admin_closed().await.join("\n");
            assert!(
                all.contains("Authentication Send x2") && all.contains("Authentication Receive x2"),
                "the kernel's unidirectional exchange is two sends and two receives: {all}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_kernel_host_and_netget_authenticate_each_other() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let host = host_nqn("bidi");
        let nqn = subsys("kauth", "bidi");
        let secret = gen_key(&nvme, 1, 32, &host).await;
        let ctrl_secret = gen_key(&nvme, 2, 48, &nqn).await;
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(AUTH_POLICY),
            Some(serde_json::json!({
                "dhchap_secret": secret,
                "dhchap_ctrl_secret": ctrl_secret,
                "dhchap_hashes": "sha384",
                "dhchap_dhgroups": "ffdhe2048",
            })),
        )
        .await;
        let _gone = Gone(nvme.clone(), nqn.clone());
        let marker = mark(&nqn);
        let a = format!("--dhchap-secret={secret}");
        let b = format!("--dhchap-ctrl-secret={ctrl_secret}");
        let out = connect(&nvme, srv.port, &nqn, &host, &[&a, &b]).await;
        if !out.status.success() {
            panic!(
                "nvme connect: {}{}\ntarget: {:#?}\nkernel:\n{}",
                text(&out.stdout),
                text(&out.stderr),
                srv.logs(),
                since(&marker)
            );
        }
        let (ctrl, ns) = namespace(&nvme, &nqn).await;
        let data = until_ok("reading", move || read_direct(&ns, 0, 512))
            .await
            .unwrap();
        assert_eq!(&data[..27], b"authenticated by the kernel");
        let kernel = since(&marker);
        println!("kernel:\n{kernel}");
        assert!(
            kernel.contains(&format!(
                "{ctrl}: qid 0: authenticated with hash hmac(sha384) dhgroup ffdhe2048"
            )),
            "{kernel}"
        );
        assert!(
            kernel.contains(&format!("{ctrl}: qid 0: controller authenticated")),
            "the kernel checked R2:\n{kernel}"
        );
        assert!(
            srv.logs()
                .iter()
                .any(|l| l.contains("authenticated both ways")),
            "{:#?}",
            srv.logs()
        );
        disconnect(&nvme, &nqn).await;
        print_commands(&srv, "bidirectional");
        let all = srv.commands_once_admin_closed().await.join("\n");
        assert!(
            all.contains("Authentication Send x3"),
            "negotiate, reply and success2: {all}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_kernel_host_is_refused_with_the_wrong_secret_and_refuses_the_wrong_controller() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let host = host_nqn("wrong");
        let secret = gen_key(&nvme, 1, 32, &host).await;
        let other = gen_key(&nvme, 1, 32, &host).await;
        let nqn_ctrl = subsys("kauth", "wrongctrl");
        let ctrl_secret = gen_key(&nvme, 0, 32, &nqn_ctrl).await;
        let other_ctrl = gen_key(&nvme, 0, 32, &nqn_ctrl).await;
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(AUTH_POLICY),
            Some(serde_json::json!({
                "dhchap_secret": secret,
                "dhchap_ctrl_secret": ctrl_secret,
                "dhchap_dhgroups": "ffdhe2048,null",
            })),
        )
        .await;

        // The host's secret is not the one NetGet holds: NetGet refuses it.
        let nqn = subsys("kauth", "wronghost");
        let _g1 = Gone(nvme.clone(), nqn.clone());
        let marker = mark(&nqn);
        let a = format!("--dhchap-secret={other}");
        let out = connect(&nvme, srv.port, &nqn, &host, &[&a]).await;
        let kernel = since(&marker);
        println!(
            "wrong host secret: {}{}\nkernel:\n{kernel}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(!out.status.success(), "the connect fails");
        assert!(kernel.contains("qid 0: authentication failed"), "{kernel}");
        assert!(subsystem_dir(&nqn).is_none() || devices(&nqn).1.is_empty());
        assert!(
            srv.logs()
                .iter()
                .any(|l| l.contains("does not match the configured secret")),
            "{:#?}",
            srv.logs()
        );

        // NetGet proves a controller secret the host does not hold: the host refuses NetGet.
        let _g2 = Gone(nvme.clone(), nqn_ctrl.clone());
        let marker = mark(&nqn_ctrl);
        let a = format!("--dhchap-secret={secret}");
        let b = format!("--dhchap-ctrl-secret={other_ctrl}");
        let out = connect(&nvme, srv.port, &nqn_ctrl, &host, &[&a, &b]).await;
        let kernel = since(&marker);
        println!(
            "wrong controller secret: {}{}\nkernel:\n{kernel}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(!out.status.success());
        assert!(
            kernel.contains("qid 0: controller authentication failed"),
            "{kernel}"
        );
        assert!(
            srv.logs().iter().any(|l| l.contains("AUTH_Failure2")),
            "NetGet saw the host refuse it: {:#?}",
            srv.logs()
        );

        // No secret at all: the kernel cannot answer the ATR and the controller never comes up.
        let nqn = subsys("kauth", "nosecret");
        let _g3 = Gone(nvme.clone(), nqn.clone());
        let marker = mark(&nqn);
        let out = connect(&nvme, srv.port, &nqn, &host, &[]).await;
        println!(
            "no secret: {}{}\nkernel:\n{}",
            text(&out.stdout),
            text(&out.stderr),
            since(&marker)
        );
        assert!(!out.status.success());
        print_commands(&srv, "refusals");
        let secrets = [&secret, &other, &ctrl_secret, &other_ctrl];
        for l in srv.logs() {
            for s in secrets {
                let key = s.split(':').nth(2).unwrap();
                assert!(!l.contains(key), "a secret in the target's log: {l}");
            }
        }
    }

    /// The raw host of `support.rs`, as a second host of the same subsystem.
    async fn raw_host(port: u16, subnqn: &str) -> (Raw, Raw, u16) {
        let id: [u8; 16] = [0xC3; 16];
        let hn = "nqn.2026-10.org.example:raw-second-host";
        let mut admin = Raw::connect(port).await;
        let cntlid = admin.admin_session_as(subnqn, hn, &id).await;
        let mut io = Raw::connect(port).await;
        assert!(io.io_session_as(cntlid, subnqn, hn, &id).await.ok());
        (admin, io, cntlid)
    }

    /// Commands by name over every queue of the target but `skip`'s controller.
    fn totals(srv: &Started, skip: Option<u16>) -> std::collections::BTreeMap<String, u64> {
        let mut t = std::collections::BTreeMap::new();
        for line in srv.commands() {
            if skip.is_some_and(|c| line.contains(&format!("of controller {c} received"))) {
                continue;
            }
            let Some((_, list)) = line.split_once("received: ") else {
                continue;
            };
            for item in list.split(", ") {
                if let Some((name, n)) = item.rsplit_once(" x") {
                    *t.entry(name.to_string()).or_default() += n.trim().parse::<u64>().unwrap_or(0);
                }
            }
        }
        t
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nvme_cli_compares_verifies_copies_and_reserves_through_the_kernel() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let host = host_nqn("cmds");
        let nqn = subsys("kcmd", "io");
        let srv = start_on("127.0.0.1", 0, policy(AUTH_POLICY), None).await;
        let _gone = Gone(nvme.clone(), nqn.clone());
        let out = connect(&nvme, srv.port, &nqn, &host, &[]).await;
        assert!(
            out.status.success(),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        let (_, ns) = namespace(&nvme, &nqn).await;
        let dev = ns.display().to_string();
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, data: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, data).unwrap();
            p.display().to_string()
        };
        let cli = |args: Vec<String>| {
            let nvme = nvme.clone();
            async move {
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let o = run(&nvme, &a).await;
                println!(
                    "$ nvme {}\n{}{}",
                    args.join(" "),
                    text(&o.stdout),
                    text(&o.stderr)
                );
                o
            }
        };
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // Compare: the described bytes match, one changed byte is COMPARE FAILURE.
        let mut block = b"authenticated by the kernel".to_vec();
        block.resize(512, 0);
        let same = file("same", &block);
        let o = cli(s(&[
            "compare", &dev, "-n", "1", "-s", "0", "-c", "0", "-z", "512", "-d", &same,
        ]))
        .await;
        assert!(o.status.success());
        block[0] ^= 1;
        let diff = file("diff", &block);
        let o = cli(s(&[
            "compare", &dev, "-n", "1", "-s", "0", "-c", "0", "-z", "512", "-d", &diff,
        ]))
        .await;
        assert!(!o.status.success());
        assert!(
            text(&o.stderr).to_uppercase().contains("COMPARE"),
            "nvme-cli names the miscompare"
        );

        // Verify: readable blocks pass, the medium error does not.
        assert!(cli(s(&["verify", &dev, "-n", "1", "-s", "0", "-c", "15"]))
            .await
            .status
            .success());
        let o = cli(s(&["verify", &dev, "-n", "1", "-s", "4096", "-c", "7"])).await;
        assert!(!o.status.success());

        // Copy: blocks 0 and 8 to 200, read back through the block device.
        let o = cli(s(&[
            "copy",
            &dev,
            "-n",
            "1",
            "--sdlba=200",
            "--slbs=0,8",
            "--blocks=0,0",
        ]))
        .await;
        assert!(o.status.success());
        let p = ns.clone();
        let d = until_ok("reading the copy", move || read_direct(&p, 200 * 512, 1024))
            .await
            .unwrap();
        assert_eq!(&d[..27], b"authenticated by the kernel");
        assert!(d[512..].iter().all(|b| *b == 0xAB));

        // Reservations: register and acquire Write Exclusive, report it (extended only).
        assert!(cli(s(&[
            "resv-register",
            &dev,
            "--namespace-id=1",
            "--nrkey=0xA1",
            "--rrega=0"
        ]))
        .await
        .status
        .success());
        assert!(cli(s(&[
            "resv-acquire",
            &dev,
            "--namespace-id=1",
            "--crkey=0xA1",
            "--rtype=1",
            "--racqa=0"
        ]))
        .await
        .status
        .success());
        let o = cli(s(&[
            "resv-report",
            &dev,
            "--namespace-id=1",
            "--eds",
            "-o",
            "json",
        ]))
        .await;
        assert!(o.status.success());
        let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(r["rtype"], 1, "{r}");
        assert_eq!(r["regctl"], 1, "{r}");
        let entry = &r["regctlext"][0];
        assert_eq!(entry["rkey"], 0xA1, "{r}");
        assert_eq!(entry["rcsts"], 1, "{r}");
        let o = cli(s(&["resv-report", &dev, "--namespace-id=1", "-o", "json"])).await;
        assert!(
            !o.status.success(),
            "without --eds the 64-bit host ID format is refused"
        );

        // A second host (the raw host) sees the kernel's reservation: it reads, it may not write.
        let (_ra, mut rio, raw_cntlid) = raw_host(srv.port, &nqn).await;
        assert!(rio.read(1, 0, 1, 512).await.1.ok());
        let mut w = vec![0u8; 512];
        w[..5].copy_from_slice(b"raw!!");
        assert_eq!(
            rio.write_in_capsule(1, 300, &w, 512).await.sc(),
            RESERVATION_CONFLICT
        );
        // The kernel releases; the raw host takes Exclusive Access; the kernel is shut out.
        assert!(cli(s(&[
            "resv-release",
            &dev,
            "--namespace-id=1",
            "--crkey=0xA1",
            "--rtype=1",
            "--rrela=0"
        ]))
        .await
        .status
        .success());
        // Register (CRKEY 0, NRKEY C5h), then acquire with CRKEY C5h.
        let mut d = 0u64.to_le_bytes().to_vec();
        d.extend(0xC5u64.to_le_bytes());
        let reg = Sqe::new(0x0D, 1).cdw(10, 0).in_capsule(16);
        assert!(rio.cmd(&reg, &d).await.1.ok());
        let mut d = 0xC5u64.to_le_bytes().to_vec();
        d.extend(0u64.to_le_bytes());
        let acq = Sqe::new(0x11, 1).cdw(10, 2 << 8).in_capsule(16);
        assert!(rio.cmd(&acq, &d).await.1.ok());
        let o = cli(s(&[
            "read",
            &dev,
            "-n",
            "1",
            "-s",
            "0",
            "-c",
            "0",
            "-z",
            "512",
            "-d",
            &dir.path().join("out").display().to_string(),
        ]))
        .await;
        assert!(!o.status.success());
        assert!(
            text(&o.stderr).to_uppercase().contains("RESERVATION"),
            "nvme-cli names the conflict"
        );
        // The model refuses the kernel's preempt-and-abort; it allows the preempt.
        let o = cli(s(&[
            "resv-acquire",
            &dev,
            "--namespace-id=1",
            "--crkey=0xA1",
            "--prkey=0xC5",
            "--rtype=1",
            "--racqa=2",
        ]))
        .await;
        assert!(!o.status.success());
        let o = cli(s(&[
            "resv-acquire",
            &dev,
            "--namespace-id=1",
            "--crkey=0xA1",
            "--prkey=0xC5",
            "--rtype=1",
            "--racqa=1",
        ]))
        .await;
        assert!(o.status.success());
        assert!(
            rio.read(1, 0, 1, 512).await.1.ok(),
            "under Write Exclusive the raw host reads"
        );
        assert!(cli(s(&[
            "resv-release",
            &dev,
            "--namespace-id=1",
            "--crkey=0xA1",
            "--rrela=1"
        ]))
        .await
        .status
        .success());

        let ops: Vec<String> = events(&srv.state, srv.id, "nvme_tcp_reservation")
            .await
            .iter()
            .map(|e| {
                format!(
                    "{} by {}",
                    e["operation"].as_str().unwrap(),
                    e["host_nqn"].as_str().unwrap()
                )
            })
            .collect();
        println!("reservation decisions asked of the model: {ops:#?}");
        let names: Vec<&str> = ops.iter().map(|o| o.split(' ').next().unwrap()).collect();
        assert_eq!(
            names,
            [
                "register",
                "acquire",
                "release",
                "register",
                "acquire",
                "preempt_and_abort",
                "preempt",
                "clear"
            ],
            "each change the kernel and the raw host asked for, and nothing else: {ops:#?}"
        );
        drop((_ra, rio));
        disconnect(&nvme, &nqn).await;
        print_commands(&srv, "nvme-cli");
        let kernel = totals(&srv, Some(raw_cntlid));
        println!("the kernel host sent, over all its queues: {kernel:#?}");
        for (c, n) in [
            ("Compare", 2),
            ("Verify", 2),
            ("Copy", 1),
            ("Reservation Register", 1),
            ("Reservation Acquire", 3),
            ("Reservation Release", 2),
            ("Reservation Report", 2),
        ] {
            assert_eq!(
                kernel.get(c).copied(),
                Some(n),
                "the kernel sent {c}: {kernel:#?}"
            );
        }
    }
}
