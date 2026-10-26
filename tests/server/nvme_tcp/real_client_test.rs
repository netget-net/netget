//! NetGet's NVMe/TCP target against the Linux kernel's NVMe/TCP host (`nvme-tcp`, driven by
//! nvme-cli): `nvme discover` reads the discovery log, `nvme connect` makes an association
//! with an admin queue and an I/O queue per CPU, the kernel identifies the controller and
//! scans the namespaces, and the block devices it makes are read (and written, with O_DIRECT)
//! and compared with what the model described. `nvme id-ctrl`, `nvme id-ns` and `nvme
//! smart-log` are checked against the description, then `nvme disconnect` shuts it down.
//!
//! Linux, as root, with the `nvme-tcp` module loaded: the `nvme-tcp` pair job runs this binary
//! through sudo. The test fails, never skips, when nvme-cli, root or the module is missing.
#[cfg(target_os = "linux")]
pub mod kernel_host {
    use super::super::support::*;
    use std::path::{Path, PathBuf};
    use std::process::Output;
    use std::time::Duration;

    /// The model for the kernel: disk0 as in `POLICY`, its first namespace writable, its second
    /// read-only; the discovery log lists disk0 at this listener.
    pub const REAL_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='nvme_tcp_discovery':
  a=[{'type':'nvme_tcp_discovery_entries','subsystems':[{'nqn':'nqn.2026-10.net.netget:disk0'}]}]
elif e['subsystem_nqn']=='nqn.2026-10.net.netget:disk0':
  a=[{'type':'nvme_tcp_accept_connect','model':'NETGET-BOOT','serial':'SER0001','firmware':'NG1','namespaces':[
    {'nsid':1,'size':4194304,'writable':True,
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}]},
    {'nsid':2,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]}]}]
else:
  a=[{'type':'nvme_tcp_reject_connect','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

    pub const KERNEL_HOST: &str = "nqn.2026-10.net.netget:kernel-host";
    pub const KERNEL_HOSTID: &str = "4e0c7b55-2d71-4f3a-9a64-6f2b1c0d8e93";

    pub fn require_root() {
        assert!(
            unsafe { libc::geteuid() } == 0, // SAFETY: geteuid has no preconditions.
            "the kernel host needs root (nvme connect writes /dev/nvme-fabrics and the kernel \
             makes block devices): the nvme-tcp pair job runs this binary through sudo"
        );
    }

    /// nvme-cli on PATH or in /usr/sbin, or a failure that says how to install it.
    pub fn nvme_cli() -> PathBuf {
        let mut dirs: Vec<PathBuf> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
        dirs.extend(["/usr/sbin".into(), "/sbin".into(), "/usr/bin".into()]);
        for d in dirs {
            let p = d.join("nvme");
            if p.is_file() {
                return p;
            }
        }
        panic!(
            "nvme (nvme-cli) is not installed. It drives the independent host this test exists \
             for, and skipping would leave the NVMe/TCP target's evidence resting on NetGet's \
             own host. Install it with: apt-get install nvme-cli (and modprobe nvme-tcp)"
        );
    }

    pub fn require_module() {
        assert!(
            Path::new("/dev/nvme-fabrics").exists() && Path::new("/sys/module/nvme_tcp").exists(),
            "the nvme-tcp kernel module is not loaded (no /dev/nvme-fabrics or \
             /sys/module/nvme_tcp): modprobe nvme-tcp, from linux-modules-extra-$(uname -r) on \
             Ubuntu"
        );
    }

    pub async fn run(bin: &Path, args: &[&str]) -> Output {
        tokio::time::timeout(
            Duration::from_secs(120),
            tokio::process::Command::new(bin)
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap_or_else(|_| panic!("{} {args:?} did not finish in 120 s", bin.display()))
        .unwrap_or_else(|e| panic!("running {}: {e}", bin.display()))
    }

    pub fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    pub fn read_trim(p: &Path) -> String {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    /// The kernel's subsystem directory for an NQN, from sysfs.
    pub fn subsystem_dir(nqn: &str) -> Option<PathBuf> {
        std::fs::read_dir("/sys/class/nvme-subsystem")
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| read_trim(&p.join("subsysnqn")) == nqn)
    }

    pub fn is_ns_name(name: &str) -> bool {
        // nvme<N>n<M>, not a per-path nvme<N>c<C>n<M>.
        let Some(rest) = name.strip_prefix("nvme") else {
            return false;
        };
        let mut parts = rest.splitn(2, 'n');
        let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        !a.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.bytes().all(|c| c.is_ascii_digit())
    }

    pub fn is_ctrl_name(name: &str) -> bool {
        name.strip_prefix("nvme")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()))
    }

    /// The controllers of a subsystem and its namespace block devices by NSID. Never a guessed
    /// /dev/nvme0n1: the runner may have NVMe disks of its own.
    pub fn devices(nqn: &str) -> (Vec<String>, Vec<(u32, String)>) {
        let Some(dir) = subsystem_dir(nqn) else {
            return (vec![], vec![]);
        };
        let mut ctrls = Vec::new();
        let mut names = Vec::new();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if is_ctrl_name(&n) {
                ctrls.push(n.clone());
                // Without native multipath the namespaces hang off the controller.
                for c in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                    let cn = c.file_name().to_string_lossy().into_owned();
                    if is_ns_name(&cn) {
                        names.push(cn);
                    }
                }
            } else if is_ns_name(&n) {
                names.push(n);
            }
        }
        names.sort();
        names.dedup();
        let mut ns: Vec<(u32, String)> = names
            .into_iter()
            .filter_map(|n| {
                let id = read_trim(&PathBuf::from(format!("/sys/block/{n}/nsid")));
                id.parse().ok().map(|id| (id, n))
            })
            .collect();
        ns.sort();
        ctrls.sort();
        (ctrls, ns)
    }

    /// What the kernel and nvme-cli say about the association, for a failure message.
    pub async fn diagnostics(nvme: &Path) -> String {
        let list = run(nvme, &["list", "-v"]).await;
        let subsys = run(nvme, &["list-subsys"]).await;
        let mut sysfs = String::new();
        for e in std::fs::read_dir("/sys/class/nvme-subsystem")
            .into_iter()
            .flatten()
            .flatten()
        {
            sysfs.push_str(&format!(
                "{}: {}\n",
                e.path().display(),
                read_trim(&e.path().join("subsysnqn"))
            ));
            for c in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                let n = c.file_name().to_string_lossy().into_owned();
                if is_ctrl_name(&n) {
                    sysfs.push_str(&format!(
                        "  {n}: state={} transport={} address={}\n",
                        read_trim(&c.path().join("state")),
                        read_trim(&c.path().join("transport")),
                        read_trim(&c.path().join("address"))
                    ));
                }
            }
        }
        let dmesg = match std::process::Command::new("dmesg").output() {
            Ok(o) => {
                let all = text(&o.stdout);
                let lines: Vec<&str> = all.lines().collect();
                lines[lines.len().saturating_sub(60)..].join("\n")
            }
            Err(e) => format!("dmesg: {e}"),
        };
        format!(
            "nvme list -v:\n{}{}\nnvme list-subsys:\n{}{}\nsysfs:\n{sysfs}\ndmesg:\n{dmesg}",
            text(&list.stdout),
            text(&list.stderr),
            text(&subsys.stdout),
            text(&subsys.stderr)
        )
    }

    /// Read `len` bytes at `offset` of a block device with O_DIRECT, once it opens and reads.
    pub fn read_direct(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::{FileExt, OpenOptionsExt};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(path)?;
        let mut buf = AlignedBuf::new(len);
        f.read_exact_at(buf.as_mut(), offset)?;
        Ok(buf.as_mut().to_vec())
    }

    pub fn write_direct(path: &Path, offset: u64, data: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::{FileExt, OpenOptionsExt};
        let f = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_SYNC)
            .open(path)?;
        let mut buf = AlignedBuf::new(data.len());
        buf.as_mut().copy_from_slice(data);
        f.write_all_at(buf.as_mut(), offset)?;
        f.sync_all()
    }

    /// A 4096-aligned buffer, as O_DIRECT needs.
    struct AlignedBuf {
        raw: Vec<u8>,
        at: usize,
        len: usize,
    }

    impl AlignedBuf {
        fn new(len: usize) -> Self {
            let raw = vec![0u8; len + 4096];
            let at = (4096 - raw.as_ptr() as usize % 4096) % 4096;
            Self { raw, at, len }
        }
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.raw[self.at..self.at + self.len]
        }
    }

    /// Run a blocking block-device operation off the runtime the target runs on, retrying
    /// until it succeeds (the kernel can create the node before it has finished probing the
    /// disk) for up to 30 s.
    pub async fn until_ok<T: Send + 'static>(
        what: &str,
        f: impl Fn() -> std::io::Result<T> + Send + Sync + Clone + 'static,
    ) -> Result<T, String> {
        let mut last = String::new();
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            let g = f.clone();
            match tokio::time::timeout(Duration::from_secs(60), tokio::task::spawn_blocking(g))
                .await
            {
                Ok(Ok(Ok(v))) => return Ok(v),
                Ok(Ok(Err(e))) => last = format!("{what}: {e}"),
                Ok(Err(e)) => last = format!("{what}: the task failed: {e}"),
                Err(_) => return Err(format!("{what}: took over 60 s")),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(last)
    }

    pub async fn settle() {
        if let Some(u) = ["/usr/bin/udevadm", "/bin/udevadm", "/sbin/udevadm"]
            .iter()
            .find(|p| Path::new(p).exists())
        {
            let _ = run(Path::new(u), &["settle", "--timeout=30"]).await;
        }
    }

    /// Disconnects the subsystem when the test ends, however it ends.
    pub struct Disconnect(PathBuf);
    impl Drop for Disconnect {
        fn drop(&mut self) {
            let _ = std::process::Command::new(&self.0)
                .args(["disconnect", "-n", DISK0])
                .output();
        }
    }

    // Multi-thread, and every block-device read off the runtime: the target answering the
    // kernel's commands runs on this runtime, so a blocking read on its only worker would never
    // return.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    pub async fn the_linux_kernel_host_discovers_connects_and_reads_the_described_namespaces() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let srv = start_on("127.0.0.1", 0, policy(REAL_POLICY), None).await;
        let port = srv.port.to_string();
        let version = run(&nvme, &["version"]).await;
        println!("{}", text(&version.stdout).trim());

        // Discovery: nvme-cli's own discovery controller connection and log read.
        let out = run(
            &nvme,
            &[
                "discover",
                "-t",
                "tcp",
                "-a",
                "127.0.0.1",
                "-s",
                &port,
                "-q",
                KERNEL_HOST,
                "-I",
                KERNEL_HOSTID,
            ],
        )
        .await;
        let o = text(&out.stdout);
        if !out.status.success() || !o.contains(DISK0) {
            panic!(
                "nvme discover: {o}\n{}\n{}",
                text(&out.stderr),
                diagnostics(&nvme).await
            );
        }
        assert!(o.contains("tcp") && o.contains(&port), "{o}");
        assert_eq!(
            events(&srv.state, srv.id, "nvme_tcp_discovery").await.len(),
            1
        );

        // Connect: an association the model admits once.
        let _guard = Disconnect(nvme.clone());
        let out = run(
            &nvme,
            &[
                "connect",
                "-t",
                "tcp",
                "-a",
                "127.0.0.1",
                "-s",
                &port,
                "-n",
                DISK0,
                "-q",
                KERNEL_HOST,
                "-I",
                KERNEL_HOSTID,
            ],
        )
        .await;
        if !out.status.success() {
            panic!(
                "nvme connect: {}{}\n{}",
                text(&out.stdout),
                text(&out.stderr),
                diagnostics(&nvme).await
            );
        }
        let connects = events(&srv.state, srv.id, "nvme_tcp_connect").await;
        assert_eq!(connects.len(), 1, "one model call for the association");
        assert_eq!(connects[0]["host_nqn"], KERNEL_HOST);
        assert_eq!(connects[0]["host_id"], KERNEL_HOSTID);
        settle().await;
        let mut found = (vec![], vec![]);
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            found = devices(DISK0);
            if !found.0.is_empty() && found.1.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let (ctrls, namespaces) = found;
        if ctrls.is_empty() || namespaces.len() != 2 {
            panic!(
                "the kernel made controllers {ctrls:?} and namespaces {namespaces:?} for {DISK0}\n{}",
                diagnostics(&nvme).await
            );
        }
        let ctrl = format!("/dev/{}", ctrls[0]);
        let ns1 = PathBuf::from(format!("/dev/{}", namespaces[0].1));
        let ns2 = PathBuf::from(format!("/dev/{}", namespaces[1].1));

        // The described bytes, through the kernel's block layer.
        let p = ns1.clone();
        let data = match until_ok("reading namespace 1", move || read_direct(&p, 0, 8192)).await {
            Ok(d) => d,
            Err(e) => panic!("{e}\n{}", diagnostics(&nvme).await),
        };
        assert_eq!(&data[..17], b"hello from netget");
        assert!(data[17..4096].iter().all(|b| *b == 0));
        assert!(data[4096..4608].iter().all(|b| *b == 0xAB));
        assert!(data[4608..].iter().all(|b| *b == 0));
        let p = ns2.clone();
        let data = until_ok("reading namespace 2", move || read_direct(&p, 0, 4096))
            .await
            .unwrap();
        assert_eq!(&data[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            read_trim(&PathBuf::from(format!("/sys/block/{}/ro", namespaces[1].1))),
            "1",
            "the write-protected namespace is read-only to the kernel"
        );
        assert_eq!(
            read_trim(&PathBuf::from(format!(
                "/sys/block/{}/queue/logical_block_size",
                namespaces[1].1
            ))),
            "4096"
        );
        // A write through the kernel (O_DIRECT, 8 KiB: in the capsule or by R2T as the kernel
        // chooses) and the read that brings it back from the association's overlay.
        let payload: Vec<u8> = (0..8192).map(|i| (i % 253) as u8).collect();
        let (p, w) = (ns1.clone(), payload.clone());
        until_ok("writing namespace 1", move || write_direct(&p, 1 << 20, &w))
            .await
            .unwrap();
        let p = ns1.clone();
        let back = until_ok("reading the write back", move || {
            read_direct(&p, 1 << 20, 8192)
        })
        .await
        .unwrap();
        assert_eq!(back, payload, "the kernel reads back what it wrote");

        // nvme-cli's Identify Controller and Namespace and the health log.
        let out = run(&nvme, &["id-ctrl", &ctrl, "-o", "json"]).await;
        let id: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("id-ctrl: {e}: {}{}", text(&out.stdout), text(&out.stderr)));
        assert_eq!(id["mn"].as_str().unwrap().trim(), "NETGET-BOOT", "{id}");
        assert_eq!(id["sn"].as_str().unwrap().trim(), "SER0001");
        assert_eq!(id["fr"].as_str().unwrap().trim(), "NG1");
        assert_eq!(id["subnqn"].as_str().unwrap().trim(), DISK0);
        assert_eq!(id["mdts"], 8);
        assert_eq!(id["nn"], 2);
        let out = run(&nvme, &["id-ns", &ns1.display().to_string(), "-o", "json"]).await;
        let ns: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("id-ns: {e}: {}{}", text(&out.stdout), text(&out.stderr)));
        assert_eq!(ns["nsze"], 8192, "{ns}");
        assert_eq!(ns["lbafs"][0]["ds"], 9);
        let out = run(&nvme, &["smart-log", &ctrl, "-o", "json"]).await;
        let smart: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!("smart-log: {e}: {}{}", text(&out.stdout), text(&out.stderr))
        });
        println!("smart-log: {smart}");
        assert!(
            smart["host_write_commands"].as_u64().unwrap_or(0) >= 1,
            "the health log counts the kernel's write: {smart}"
        );

        // Disconnect: the kernel shuts the controller down and closes its queues.
        let out = run(&nvme, &["disconnect", "-n", DISK0]).await;
        assert!(
            out.status.success(),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        let started = std::time::Instant::now();
        while subsystem_dir(DISK0).is_some() && started.elapsed() < Duration::from_secs(20) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(subsystem_dir(DISK0).is_none(), "the subsystem is gone");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    pub async fn the_linux_kernel_host_is_refused_what_the_model_refuses() {
        require_root();
        let nvme = nvme_cli();
        require_module();
        let srv = start_on("127.0.0.1", 0, policy(REAL_POLICY), None).await;
        let port = srv.port.to_string();
        let out = run(
            &nvme,
            &[
                "connect",
                "-t",
                "tcp",
                "-a",
                "127.0.0.1",
                "-s",
                &port,
                "-n",
                "nqn.2026-10.net.netget:nothing",
                "-q",
                KERNEL_HOST,
            ],
        )
        .await;
        assert!(
            !out.status.success(),
            "a subsystem the model does not know is refused: {}",
            text(&out.stdout)
        );
        assert!(subsystem_dir("nqn.2026-10.net.netget:nothing").is_none());
        assert_eq!(
            events(&srv.state, srv.id, "nvme_tcp_connect").await.len(),
            1
        );
    }
}
