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
}
