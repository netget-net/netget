//! NetGet's iSCSI target against independent initiators.
//!
//! - **libiscsi** (Ronnie Sahlberg's userspace initiator, C; Homebrew `libiscsi`, Debian/Ubuntu
//!   `libiscsi-bin`): `iscsi-ls` (discovery, login, REPORT LUNS, INQUIRY, READ CAPACITY),
//!   `iscsi-inq` (standard data and VPD pages), `iscsi-readcapacity16`, `iscsi-md5sum` (reads
//!   compared with the digest of what the model described) and the `iscsi-test-cu` compliance
//!   suite, for the subset of tests the implemented commands answer. All unprivileged.
//! - **open-iscsi**, the Linux kernel initiator (`iscsiadm`, then `dd` from the block device the
//!   kernel creates), in `open_iscsi` below: Linux, as root, in the `iscsi` pair job.
//!
//! Every test fails, never skips, when its initiator is missing, naming how to install it.
use super::support::*;
use md5::Digest;
use std::path::PathBuf;
use std::process::Output;

/// A peer binary on PATH (or Homebrew's libiscsi prefix), or a failure that says how to
/// install it.
pub fn require(name: &str, install: &str) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    dirs.push("/opt/homebrew/opt/libiscsi/bin".into());
    dirs.push("/usr/local/opt/libiscsi/bin".into());
    dirs.push("/usr/sbin".into());
    dirs.push("/sbin".into());
    for d in dirs {
        let p = d.join(name);
        if p.is_file() {
            return p;
        }
    }
    panic!(
        "{name} is not installed. It is the independent initiator this test exists for, and \
         skipping would leave the iSCSI target's evidence resting on NetGet's own client. \
         Install it with: {install}"
    );
}

pub const LIBISCSI: &str = "brew install libiscsi (macOS) or apt-get install libiscsi-bin (Debian/Ubuntu)";
pub const TESTCU: &str = "iqn.2026-10.net.netget:testcu";

/// The model for the libiscsi tests: disk0 as in `POLICY`, and a plain 64 MiB writable LUN for
/// the compliance suite.
pub const REAL_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='iscsi_discovery':
  a=[{'type':'iscsi_send_targets','targets':[{'name':'iqn.2026-10.net.netget:disk0'},{'name':'iqn.2026-10.net.netget:testcu'}]}]
elif e['target_name']=='iqn.2026-10.net.netget:disk0':
  a=[{'type':'iscsi_accept_login','luns':[
    {'lun':0,'size':1048576,'writable':True,'product':'BOOT-DISK','serial':'SER0001',
     'extents':[{'offset':0,'text':'hello from netget'},{'offset':4096,'length':512,'fill':171}],
     'errors':[{'offset':524288,'length':4096,'error':'medium_error'}]},
    {'lun':1,'size':2097152,'block_size':4096,'extents':[{'offset':0,'hex':'deadbeef'}]}]}]
elif e['target_name']=='iqn.2026-10.net.netget:testcu':
  a=[{'type':'iscsi_accept_login','luns':[{'lun':0,'size':67108864,'writable':True,'extents':[{'offset':0,'text':'compliance'}]}]}]
else:
  a=[{'type':'iscsi_reject_login','reason':'not_found'}]
print(json.dumps({'actions':a}))"#;

pub async fn run(bin: &PathBuf, args: &[&str]) -> Output {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        tokio::process::Command::new(bin)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{} {args:?} did not finish in 300 s", bin.display()))
    .unwrap_or_else(|e| panic!("running {}: {e}", bin.display()));
    out
}

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[tokio::test]
async fn libiscsi_discovers_logs_in_and_reads_the_described_luns() {
    let ls = require("iscsi-ls", LIBISCSI);
    let inq = require("iscsi-inq", LIBISCSI);
    let rc16 = require("iscsi-readcapacity16", LIBISCSI);
    let md5sum = require("iscsi-md5sum", LIBISCSI);
    let srv = start(policy(REAL_POLICY), None).await;
    let portal = format!("iscsi://127.0.0.1:{}", srv.port);
    let init = ["-i", INITIATOR];

    // Discovery, then a login to every target listing its LUNs.
    let out = run(&ls, &[init[0], init[1], "-s", &portal]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains(&format!("Target:{DISK0} Portal:127.0.0.1:{},1", srv.port)), "{o}");
    assert!(o.contains(&format!("Target:{TESTCU}")), "{o}");
    assert!(o.contains("Lun:0") && o.contains("Lun:1"), "{o}");

    // Standard INQUIRY and the serial-number page.
    let lun0 = format!("{portal}/{DISK0}/0");
    let out = run(&inq, &[init[0], init[1], &lun0]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains("NETGET") && o.contains("BOOT-DISK"), "{o}");
    let out = run(&inq, &[init[0], init[1], "-e", "1", "-c", "0x80", &lun0]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains("SER0001"), "{o}");
    let out = run(&inq, &[init[0], init[1], "-e", "1", "-c", "0x83", &lun0]).await;
    assert!(out.status.success(), "{}{}", text(&out.stdout), text(&out.stderr));

    // READ CAPACITY(16) of the 4096-byte-block LUN.
    let lun1 = format!("{portal}/{DISK0}/1");
    let out = run(&rc16, &[init[0], init[1], &lun1]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains("Block size:4096") || o.contains("Block Length:4096") || o.contains("4096"), "{o}");
    assert!(o.contains("511"), "last LBA 511: {o}");

    // Reads: the digest of the first 64 KiB of LUN 0 and of all of LUN 1, computed here from
    // what the model described.
    let mut first = vec![0u8; 65536];
    first[..17].copy_from_slice(b"hello from netget");
    first[4096..4608].fill(0xAB);
    let want = hex::encode(md5::Md5::digest(&first));
    let out = run(&md5sum, &[init[0], init[1], "-o", "0", "-l", "65536", &lun0]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains(&want), "md5 {want} of the described bytes: {o}");
    let mut whole = vec![0u8; 2 * 1024 * 1024];
    whole[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let want = hex::encode(md5::Md5::digest(&whole));
    let out = run(&md5sum, &[init[0], init[1], &lun1]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(o.contains(&want), "md5 {want} of LUN 1: {o}");

    // The medium error region fails the read, as described.
    let out = run(&md5sum, &[init[0], init[1], "-o", "520192", "-l", "8192", &lun0]).await;
    assert!(!out.status.success(), "a read across the error region fails: {}", text(&out.stdout));
}

#[tokio::test]
async fn libiscsi_logs_in_with_chap() {
    let inq = require("iscsi-inq", LIBISCSI);
    let params = serde_json::json!({"chap_accounts": [{"name": "alice", "secret": "wonderland12"}]});
    let srv = start(policy(REAL_POLICY), Some(params)).await;
    let good = format!("iscsi://alice%wonderland12@127.0.0.1:{}/{DISK0}/0", srv.port);
    let out = run(&inq, &["-i", INITIATOR, &good]).await;
    assert!(out.status.success(), "{}{}", text(&out.stdout), text(&out.stderr));
    assert!(text(&out.stdout).contains("BOOT-DISK"));
    let bad = format!("iscsi://alice%wrong-secret-1@127.0.0.1:{}/{DISK0}/0", srv.port);
    let out = run(&inq, &["-i", INITIATOR, &bad]).await;
    assert!(!out.status.success(), "a wrong secret is refused");
    let login = events(&srv.state, srv.id, "iscsi_login").await;
    assert_eq!(login.len(), 1, "only the authenticated login reached the model");
    assert_eq!(login[0]["authenticated_user"], "alice");
}

/// The iscsi-test-cu tests the implemented commands are expected to pass. The rest of the
/// suite either exercises commands this target does not implement (and a target that answers
/// INVALID COMMAND OPERATION CODE makes those tests skip themselves) or is listed in
/// tests/server/iscsi/AGENTS.md with why it fails.
pub const TEST_CU_SUBSET: &[&str] = &[
    "SCSI.TestUnitReady",
    "SCSI.Inquiry.Standard",
    "SCSI.Inquiry.AllocLength",
    "SCSI.Inquiry.EVPD",
    "SCSI.Inquiry.SupportedVPD",
    "SCSI.ReadCapacity10",
    "SCSI.ReadCapacity16.Simple",
    "SCSI.ReadCapacity16.Alloclen",
    "SCSI.ReportLUNs",
    "SCSI.Read6",
    "SCSI.Read10",
    "SCSI.Read12",
    "SCSI.Read16",
    "SCSI.Write10",
    "SCSI.Write12",
    "SCSI.Write16",
    "SCSI.ModeSense6.AllPages",
    "SCSI.ModeSense6.Residuals",
    "SCSI.StartStopUnit",
    "iSCSI.iSCSIcmdsn",
    "iSCSI.iSCSIdatasn",
    "iSCSI.iSCSIResiduals.Read10Invalid",
    "iSCSI.iSCSIResiduals.Read10Residuals",
    "iSCSI.iSCSIResiduals.Read12Residuals",
    "iSCSI.iSCSIResiduals.Read16Residuals",
    "iSCSI.iSCSITMF",
    "iSCSI.iSCSISendTargets",
    "iSCSI.iSCSINop",
];

/// Run one iscsi-test-cu selection; (passed, failed, the output).
async fn test_cu(bin: &PathBuf, url: &str, test: &str) -> (u32, u32, String) {
    let out = run(bin, &["-d", "-n", "-t", test, url]).await;
    let o = format!("{}{}", text(&out.stdout), text(&out.stderr));
    // CUnit's run summary: "tests  <total> <ran> <passed> <failed> <inactive>".
    let row = o
        .lines()
        .find(|l| l.trim_start().starts_with("tests"))
        .unwrap_or_else(|| panic!("no CUnit summary for {test}:\n{o}"));
    let n: Vec<u32> = row
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    (n[2], n[3], o)
}

#[tokio::test]
async fn iscsi_test_cu_passes_the_implemented_subset() {
    let bin = require("iscsi-test-cu", LIBISCSI);
    let srv = start(policy(REAL_POLICY), None).await;
    let url = format!("iscsi://127.0.0.1:{}/{TESTCU}/0", srv.port);
    let mut failures = Vec::new();
    let mut total = 0;
    for test in TEST_CU_SUBSET {
        let (passed, failed, out) = test_cu(&bin, &url, test).await;
        total += passed;
        println!("iscsi-test-cu {test}: {passed} passed, {failed} failed");
        if failed > 0 || passed == 0 {
            failures.push(format!("{test}: {passed} passed, {failed} failed\n{out}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    assert!(total > 50, "the subset ran {total} tests");
}

#[cfg(target_os = "linux")]
mod open_iscsi {
    use super::*;

    fn require_root() {
        assert!(
            unsafe { libc::geteuid() } == 0, // SAFETY: geteuid has no preconditions.
            "the kernel initiator needs root (iscsiadm talks to iscsid and the kernel makes a \
             block device): the iscsi pair job runs this binary through sudo"
        );
    }

    /// The block device the kernel made for a session to `target`, from sysfs.
    fn block_device_for(target: &str) -> Option<PathBuf> {
        for host in std::fs::read_dir("/sys/class/iscsi_session").ok()?.flatten() {
            let name = std::fs::read_to_string(host.path().join("targetname")).unwrap_or_default();
            if name.trim() != target {
                continue;
            }
            let device = host.path().join("device");
            for t in std::fs::read_dir(&device).ok()?.flatten() {
                let tname = t.file_name().to_string_lossy().to_string();
                if !tname.starts_with("target") {
                    continue;
                }
                for lun in std::fs::read_dir(t.path()).ok()?.flatten() {
                    let block = lun.path().join("block");
                    if let Ok(mut it) = std::fs::read_dir(&block) {
                        if let Some(Ok(dev)) = it.next() {
                            return Some(PathBuf::from("/dev").join(dev.file_name()));
                        }
                    }
                }
            }
        }
        None
    }

    #[tokio::test]
    async fn the_linux_kernel_initiator_reads_the_described_disk() {
        require_root();
        let iscsiadm = require("iscsiadm", "apt-get install open-iscsi (and modprobe iscsi_tcp)");
        let srv = start_on("127.0.0.1", 0, policy(REAL_POLICY), None).await;
        let portal = format!("127.0.0.1:{}", srv.port);
        let out = run(&iscsiadm, &["-m", "discovery", "-t", "sendtargets", "-p", &portal]).await;
        let o = text(&out.stdout);
        assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
        assert!(o.contains(DISK0), "{o}");
        let out = run(&iscsiadm, &["-m", "node", "-T", DISK0, "-p", &portal, "--login"]).await;
        assert!(out.status.success(), "{}{}", text(&out.stdout), text(&out.stderr));
        let dev = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(d) = block_device_for(DISK0) {
                    if d.exists() {
                        return d;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("the kernel made a block device for the session");
        let dd = require("dd", "coreutils");
        let out = run(
            &dd,
            &[&format!("if={}", dev.display()), "bs=4096", "count=2", "iflag=direct", "status=none"],
        )
        .await;
        let _ = run(&iscsiadm, &["-m", "node", "-T", DISK0, "-p", &portal, "--logout"]).await;
        let _ = run(&iscsiadm, &["-m", "node", "-T", DISK0, "-p", &portal, "-o", "delete"]).await;
        assert!(out.status.success(), "{}", text(&out.stderr));
        let d = out.stdout;
        assert_eq!(&d[..17], b"hello from netget");
        assert!(d[4096..4608].iter().all(|b| *b == 0xAB));
        assert!(d[4608..8192].iter().all(|b| *b == 0));
    }
}
