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
pub fn require_tool(name: &str, install: &str) -> PathBuf {
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
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

pub const LIBISCSI: &str =
    "brew install libiscsi (macOS) or apt-get install libiscsi-bin (Debian/Ubuntu)";
pub const TESTCU: &str = "iqn.2026-10.net.netget:testcu";

/// The model for the libiscsi tests: disk0 as in `POLICY`, and a plain 64 MiB writable LUN for
/// the compliance suite.
pub const REAL_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='iscsi_discovery':
  a=[{'type':'iscsi_send_targets','targets':[{'name':'iqn.2026-10.net.netget:disk0'},{'name':'iqn.2026-10.net.netget:testcu'}]}]
elif t=='iscsi_task_management':
  a=[{'type':'iscsi_allow_reset'}]
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

/// iscsi-md5sum's digest of a read, which must succeed.
async fn md5_of(md5sum: &PathBuf, args: &[&str]) -> String {
    let mut a = vec!["-i", INITIATOR];
    a.extend(args);
    let out = run(md5sum, &a).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    o.trim().to_string()
}

#[tokio::test]
async fn libiscsi_discovers_logs_in_and_reads_the_described_luns() {
    let ls = require_tool("iscsi-ls", LIBISCSI);
    let inq = require_tool("iscsi-inq", LIBISCSI);
    let rc16 = require_tool("iscsi-readcapacity16", LIBISCSI);
    let md5sum = require_tool("iscsi-md5sum", LIBISCSI);
    let srv = start(policy(REAL_POLICY), None).await;
    let portal = format!("iscsi://127.0.0.1:{}", srv.port);
    let init = ["-i", INITIATOR];

    // Discovery, then a login to every target listing its LUNs.
    let out = run(&ls, &[init[0], init[1], "-s", &portal]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(
        o.contains(&format!("Target:{DISK0} Portal:127.0.0.1:{},1", srv.port)),
        "{o}"
    );
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
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );

    // READ CAPACITY(16) of the 4096-byte-block LUN.
    let lun1 = format!("{portal}/{DISK0}/1");
    let out = run(&rc16, &[init[0], init[1], &lun1]).await;
    let o = text(&out.stdout);
    assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
    assert!(
        o.contains("Block size:4096") || o.contains("Block Length:4096") || o.contains("4096"),
        "{o}"
    );
    assert!(o.contains("511"), "last LBA 511: {o}");

    // Reads: the digest of the first 64 KiB of LUN 0 and of all of LUN 1, against the md5 of
    // the bytes the model described.
    let mut first = vec![0u8; 65536];
    first[..17].copy_from_slice(b"hello from netget");
    first[4096..4608].fill(0xAB);
    let mut whole = vec![0u8; 2 * 1024 * 1024];
    whole[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let head = md5_of(&md5sum, &["-o", "0", "-l", "65536", &lun0]).await;
    let lun1_digest = md5_of(&md5sum, &[&lun1]).await;
    if cfg!(target_os = "macos") {
        // Homebrew's libiscsi 1.20.3 bottle prints digests that are not MD5 — 75733c3b… for
        // 512 zero bytes, where MD5 is bf619eac… — while a capture of the same session shows
        // the target's bytes exactly as described (measured 19 October 2026). So on macOS
        // its digest is compared with its own digest of other reads: the same range twice
        // agrees, two ranges of zeroes agree, and ranges whose described bytes differ do
        // not. The exact MD5 comparison runs on Linux, against the source build.
        assert_eq!(
            head,
            md5_of(&md5sum, &["-o", "0", "-l", "65536", &lun0]).await
        );
        let zeros_a = md5_of(&md5sum, &["-o", "8192", "-l", "512", &lun0]).await;
        let zeros_b = md5_of(&md5sum, &["-o", "16384", "-l", "512", &lun0]).await;
        let text_block = md5_of(&md5sum, &["-o", "0", "-l", "512", &lun0]).await;
        let fill_block = md5_of(&md5sum, &["-o", "4096", "-l", "512", &lun0]).await;
        assert_eq!(zeros_a, zeros_b, "two zero blocks read the same");
        assert_ne!(zeros_a, text_block, "the text block is not zeroes");
        assert_ne!(zeros_a, fill_block, "the fill block is not zeroes");
        assert_ne!(text_block, fill_block);
        assert_ne!(head, lun1_digest);
    } else {
        let want = hex::encode(md5::Md5::digest(&first));
        assert_eq!(head, want, "md5 of the described bytes");
        let want = hex::encode(md5::Md5::digest(&whole));
        assert_eq!(lun1_digest, want, "md5 of LUN 1");
    }

    // The medium error region fails the read, as described.
    let out = run(
        &md5sum,
        &[init[0], init[1], "-o", "520192", "-l", "8192", &lun0],
    )
    .await;
    assert!(
        !out.status.success(),
        "a read across the error region fails: {}",
        text(&out.stdout)
    );
}

#[tokio::test]
async fn libiscsi_logs_in_with_chap() {
    let inq = require_tool("iscsi-inq", LIBISCSI);
    let params =
        serde_json::json!({"chap_accounts": [{"name": "alice", "secret": "wonderland12"}]});
    let srv = start(policy(REAL_POLICY), Some(params)).await;
    let good = format!(
        "iscsi://alice%wonderland12@127.0.0.1:{}/{DISK0}/0",
        srv.port
    );
    let out = run(&inq, &["-i", INITIATOR, &good]).await;
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(text(&out.stdout).contains("BOOT-DISK"));
    let bad = format!(
        "iscsi://alice%wrong-secret-1@127.0.0.1:{}/{DISK0}/0",
        srv.port
    );
    let out = run(&inq, &["-i", INITIATOR, &bad]).await;
    assert!(!out.status.success(), "a wrong secret is refused");
    let login = events(&srv.state, srv.id, "iscsi_login").await;
    assert_eq!(
        login.len(),
        1,
        "only the authenticated login reached the model"
    );
    assert_eq!(login[0]["authenticated_user"], "alice");
}

/// The iscsi-test-cu tests the implemented commands are expected to pass. The rest of the
/// suite either exercises commands this target does not implement (and a target that answers
/// INVALID COMMAND OPERATION CODE makes those tests skip themselves) or is listed in
/// tests/server/iscsi/AGENTS.md with why it fails.
pub const TEST_CU_SUBSET: &[&str] = &[
    "SCSI.TestUnitReady",
    "SCSI.Inquiry",
    "SCSI.Mandatory",
    "SCSI.NoMedia",
    "SCSI.ReadCapacity10",
    "SCSI.ReadCapacity16",
    "SCSI.ReportLUNs",
    "SCSI.Read6",
    "SCSI.Read10",
    "SCSI.Read12",
    "SCSI.Read16",
    "SCSI.Write10",
    "SCSI.Write12",
    "SCSI.Write16",
    "SCSI.ModeSense6",
    "SCSI.StartStopUnit",
    "iSCSI.iSCSIcmdsn",
    "iSCSI.iSCSIdatasn",
    "iSCSI.iSCSIResiduals",
    "iSCSI.iSCSISendTargets",
    "iSCSI.iSCSINop",
];

/// Run one iscsi-test-cu selection; (passed, failed, the output).
async fn test_cu(bin: &PathBuf, url: &str, test: &str) -> (u32, u32, String) {
    test_cu_paths(bin, &[url], test).await
}

/// iscsi-test-cu over one or more paths (a second URL is a second I_T nexus, logged in as the
/// second initiator name, for the MultipathIO suite).
async fn test_cu_paths(bin: &PathBuf, urls: &[&str], test: &str) -> (u32, u32, String) {
    let mut args = vec![
        "-d",
        "-n",
        "-i",
        "iqn.2026-10.org.example:testcu-path0",
        "-I",
        "iqn.2026-10.org.example:testcu-path1",
        "-t",
        test,
    ];
    args.extend(urls);
    let out = run(bin, &args).await;
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
    let bin = require_tool("iscsi-test-cu", LIBISCSI);
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

/// The iscsi-test-cu tests that drive task management, each with how many paths (I_T nexuses)
/// it needs. `SCSI.MultipathIO.Reset` resets the LUN on each path in turn and requires a unit
/// attention on every path afterwards, which is the per-nexus unit attention of SAM-5 §6.3.3.
pub const TEST_CU_TMF: &[(&str, usize)] = &[
    ("iSCSI.iSCSITMF.AbortTaskSimpleAsync", 1),
    ("iSCSI.iSCSITMF.LUNResetSimpleAsync", 1),
    ("iSCSI.iSCSITMF.LogoutDuringIOAsync", 1),
    ("SCSI.MultipathIO.Reset", 2),
];

/// The one assertion of the two async TMF tests that is about libiscsi rather than the target:
/// `iscsi_out_queue_length(…) == 1` right after queuing the WRITE, before anything is serviced.
/// Homebrew's build has already sent it by then ("dispatching out queue… dispatched" with no
/// service call), so the queue is empty; every assertion about what the target answered
/// passes. A failure is accepted only when it is that assertion and nothing else.
fn only_libiscsi_queue_assert(out: &str) -> bool {
    let failures: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.split_once(". ")
                .is_some_and(|(n, rest)| n.parse::<u32>().is_ok() && rest.contains(".c:"))
        })
        .collect();
    !failures.is_empty()
        && failures
            .iter()
            .all(|l| l.contains("CU_ASSERT_EQUAL(iscsi_out_queue_length(sd->iscsi_ctx),1)"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iscsi_test_cu_task_management_and_unit_attentions() {
    let bin = require_tool("iscsi-test-cu", LIBISCSI);
    let srv = start(policy(REAL_POLICY), None).await;
    let url = format!("iscsi://127.0.0.1:{}/{TESTCU}/0", srv.port);
    let mut failures = Vec::new();
    for (test, paths) in TEST_CU_TMF {
        let urls: Vec<&str> = std::iter::repeat_n(url.as_str(), *paths).collect();
        let (passed, failed, out) = test_cu_paths(&bin, &urls, test).await;
        let host_side = failed == 1 && passed == 0 && only_libiscsi_queue_assert(&out);
        println!(
            "iscsi-test-cu {test} over {paths} path(s): {passed} passed, {failed} failed{}",
            if host_side {
                " (only libiscsi's own out-queue assertion; every assertion about the target passed)"
            } else {
                ""
            }
        );
        if !host_side && (failed > 0 || passed == 0) {
            failures.push(format!("{test}: {passed} passed, {failed} failed\n{out}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    // Every reset was the model's to allow, and named its LUN.
    let asked = events(&srv.state, srv.id, "iscsi_task_management").await;
    let resets = asked
        .iter()
        .filter(|e| e["function"] == "logical_unit_reset" && e["lun"] == 0)
        .count();
    // LUNResetSimpleAsync resets once, MultipathIO.Reset once per path.
    assert!(
        resets >= 3,
        "the model decided {resets} LUN resets: {asked:?}"
    );
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

    /// What the kernel and open-iscsi say about the session, for a failure message.
    async fn diagnostics(iscsiadm: &PathBuf) -> String {
        let session = run(iscsiadm, &["-m", "session", "-P", "3"]).await;
        let by_path = std::fs::read_dir("/dev/disk/by-path")
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let dmesg = match std::process::Command::new("dmesg").output() {
            Ok(o) => {
                let all = text(&o.stdout);
                let lines: Vec<&str> = all.lines().collect();
                lines[lines.len().saturating_sub(60)..].join("\n")
            }
            Err(e) => format!("dmesg: {e}"),
        };
        format!(
            "iscsiadm -m session -P 3:\n{}{}\n/dev/disk/by-path:\n{by_path}\ndmesg:\n{dmesg}",
            text(&session.stdout),
            text(&session.stderr)
        )
    }

    /// Read `len` bytes from the start of the block device, once it opens and reads.
    fn read_start(path: &std::path::Path, len: usize) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    // Multi-thread, and the read below off the runtime: the target answering the kernel's READ
    // runs on this runtime, so a blocking read of its disk on the only worker never returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_linux_kernel_initiator_reads_the_described_disk() {
        require_root();
        let iscsiadm = require_tool(
            "iscsiadm",
            "apt-get install open-iscsi (and modprobe iscsi_tcp)",
        );
        let srv = start_on("127.0.0.1", 0, policy(REAL_POLICY), None).await;
        let portal = format!("127.0.0.1:{}", srv.port);
        let out = run(
            &iscsiadm,
            &["-m", "discovery", "-t", "sendtargets", "-p", &portal],
        )
        .await;
        let o = text(&out.stdout);
        assert!(out.status.success(), "{o}\n{}", text(&out.stderr));
        assert!(o.contains(DISK0), "{o}");
        let out = run(
            &iscsiadm,
            &["-m", "node", "-T", DISK0, "-p", &portal, "--login"],
        )
        .await;
        assert!(
            out.status.success(),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        // The kernel names the disk; udev links it by portal, target and LUN. Never guess the
        // sdX name: the runner has disks of its own, and LUN 1 is a disk of this session too.
        let link = PathBuf::from(format!("/dev/disk/by-path/ip-{portal}-iscsi-{DISK0}-lun-0"));
        if let Some(udevadm) = ["/usr/bin/udevadm", "/bin/udevadm", "/sbin/udevadm"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        {
            let _ = run(&PathBuf::from(udevadm), &["settle", "--timeout=30"]).await;
        }
        // The node can exist before the kernel has finished probing the disk (opening it then
        // fails with ENXIO), so wait for a read to succeed, not for the name to appear.
        let mut last = String::new();
        let mut data = None;
        for _ in 0..150 {
            let path = link.clone();
            let read = tokio::task::spawn_blocking(move || read_start(&path, 8192));
            match tokio::time::timeout(std::time::Duration::from_secs(60), read).await {
                Ok(Ok(Ok(d))) => {
                    data = Some(d);
                    break;
                }
                Ok(Ok(Err(e))) => last = format!("{}: {e}", link.display()),
                Ok(Err(e)) => last = format!("{}: the read task failed: {e}", link.display()),
                Err(_) => {
                    last = format!("{}: a read took over 60 s", link.display());
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        let report = if data.is_none() {
            diagnostics(&iscsiadm).await
        } else {
            String::new()
        };
        let _ = run(
            &iscsiadm,
            &["-m", "node", "-T", DISK0, "-p", &portal, "--logout"],
        )
        .await;
        let _ = run(
            &iscsiadm,
            &["-m", "node", "-T", DISK0, "-p", &portal, "-o", "delete"],
        )
        .await;
        let d = data
            .unwrap_or_else(|| panic!("the kernel's disk for LUN 0 never read: {last}\n{report}"));
        assert_eq!(&d[..17], b"hello from netget");
        assert!(d[4096..4608].iter().all(|b| *b == 0xAB));
        assert!(d[4608..8192].iter().all(|b| *b == 0));
    }
}
