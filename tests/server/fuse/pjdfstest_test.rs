//! pjdfstest — the POSIX conformance suite FreeBSD, ZFS and fuser itself run — on the mount.
//!
//! The C suite, built by `scripts/test-peers/build-pjdfstest.sh` (`NETGET_PJDFSTEST` names the
//! checkout), run with `prove` from inside the mount, as root, with `allow_other` so its
//! switches to other uids reach the filesystem. The model is a static handler that allows every
//! change, so this measures the filesystem semantics NetGet implements, not a policy.
//!
//! Every test file is run and the whole table printed. [`MUST_PASS`] is the subset that passes
//! in full wherever this runs as root, and [`MUST_PASS_WITH_DEVICE_NODES`] what passes on top of
//! it where the kernel lets root make device nodes (probed, not assumed); a regression in any
//! file of the floor that applies fails the test. The rest fail for reasons
//! `src/server/fuse/AGENTS.md` lists: files are bounded at 1 GiB, pjdfstest's own TODO cases,
//! and a kernel that refuses device nodes (any user namespace) fails every case that makes one.
//! The C suite has no extended-attribute tests; `links_xattrs_test.rs` covers those.
//!
//! Each file runs under its own two-minute deadline, so one that hangs is named rather than
//! taking the run with it. pjdfstest names its files with `openssl md5`; without openssl its
//! name generator loops forever, which looks exactly like a filesystem hang.
use super::support::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Test files that pass in full wherever the suite runs as root: 203 of 238, measured on
/// Linux 7.2 (aarch64) as root in a rootless container, where the kernel refuses block and
/// character device nodes to everyone, so the device-node cases fail there for a reason that is
/// not this server's. Kept as the floor. [`MUST_PASS_WITH_DEVICE_NODES`] is what a root that
/// may make device nodes (CI's sudo; a rootful container) passes on top of it.
const MUST_PASS: &[&str] = &[
    "chflags/00.t",
    "chflags/01.t",
    "chflags/02.t",
    "chflags/03.t",
    "chflags/04.t",
    "chflags/05.t",
    "chflags/06.t",
    "chflags/07.t",
    "chflags/08.t",
    "chflags/09.t",
    "chflags/10.t",
    "chflags/11.t",
    "chflags/12.t",
    "chflags/13.t",
    "chmod/02.t",
    "chmod/03.t",
    "chmod/04.t",
    "chmod/05.t",
    "chmod/06.t",
    "chmod/07.t",
    "chmod/08.t",
    "chmod/09.t",
    "chmod/10.t",
    "chmod/12.t",
    "chown/02.t",
    "chown/03.t",
    "chown/04.t",
    "chown/05.t",
    "chown/06.t",
    "chown/08.t",
    "chown/09.t",
    "chown/10.t",
    "ftruncate/00.t",
    "ftruncate/01.t",
    "ftruncate/02.t",
    "ftruncate/03.t",
    "ftruncate/04.t",
    "ftruncate/05.t",
    "ftruncate/06.t",
    "ftruncate/07.t",
    "ftruncate/08.t",
    "ftruncate/09.t",
    "ftruncate/10.t",
    "ftruncate/11.t",
    "ftruncate/12.t",
    "ftruncate/13.t",
    "ftruncate/14.t",
    "granular/00.t",
    "granular/01.t",
    "granular/02.t",
    "granular/03.t",
    "granular/04.t",
    "granular/05.t",
    "granular/06.t",
    "link/02.t",
    "link/03.t",
    "link/04.t",
    "link/05.t",
    "link/06.t",
    "link/07.t",
    "link/08.t",
    "link/09.t",
    "link/11.t",
    "link/12.t",
    "link/13.t",
    "link/14.t",
    "link/15.t",
    "link/16.t",
    "link/17.t",
    "mkdir/00.t",
    "mkdir/02.t",
    "mkdir/03.t",
    "mkdir/04.t",
    "mkdir/05.t",
    "mkdir/06.t",
    "mkdir/07.t",
    "mkdir/08.t",
    "mkdir/09.t",
    "mkdir/11.t",
    "mkdir/12.t",
    "mkfifo/00.t",
    "mkfifo/02.t",
    "mkfifo/03.t",
    "mkfifo/04.t",
    "mkfifo/05.t",
    "mkfifo/06.t",
    "mkfifo/07.t",
    "mkfifo/08.t",
    "mkfifo/10.t",
    "mkfifo/11.t",
    "mkfifo/12.t",
    "mknod/00.t",
    "mknod/04.t",
    "mknod/05.t",
    "mknod/06.t",
    "mknod/07.t",
    "mknod/09.t",
    "mknod/10.t",
    "open/00.t",
    "open/02.t",
    "open/03.t",
    "open/04.t",
    "open/05.t",
    "open/06.t",
    "open/07.t",
    "open/08.t",
    "open/09.t",
    "open/10.t",
    "open/11.t",
    "open/12.t",
    "open/13.t",
    "open/14.t",
    "open/15.t",
    "open/16.t",
    "open/17.t",
    "open/18.t",
    "open/19.t",
    "open/20.t",
    "open/21.t",
    "open/23.t",
    "open/24.t",
    "open/26.t",
    "posix_fallocate/00.t",
    "rename/01.t",
    "rename/02.t",
    "rename/03.t",
    "rename/04.t",
    "rename/05.t",
    "rename/06.t",
    "rename/07.t",
    "rename/08.t",
    "rename/11.t",
    "rename/15.t",
    "rename/16.t",
    "rename/17.t",
    "rename/18.t",
    "rename/19.t",
    "rename/21.t",
    "rename/22.t",
    "rename/24.t",
    "rmdir/00.t",
    "rmdir/01.t",
    "rmdir/02.t",
    "rmdir/03.t",
    "rmdir/04.t",
    "rmdir/05.t",
    "rmdir/07.t",
    "rmdir/08.t",
    "rmdir/09.t",
    "rmdir/10.t",
    "rmdir/11.t",
    "rmdir/12.t",
    "rmdir/13.t",
    "rmdir/14.t",
    "rmdir/15.t",
    "symlink/00.t",
    "symlink/01.t",
    "symlink/02.t",
    "symlink/03.t",
    "symlink/04.t",
    "symlink/05.t",
    "symlink/06.t",
    "symlink/07.t",
    "symlink/09.t",
    "symlink/10.t",
    "symlink/11.t",
    "symlink/12.t",
    "truncate/00.t",
    "truncate/01.t",
    "truncate/02.t",
    "truncate/03.t",
    "truncate/04.t",
    "truncate/05.t",
    "truncate/06.t",
    "truncate/07.t",
    "truncate/08.t",
    "truncate/09.t",
    "truncate/10.t",
    "truncate/11.t",
    "truncate/12.t",
    "truncate/13.t",
    "truncate/14.t",
    "unlink/01.t",
    "unlink/02.t",
    "unlink/03.t",
    "unlink/04.t",
    "unlink/05.t",
    "unlink/06.t",
    "unlink/07.t",
    "unlink/09.t",
    "unlink/10.t",
    "unlink/12.t",
    "unlink/13.t",
    "unlink/14.t",
    "utimensat/01.t",
    "utimensat/02.t",
    "utimensat/03.t",
    "utimensat/04.t",
    "utimensat/05.t",
    "utimensat/06.t",
    "utimensat/07.t",
    "utimensat/08.t",
    "utimensat/09.t",
];

/// The 32 more files that pass in full where the kernel lets root make block and character
/// device nodes: 235 of 238 in all, measured on Linux 7.2 (aarch64) as root in a rootful
/// container. The three left fail on a 2 GiB pwrite (files are bounded at 1 GiB) and on
/// pjdfstest's own TODO cases (`chown/00.t`, `unlink/08.t`), which the tally counts as failures.
const MUST_PASS_WITH_DEVICE_NODES: &[&str] = &[
    "chmod/00.t",
    "chmod/01.t",
    "chmod/11.t",
    "chown/01.t",
    "chown/07.t",
    "link/00.t",
    "link/01.t",
    "link/10.t",
    "mkdir/01.t",
    "mkdir/10.t",
    "mkfifo/01.t",
    "mkfifo/09.t",
    "mknod/01.t",
    "mknod/02.t",
    "mknod/03.t",
    "mknod/08.t",
    "mknod/11.t",
    "open/01.t",
    "open/22.t",
    "rename/00.t",
    "rename/09.t",
    "rename/10.t",
    "rename/12.t",
    "rename/13.t",
    "rename/14.t",
    "rename/20.t",
    "rename/23.t",
    "rmdir/06.t",
    "symlink/08.t",
    "unlink/00.t",
    "unlink/11.t",
    "utimensat/00.t",
];

/// Whether the kernel lets this process make a block device node, tried on an ordinary
/// directory outside the mount: root in the initial user namespace may; root in a rootless
/// container may not, whatever the filesystem.
fn can_make_device_nodes(scratch: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let p = scratch.join("device-probe");
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path; mknod has no other preconditions.
    let made = unsafe { libc::mknod(c.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(1, 2)) } == 0;
    let _ = std::fs::remove_file(&p);
    made
}

fn pjdfstest_dir() -> PathBuf {
    let dir = std::env::var_os("NETGET_PJDFSTEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
            "NETGET_PJDFSTEST is not set. It names a pjdfstest checkout with the pjdfstest binary \
             built, the compliance suite this test exists for; skipping would leave the FUSE \
             server's evidence resting on coreutils alone. Build it with: sh \
             scripts/test-peers/build-pjdfstest.sh <dir> (needs autoconf, automake, gcc, make)"
        )
        });
    assert!(
        dir.join("pjdfstest").is_file() && dir.join("tests").is_dir(),
        "{} has no built pjdfstest binary and tests/ directory",
        dir.display()
    );
    dir
}

/// (passed, failed) subtests per test file, from prove's verbose output.
fn tally(output: &str) -> BTreeMap<String, (usize, usize)> {
    let mut out: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut current = String::new();
    for line in output.lines() {
        if let Some(i) = line.find("/tests/") {
            if line.trim_end().ends_with(".t ..") || line.contains(".t ..") {
                let rest = &line[i + "/tests/".len()..];
                current = rest[..rest.find(".t").map_or(rest.len(), |e| e + 2)].to_string();
                out.entry(current.clone()).or_default();
                continue;
            }
        }
        if current.is_empty() {
            continue;
        }
        let t = line.trim_start();
        if t.starts_with("ok ") {
            out.get_mut(&current).unwrap().0 += 1;
        } else if t.starts_with("not ok ") {
            out.get_mut(&current).unwrap().1 += 1;
        }
    }
    out
}

/// The first few `not ok` lines of each test file: pjdfstest says what it tried, what it
/// expected and what it got, which is the whole diagnosis.
fn first_failures(output: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in output.lines() {
        if let Some(i) = line.find("/tests/") {
            if line.contains(".t ..") {
                let rest = &line[i + "/tests/".len()..];
                current = rest[..rest.find(".t").map_or(rest.len(), |e| e + 2)].to_string();
                continue;
            }
        }
        if !current.is_empty() && line.trim_start().starts_with("not ok ") {
            let lines = out.entry(current.clone()).or_default();
            if lines.len() < 3 {
                lines.push(line.trim().to_string());
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pjdfstest_passes_on_the_mount() {
    let suite = pjdfstest_dir();
    assert!(
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() } == 0,
        "pjdfstest switches between users and needs root: the fuse pair job runs this binary \
         through sudo"
    );
    let m = mount(
        Some(vec![
            json!({"event_pattern": "fuse_describe_directory", "handler": {"type": "static",
                "actions": [{"type": "fuse_directory", "entries": []}]}}),
            json!({"event_pattern": "*", "handler": {"type": "static",
                "actions": [{"type": "fuse_allow"}]}}),
        ]),
        json!({"allow_other": true, "decision_timeout_secs": 30}),
    )
    .await;
    let _diag = OnFailure(&m);
    // The mount point's own mode: pjdfstest's users must be able to work in it.
    m.ok(r#"chmod 0777 "$M""#).await;
    // One prove per test file, each under its own deadline, so a file that hangs is reported
    // as such instead of taking the rest of the run with it.
    let mut files: Vec<PathBuf> = Vec::new();
    for group in std::fs::read_dir(suite.join("tests")).unwrap().flatten() {
        if group.path().is_dir() {
            for t in std::fs::read_dir(group.path()).unwrap().flatten() {
                if t.path().extension().is_some_and(|e| e == "t") {
                    files.push(t.path());
                }
            }
        }
    }
    files.sort();
    let mut text = String::new();
    let mut hung = Vec::new();
    for file in &files {
        let run = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            tokio::process::Command::new("prove")
                .arg("-v")
                .arg(file)
                .current_dir(&m.path)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        match run {
            Ok(out) => {
                let out = out.expect("prove (perl) runs: apt-get install perl");
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push('\n');
            }
            Err(_) => {
                println!("pjdfstest: {} did not finish in 120 s", file.display());
                hung.push(file.display().to_string());
            }
        }
    }
    let table = tally(&text);
    assert!(
        table.len() > 100,
        "prove ran the suite ({} files of {})",
        table.len(),
        files.len()
    );
    assert!(hung.is_empty(), "pjdfstest files that hung: {hung:?}");
    let (mut files_ok, mut sub_ok, mut sub_bad) = (0, 0, 0);
    let why = first_failures(&text);
    println!("pjdfstest on the NetGet FUSE mount:");
    for (file, (ok, bad)) in &table {
        println!(
            "  {file:<28} {ok:>4} ok {bad:>4} not ok{}",
            if *bad == 0 && *ok > 0 { "" } else { "  <-" }
        );
        for line in why.get(file).into_iter().flatten() {
            println!("      {line}");
        }
        sub_ok += ok;
        sub_bad += bad;
        if *bad == 0 && *ok > 0 {
            files_ok += 1;
        }
    }
    println!(
        "pjdfstest: {files_ok}/{} files pass in full; {sub_ok} subtests ok, {sub_bad} not ok",
        table.len()
    );
    let passing: Vec<&String> = table
        .iter()
        .filter(|(_, (ok, bad))| *bad == 0 && *ok > 0)
        .map(|(f, _)| f)
        .collect();
    println!("passing files: {passing:?}");
    let devices = can_make_device_nodes(m.dir.path());
    println!(
        "pjdfstest: device nodes {} here, so the floor is {} files",
        if devices {
            "can be made"
        } else {
            "cannot be made"
        },
        MUST_PASS.len()
            + if devices {
                MUST_PASS_WITH_DEVICE_NODES.len()
            } else {
                0
            }
    );
    let floor: Vec<&&str> = MUST_PASS
        .iter()
        .chain(if devices {
            MUST_PASS_WITH_DEVICE_NODES.iter()
        } else {
            [].iter()
        })
        .collect();
    let regressed: Vec<&&str> = floor
        .into_iter()
        .filter(|f| !table.get(**f).is_some_and(|(ok, bad)| *bad == 0 && *ok > 0))
        .collect();
    assert!(
        regressed.is_empty(),
        "pjdfstest files that passed in full no longer do: {regressed:?}"
    );
    m.stop().await;
}
