//! NetGet's iSCSI initiator against independent targets, each serving a backing file the test
//! wrote: what the model reads must be the file's bytes, and what it writes must land in the
//! file.
//!
//! - **gotgt** (gostor/gotgt, a userspace target in Go; `go install
//!   github.com/gostor/gotgt@v0.2.2`, then point `NETGET_GOTGT` at the binary or put it on
//!   PATH): unprivileged, on macOS and Linux.
//! - **tgtd** (the Linux SCSI target framework, Debian/Ubuntu `tgt`): Linux, as root, in the
//!   `iscsi` pair job — including CHAP and mutual CHAP against its account database.
//!
//! Every test fails, never skips, when its target is missing, naming how to install it.
use super::support::*;
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

fn find_binary(name: &str, env: &str, install: &str) -> PathBuf {
    if let Some(p) = std::env::var_os(env) {
        let p = PathBuf::from(p);
        assert!(p.is_file(), "{env}={} is not a file", p.display());
        return p;
    }
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join("go/bin"));
    }
    dirs.push("/usr/sbin".into());
    for d in dirs {
        let p = d.join(name);
        if p.is_file() {
            return p;
        }
    }
    panic!(
        "{name} is not installed. It is the independent target this test exists for, and \
         skipping would leave the iSCSI initiator's evidence resting on NetGet's own target. \
         Install it with: {install}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_port(port: u16) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the target listens");
}

/// A 4 MiB backing file whose first sector says `marker`.
fn backing_file(dir: &std::path::Path, marker: &str) -> PathBuf {
    let path = dir.join("disk.img");
    let mut d = vec![0u8; 4 * 1024 * 1024];
    d[..marker.len()].copy_from_slice(marker.as_bytes());
    std::fs::write(&path, d).unwrap();
    path
}

/// Wait until the backing file holds `WRITE_TEXT` at block 100.
async fn wait_for_write(path: &std::path::Path) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let d = std::fs::read(path).unwrap();
            if d[51200..51200 + WRITE_TEXT.len()] == *WRITE_TEXT.as_bytes() {
                return d;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the model's write reached the target's backing file")
}

const GOTGT_TARGET: &str = "iqn.2026-10.org.gostor:netget-disk";

/// gotgt serving a 4 MiB backing file as LUN 0 of [`GOTGT_TARGET`], from a test-owned `HOME`
/// (its config.json lives there): (the daemon, its port, the backing file).
async fn start_gotgt(
    home: &std::path::Path,
    marker: &str,
) -> (tokio::process::Child, u16, PathBuf) {
    let gotgt = find_binary(
        "gotgt",
        "NETGET_GOTGT",
        "go install github.com/gostor/gotgt@v0.2.2 (then NETGET_GOTGT=$(go env GOPATH)/bin/gotgt)",
    );
    let disk = backing_file(home, marker);
    let (port, control) = (free_port(), free_port());
    std::fs::create_dir_all(home.join(".gotgt")).unwrap();
    std::fs::write(
        home.join(".gotgt/config.json"),
        json!({
            "storages": [{"deviceID": 1000, "path": format!("file:{}", disk.display()),
                          "online": true, "thinProvisioning": false, "blockShift": 9}],
            "iscsiportals": [{"id": 0, "portal": format!("127.0.0.1:{port}")}],
            "iscsitargets": {GOTGT_TARGET: {"tpgts": {"1": [0]}, "luns": {"0": 1000}}}
        })
        .to_string(),
    )
    .unwrap();
    let daemon = tokio::process::Command::new(&gotgt)
        .args([
            "daemon",
            "--port",
            &port.to_string(),
            "--host",
            &format!("tcp://127.0.0.1:{control}"),
        ])
        .env("HOME", home)
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(home.join("gotgt.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_port(port).await;
    (daemon, port, disk)
}

#[tokio::test]
async fn gotgt_answers_the_models_task_management() {
    let home = tempfile::tempdir().unwrap();
    let (_daemon, port, _disk) = start_gotgt(home.path(), "hello from gotgt").await;
    let (state, id) = client(
        format!("127.0.0.1:{port}"),
        json!({"initiator_name": "iqn.2026-10.net.netget:gotgt-tmf", "target_name": GOTGT_TARGET}),
        chain(&stepping_policy(&home.path().join("step"), &tmf_steps(0))),
    )
    .await
    .unwrap();
    let log = || std::fs::read_to_string(home.path().join("gotgt.log")).unwrap_or_default();
    let r = tmf_results(&state, id, 7).await;
    // gotgt 0.2.2 (pkg/port/iscsit/iscsid.go): ABORT TASK looks only at tasks still waiting,
    // ABORT TASK SET and LOGICAL UNIT RESET are empty cases answered "function complete",
    // everything else is "not supported", and the session goes on after both target resets.
    let want = [
        ("abort_task", "task_does_not_exist"),
        ("abort_task_set", "function_complete"),
        ("clear_aca", "function_not_supported"),
        ("clear_task_set", "function_not_supported"),
        ("logical_unit_reset", "function_complete"),
        ("target_warm_reset", "function_not_supported"),
        ("target_cold_reset", "function_not_supported"),
    ];
    let got: Vec<(&str, &str)> = r.iter().map(|(f, s)| (f.as_str(), s.as_str())).collect();
    assert_eq!(got, want, "{}", log());
    // gotgt establishes no unit attention, after login or after its LUN reset.
    let c = results(&state, id, 4).await;
    assert!(c.iter().all(|r| r["status"] == "GOOD"), "{c:?}\n{}", log());
    let out = wait_event(&state, id, "iscsi_logged_out", 0).await;
    assert_eq!(
        out["reason"], "logged out",
        "the session outlived both target resets"
    );
}

#[tokio::test]
async fn gotgt_serves_the_models_session_from_its_backing_file() {
    let home = tempfile::tempdir().unwrap();
    let (_daemon, port, disk) = start_gotgt(home.path(), "hello from gotgt").await;
    // gotgt 0.2.2 has no discovery session: a login without a TargetName is closed unanswered
    // ("No target found with name()"), so this session logs straight in to the target.
    let (state, id) = client(
        format!("127.0.0.1:{port}"),
        json!({"initiator_name": "iqn.2026-10.net.netget:gotgt-test", "target_name": GOTGT_TARGET}),
        chain(&login_first_policy()),
    )
    .await
    .unwrap();
    let log = || std::fs::read_to_string(home.path().join("gotgt.log")).unwrap_or_default();
    let login = wait_event(&state, id, "iscsi_login_result", 0).await;
    assert_eq!(login["logged_in"], true, "{login}\n{}", log());
    let r = results(&state, id, 6).await;
    assert_eq!(r[0]["luns"], json!([0]), "{}", r[0]);
    assert_eq!(
        r[1]["inquiry"]["device_type"], "direct-access block device",
        "{}",
        r[1]
    );
    assert_eq!(r[2]["capacity"]["size_bytes"], 4 * 1024 * 1024, "{}", r[2]);
    assert_eq!(r[3]["data"], "hello from gotgt", "{}", r[3]);
    assert_eq!(r[4]["status"], "GOOD", "{}", r[4]);
    assert_eq!(r[5]["data"], WRITE_TEXT, "{}", r[5]);
    let d = wait_for_write(&disk).await;
    assert!(
        d[51200 + WRITE_TEXT.len()..51712].iter().all(|b| *b == 0),
        "zero-padded to the block"
    );
    wait_event(&state, id, "iscsi_logged_out", 0).await;
}

#[cfg(target_os = "linux")]
mod tgtd {
    use super::*;

    fn require_root() {
        assert!(
            unsafe { libc::geteuid() } == 0, // SAFETY: geteuid has no preconditions.
            "tgtd needs root: the iscsi pair job runs this binary through sudo"
        );
    }

    const TARGET: &str = "iqn.2026-10.org.tgt:netget-disk";

    async fn tgtadm(control: u16, args: &[&str]) {
        let tgtadm = find_binary("tgtadm", "NETGET_TGTADM", "apt-get install tgt");
        let out = tokio::process::Command::new(tgtadm)
            .arg("-C")
            .arg(control.to_string())
            .args(args)
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "tgtadm {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[tokio::test]
    async fn tgtd_answers_the_models_task_management() {
        require_root();
        let tgtd = find_binary("tgtd", "NETGET_TGTD", "apt-get install tgt");
        let dir = tempfile::tempdir().unwrap();
        let disk = backing_file(dir.path(), "hello from tgt");
        let port = free_port();
        // Its own control port: the other tgtd test may be running at the same time.
        let control: u16 = 18;
        let log_path = dir.path().join("tgtd.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let tgtd_log = || {
            format!(
                "\n--- tgtd -d 1 ---\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            )
        };
        let _daemon = tokio::process::Command::new(&tgtd)
            .args([
                "-f",
                "-d",
                "1",
                "-C",
                &control.to_string(),
                "--iscsi",
                &format!("portal=127.0.0.1:{port}"),
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        wait_for_port(port).await;
        for args in [
            vec![
                "--lld", "iscsi", "--op", "new", "--mode", "target", "--tid", "1", "-T", TARGET,
            ],
            vec![
                "--lld",
                "iscsi",
                "--op",
                "new",
                "--mode",
                "logicalunit",
                "--tid",
                "1",
                "--lun",
                "1",
                "-b",
                disk.to_str().unwrap(),
            ],
            vec![
                "--lld", "iscsi", "--op", "bind", "--mode", "target", "--tid", "1", "-I", "ALL",
            ],
        ] {
            tgtadm(control, &args).await;
        }
        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"initiator_name": "iqn.2026-10.net.netget:tgt-tmf", "target_name": TARGET}),
            chain(&stepping_policy(&dir.path().join("step"), &tmf_steps(1))),
        )
        .await
        .unwrap();
        let r = tmf_results(&state, id, 7).await;
        // tgt 1.0.85 (usr/iscsi/iscsid.c iscsi_tm_execute): ABORT TASK, ABORT TASK SET and LUN
        // RESET reach the target; CLEAR ACA, CLEAR TASK SET and both target resets are "not
        // supported", and the session goes on.
        let want = [
            ("abort_task", "task_does_not_exist"),
            ("abort_task_set", "function_complete"),
            ("clear_aca", "function_not_supported"),
            ("clear_task_set", "function_not_supported"),
            ("logical_unit_reset", "function_complete"),
            ("target_warm_reset", "function_not_supported"),
            ("target_cold_reset", "function_not_supported"),
        ];
        let got: Vec<(&str, &str)> = r.iter().map(|(f, s)| (f.as_str(), s.as_str())).collect();
        assert_eq!(got, want, "{}", tgtd_log());
        // tgt sets POWER ON, RESET, OR BUS DEVICE RESET OCCURRED on a new nexus and again on
        // its LUN reset: the first TEST UNIT READY after each reports it, the next is GOOD.
        let c = results(&state, id, 4).await;
        let ua = |r: &serde_json::Value| {
            r["sense"]
                .as_str()
                .is_some_and(|s| s.contains("POWER ON, RESET, OR BUS DEVICE RESET OCCURRED"))
        };
        assert!(ua(&c[0]) && ua(&c[2]), "{c:?}{}", tgtd_log());
        assert_eq!(
            (&c[1]["status"], &c[3]["status"]),
            (&json!("GOOD"), &json!("GOOD"))
        );
        let out = wait_event(&state, id, "iscsi_logged_out", 0).await;
        assert_eq!(out["reason"], "logged out", "{}", tgtd_log());
    }

    #[tokio::test]
    async fn tgtd_serves_the_models_session_with_chap_and_mutual_chap() {
        require_root();
        let tgtd = find_binary("tgtd", "NETGET_TGTD", "apt-get install tgt");
        let dir = tempfile::tempdir().unwrap();
        let disk = backing_file(dir.path(), "hello from tgt");
        let port = free_port();
        let control: u16 = 17;
        // tgtd's own debug log goes to a file, and every assertion below prints it: tgtd says
        // why it refused a login only there, never on the wire.
        let log_path = dir.path().join("tgtd.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let tgtd_log = || {
            format!(
                "\n--- tgtd -d 1 ---\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            )
        };
        let _daemon = tokio::process::Command::new(&tgtd)
            .args([
                "-f",
                "-d",
                "1",
                "-C",
                &control.to_string(),
                "--iscsi",
                &format!("portal=127.0.0.1:{port}"),
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        wait_for_port(port).await;
        tgtadm(
            control,
            &[
                "--lld", "iscsi", "--op", "new", "--mode", "target", "--tid", "1", "-T", TARGET,
            ],
        )
        .await;
        tgtadm(
            control,
            &[
                "--lld",
                "iscsi",
                "--op",
                "new",
                "--mode",
                "logicalunit",
                "--tid",
                "1",
                "--lun",
                "1",
                "-b",
                disk.to_str().unwrap(),
            ],
        )
        .await;
        tgtadm(
            control,
            &[
                "--lld", "iscsi", "--op", "bind", "--mode", "target", "--tid", "1", "-I", "ALL",
            ],
        )
        .await;
        // tgt's own digest setting is None, which it answers to an offer of CRC32C alone.
        for key in ["HeaderDigest", "DataDigest"] {
            tgtadm(
                control,
                &[
                    "--lld", "iscsi", "--op", "update", "--mode", "target", "--tid", "1", "--name",
                    key, "--value", "CRC32C",
                ],
            )
            .await;
        }
        tgtadm(
            control,
            &[
                "--lld",
                "iscsi",
                "--op",
                "new",
                "--mode",
                "account",
                "--user",
                "alice",
                "--password",
                "wonderland12",
            ],
        )
        .await;
        tgtadm(
            control,
            &[
                "--lld", "iscsi", "--op", "bind", "--mode", "account", "--tid", "1", "--user",
                "alice",
            ],
        )
        .await;
        tgtadm(
            control,
            &[
                "--lld",
                "iscsi",
                "--op",
                "new",
                "--mode",
                "account",
                "--user",
                "tgt-target",
                "--password",
                "targetsecret1",
            ],
        )
        .await;
        tgtadm(
            control,
            &[
                "--lld",
                "iscsi",
                "--op",
                "bind",
                "--mode",
                "account",
                "--tid",
                "1",
                "--user",
                "tgt-target",
                "--outgoing",
            ],
        )
        .await;

        // tgt's LUN 0 is its controller; the disk is LUN 1. Both digests are offered as
        // "None,CRC32C": tgt negotiates a discovery session from its global setting, None,
        // and the normal session from the target's, CRC32C, which is asserted below.
        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"chap_name": "alice", "chap_secret": "wonderland12",
                   "target_chap_name": "tgt-target", "target_chap_secret": "targetsecret1",
                   "digests": "either"}),
            chain(&session_policy(1)),
        )
        .await
        .unwrap();
        let targets = wait_event(&state, id, "iscsi_targets", 0).await;
        assert_eq!(
            targets["targets"][0]["name"],
            TARGET,
            "{targets}{}",
            tgtd_log()
        );
        let login = wait_event(&state, id, "iscsi_login_result", 0).await;
        assert_eq!(login["logged_in"], true, "{login}{}", tgtd_log());
        assert_eq!(
            login["negotiated"]["data_digest"],
            "CRC32C",
            "{login}{}",
            tgtd_log()
        );
        let r = results(&state, id, 6).await;
        assert_eq!(r[0]["luns"], json!([0, 1]), "{}{}", r[0], tgtd_log());
        assert_eq!(r[3]["data"], "hello from tgt", "{}{}", r[3], tgtd_log());
        assert_eq!(r[5]["data"], WRITE_TEXT, "{}{}", r[5], tgtd_log());
        wait_for_write(&disk).await;

        // A wrong secret is refused by tgtd.
        let (state, id) = client(
            format!("127.0.0.1:{port}"),
            json!({"target_name": TARGET, "chap_name": "alice", "chap_secret": "not-the-secret1"}),
            chain(r#"import json,sys
i=json.load(sys.stdin)
print(json.dumps({'actions':[{'type':'iscsi_login'}] if i['event_type_id']=='iscsi_connected' else []}))"#),
        )
        .await
        .unwrap();
        let login = wait_event(&state, id, "iscsi_login_result", 0).await;
        assert_eq!(login["logged_in"], false, "{login}{}", tgtd_log());
        assert_eq!(login["status"], "0x0201", "{login}{}", tgtd_log());
    }
}
