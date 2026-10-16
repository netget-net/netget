//! Two independent AFP clients against NetGet's server, each through a recording relay so
//! tshark's `dsi` and `afp` dissectors read every byte both ways:
//!
//! - **netatalk 4.6's test clients** (C): `afparg`, which logs in with Cleartxt Passwrd and runs
//!   one AFP operation — a recursive FPEnumerate walk with FPResolveID per file, a read
//!   (FPOpenFork, FPGetForkParms, FPRead), a write (FPCreateFile, FPOpenFork, FPSetForkParms,
//!   FPWrite) — and `asip-status`, which decodes FPGetSrvrInfo. Their AFP client library is
//!   netatalk's own (`test/testsuite/afpcmd.c`), written against netatalk's server.
//! - **Nmap's AFP library** (Lua, `nselib/afp.lua`): `afp-serverinfo`, `afp-showmount` and
//!   `afp-ls`, logging in as a guest with No User Authent and listing with FPEnumerateExt2,
//!   Unix privileges and dates.
//!
//! They fail, rather than skip, when a peer is missing: `brew install netatalk nmap` on macOS;
//! on Ubuntu `sudo apt-get install nmap` and `sh scripts/test-peers/build-netatalk.sh <dir>`
//! (Ubuntu's netatalk package ships neither 4.x nor the test clients), then put `<dir>/bin` on
//! `PATH`. No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, README};
use crate::helpers::real_server::{find_binary, missing_binary, run_tool, InstallHint};
use crate::helpers::recording_relay;
use crate::helpers::E2EResult;
use serde_json::json;
use std::process::Command;

const NETATALK: InstallHint = InstallHint {
    brew: "netatalk",
    apt: "netatalk 4.x with its test suite (Ubuntu's package has neither): run \
          `sh scripts/test-peers/build-netatalk.sh <dir>` and put <dir>/bin on PATH",
};
const NMAP: InstallHint = InstallHint {
    brew: "nmap",
    apt: "nmap",
};

fn tool(name: &str, hint: InstallHint) -> E2EResult<std::path::PathBuf> {
    find_binary(name).ok_or_else(|| missing_binary(name, hint, "not found on PATH"))
}

fn afparg(port: u16, user: &str, password: &str, args: &[&str]) -> E2EResult<Command> {
    let mut c = Command::new(tool("afparg", NETATALK)?);
    c.args([
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-u",
        user,
        "-w",
        password,
        "-s",
        "Share",
        "-f",
    ]);
    c.args(args);
    Ok(c)
}

fn oracle(streams: &std::sync::Arc<std::sync::Mutex<Vec<recording_relay::Recording>>>) {
    let streams = streams.lock().unwrap().clone();
    assert!(!streams.is_empty(), "nothing went through the relay");
    for s in streams {
        let chunks = s.lock().unwrap().clone();
        if chunks.is_empty() {
            continue;
        }
        support::oracle_of(&chunks).assert_clean();
    }
}

#[tokio::test]
async fn netatalks_test_client_logs_in_walks_reads_and_writes() -> E2EResult<()> {
    let s = support::start(
        support::policy(),
        json!({"username": "alice", "password": "pw1234", "server_name": "Studio"}),
    )
    .await;
    let (relay, streams) = recording_relay::tcp_relay(s.addr()).await;
    let port = relay.port();

    // FPGetSrvrInfo, decoded by netatalk's asip-status. Its exit status says whether guests
    // are admitted (1 here), so it is read from stdout rather than from success.
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new(tool("asip-status", NETATALK)?)
            .args(["127.0.0.1", &port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        format!(
            "asip-status did not finish within 30 s; the relay saw {:?}",
            streams
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.lock().unwrap().clone())
                .collect::<Vec<_>>()
        )
    })?
    .map_err(|e| missing_binary("asip-status", NETATALK, e))?;
    let status = String::from_utf8_lossy(&status.stdout).to_string();
    println!("{status}");
    assert!(status.contains("Server name: Studio"), "{status}");
    assert!(status.contains("Machine type: NetGet"), "{status}");
    assert!(
        status.contains("UAMs: No User Authent,Cleartxt Passwrd"),
        "{status}"
    );
    assert!(status.contains("AFP3.4"), "{status}");
    assert!(status.contains("UTF8 Servername: Studio"), "{status}");

    // A recursive walk: every directory enumerated, every file resolved by its ID.
    let walk = run_tool(
        afparg(port, "alice", "pw1234", &["FPEnumerate"])?,
        "afparg",
        NETATALK,
    )
    .await?;
    println!("{walk}");
    for want in ["README.txt", "secret.txt", "docs/", "notes.txt", "empty/"] {
        assert!(
            walk.lines().any(|l| l.trim_end() == want),
            "{want} missing from:\n{walk}\n{}",
            s.log_text()
        );
    }
    assert!(!walk.contains("Can't resolve ID"), "{walk}");

    // A read: the bytes the model gave, all of them.
    let read = run_tool(
        afparg(port, "alice", "pw1234", &["FPRead", "README.txt"])?,
        "afparg",
        NETATALK,
    )
    .await?;
    assert!(read.contains(&format!("DATA:{README}")), "{read}");
    let reads = s.events("afp_read_file").await;
    assert_eq!(reads.last().unwrap()["path"], "README.txt");
    assert_eq!(reads.last().unwrap()["user"], "alice");

    // A write: create, truncate, write — each the model's decision, the data as written.
    let write = run_tool(
        afparg(
            port,
            "alice",
            "pw1234",
            &["FPWrite", "upload.txt", "written by afparg"],
        )?,
        "afparg",
        NETATALK,
    )
    .await?;
    println!("{write}");
    let creates = s.events("afp_create").await;
    assert_eq!(creates[0]["path"], "upload.txt", "{}", s.log_text());
    assert_eq!(creates[0]["kind"], "file");
    let writes = s.events("afp_write_file").await;
    let data: Vec<&str> = writes.iter().filter_map(|w| w["data"].as_str()).collect();
    assert_eq!(data, ["written by afparg"], "{writes:?}");

    // A wrong password is refused by NetGet, and the model never sees it.
    let mut cmd = tokio::process::Command::from(afparg(port, "alice", "wrong", &["FPEnumerate"])?);
    cmd.arg("-V").kill_on_drop(true);
    let refused = tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output())
        .await
        .map_err(|_| {
            format!(
                "afparg with a wrong password did not finish:\n{}",
                s.log_text()
            )
        })?
        .map_err(|e| missing_binary("afparg", NETATALK, e))?;
    let out = String::from_utf8_lossy(&refused.stdout).to_string();
    assert!(!refused.status.success(), "{out}");
    assert!(out.contains("Login failed"), "{out}\n{}", s.log_text());
    assert!(s.log_text().contains("decision=login_refused"));
    let everything = serde_json::to_string(&s.all_events().await)?;
    assert!(!everything.contains("pw1234"));

    oracle(&streams);
    Ok(())
}

#[tokio::test]
async fn nmaps_afp_scripts_read_the_server_and_list_a_volume_as_a_guest() -> E2EResult<()> {
    let s = support::start(support::policy(), json!({"server_name": "Studio"})).await;
    let (relay, streams) = recording_relay::tcp_relay(s.addr()).await;
    let port = relay.port();
    // Nmap runs its AFP scripts on port 548 or a port its services file calls "afp". A data
    // directory holding only that file overrides the services file and nothing else
    // (`--servicedb` would also imply a fast scan, which refuses `-p`).
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("nmap-services"),
        format!("afp\t{port}/tcp\t0.5\t# AFP over TCP\n"),
    )?;
    let mut c = Command::new(tool("nmap", NMAP)?);
    c.args(["-Pn", "-n", "-sT", "-p", &port.to_string(), "--datadir"])
        .arg(dir.path())
        .args([
            "--script",
            "afp-serverinfo,afp-showmount,afp-ls",
            "--script-args",
            "ls.maxfiles=0",
            "127.0.0.1",
        ]);
    let out = run_tool(c, "nmap", NMAP).await?;
    println!("{out}");
    assert!(out.contains("Server Name: Studio"), "{out}");
    assert!(out.contains("Machine Type: NetGet"), "{out}");
    assert!(out.contains("UAMs: No User Authent"), "{out}");
    assert!(out.contains("AFP3.4"), "{out}");
    // afp-showmount: both volumes. afp-ls: the root of each, with Unix modes and sizes.
    assert!(out.contains("Share"), "{out}");
    assert!(out.contains("Archive"), "{out}");
    let line = |name: &str| {
        out.lines()
            .find(|l| l.trim_end().ends_with(name))
            .unwrap_or_else(|| panic!("no {name} in:\n{out}\n{}", s.log_text()))
            .to_string()
    };
    let readme = line("README.txt");
    assert!(readme.contains("-rw-r--r--"), "{readme}");
    assert!(readme.contains(" 18 "), "{readme}");
    assert!(readme.contains("2026-01-02T03:04:05"), "{readme}");
    assert!(line("secret.txt").contains("-rw-------"));
    assert!(line("docs").contains("drwxr-xr-x"));
    oracle(&streams);
    Ok(())
}
