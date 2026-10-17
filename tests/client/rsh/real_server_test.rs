//! The r-service clients against the real daemons: GNU inetutils' `rshd`, `rlogind` and
//! `rexecd` (named `grshd`, `grlogind`, `grexecd` as Homebrew and
//! `scripts/test-peers/build-inetutils.sh` install them) and rsh-redone's `in.rshd` and
//! `in.rlogind` (Ubuntu's `rsh-redone-server`), each run the only way they run — from inetd,
//! here `inetd.py`, a one-service inetd that hands each connection to a fresh daemon as its
//! stdin, stdout and stderr.
//!
//! Linux and root only: the daemons switch to the account they log into, read its `.rhosts`
//! and the shadow file, and refuse a client whose source port is not reserved — so NetGet's
//! client has to be root too, which is the point: it is the reserved-port path a stock rshd
//! demands. The test creates the account `rshtest` (password `rsh-test-pw`, `.rhosts` trusting
//! client user `alice` from localhost). Every daemon missing is a failure, never a skip.
use super::e2e_test::{client, client_events, wait_event};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

const USER: &str = "rshtest";
const PASSWORD: &str = "rsh-test-pw";

const INETUTILS: &str = "scripts/test-peers/build-inetutils.sh <dir>, then put <dir>/bin and \
     <dir>/libexec on PATH (Homebrew's inetutils has them too, as g-prefixed names, but the \
     daemons need Linux root)";
const REDONE: &str = "apt-get install rsh-redone-server";

/// A daemon on PATH or in the sbin/libexec directories daemons live in.
fn require_daemon(names: &[&str], install: &str) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(
        [
            "/usr/sbin",
            "/usr/libexec",
            "/usr/local/libexec",
            "/usr/local/sbin",
        ]
        .map(PathBuf::from),
    );
    for name in names {
        for d in &dirs {
            if d.join(name).is_file() {
                return d.join(name);
            }
        }
    }
    panic!(
        "none of {names:?} is installed. Install it: {install}. This test fails rather than \
         skips: a missing peer would otherwise leave the evidence resting on nothing."
    );
}

fn require_root() {
    assert!(
        unsafe { libc::geteuid() } == 0, // SAFETY: geteuid has no preconditions.
        "the r-service daemons and a reserved source port need root: the rsh pair job runs \
         this binary through sudo"
    );
}

fn sh(script: &str) {
    let status = std::process::Command::new("sh")
        .args(["-c", script])
        .status()
        .unwrap();
    assert!(status.success(), "setup failed: {script}");
}

/// The account the daemons log into, with a password for rexecd and a `.rhosts` for rshd
/// and rlogind. Idempotent.
fn account() {
    sh(&format!(
        "id {USER} >/dev/null 2>&1 || useradd -m -s /bin/sh {USER}; \
         echo '{USER}:{PASSWORD}' | chpasswd; \
         printf 'localhost alice\\n127.0.0.1 alice\\n' > ~{USER}/.rhosts; \
         chown {USER} ~{USER}/.rhosts; chmod 600 ~{USER}/.rhosts; chmod 755 ~{USER}; \
         grep -q '^127.0.0.1[[:space:]].*localhost' /etc/hosts || echo '127.0.0.1 localhost' >> /etc/hosts"
    ));
}

/// `daemon` behind `inetd.py` on 127.0.0.1 and a free port; killed on drop.
struct Inetd {
    child: tokio::process::Child,
    port: u16,
}

impl Inetd {
    async fn start(daemon: &PathBuf, args: &[&str]) -> Self {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let script = format!("{}/tests/client/rsh/inetd.py", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("python3")
            .arg(&script)
            .arg("127.0.0.1")
            .arg(port.to_string())
            .arg(daemon)
            .args(args)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("python3 runs inetd.py");
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("inetd.py starts")
            .unwrap();
        assert_eq!(ready.as_deref(), Some("listening"));
        Self { child, port }
    }
}

impl Drop for Inetd {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

const RSH_CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'rsh_run','command':'echo out-$((6*7)); echo err-$((6*7)) >&2; id -un'}] if i['event_type_id']=='rsh_connected' else []
print(json.dumps({'actions':a}))"#;

async fn rsh_against(daemon: &PathBuf, args: &[&str]) {
    let inetd = Inetd::start(daemon, args).await;
    let remote = format!("127.0.0.1:{}", inetd.port);
    let (state, id) = client(
        "rsh",
        remote.clone(),
        json!({"local_user": "alice", "remote_user": USER}),
        Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":RSH_CHAIN}})]),
    )
    .await
    .unwrap();
    let connected = wait_event(&state, id, "rsh_connected", 0).await;
    assert_eq!(connected["reserved_ports"], true);
    let r = wait_event(&state, id, "rsh_result", 0).await;
    assert_eq!(r["accepted"], true, "{} refused: {r}", daemon.display());
    assert_eq!(r["stdout"], format!("out-42\n{USER}\n"), "{r}");
    assert_eq!(r["stderr"], "err-42\n", "over the stderr connection: {r}");
    assert_eq!(r["reserved_source_port"], true);

    // A client user the .rhosts does not list is refused.
    let (state, id) = client(
        "rsh",
        remote,
        json!({"local_user": "mallory", "remote_user": USER, "stderr": false}),
        Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":RSH_CHAIN}})]),
    )
    .await
    .unwrap();
    let r = wait_event(&state, id, "rsh_result", 0).await;
    assert!(
        !r["stdout"].as_str().unwrap_or_default().contains("out-42"),
        "the command ran for an untrusted user: {r}"
    );
    // inetutils rshd refuses with the error byte; rsh-redone's in.rshd sends the go-ahead
    // byte first and then PAM's message, so the refusal is in what it printed.
    let said = format!("{} {}", r["error"], r["stdout"]);
    assert!(
        r["accepted"] == false && !r["error"].as_str().unwrap_or_default().is_empty()
            || said.contains("Authentication failure")
            || said.contains("Permission denied"),
        "{r}"
    );
}

#[tokio::test]
async fn rsh_client_against_inetutils_rshd_and_rsh_redone_in_rshd() {
    require_root();
    account();
    let inetutils = require_daemon(&["grshd", "rshd"], INETUTILS);
    let redone = require_daemon(&["in.rshd"], REDONE);
    rsh_against(&inetutils, &[]).await;
    rsh_against(&redone, &[]).await;
}

#[tokio::test]
async fn rexec_client_against_inetutils_rexecd() {
    require_root();
    account();
    let rexecd = require_daemon(&["grexecd", "rexecd"], INETUTILS);
    let inetd = Inetd::start(&rexecd, &[]).await;
    let remote = format!("127.0.0.1:{}", inetd.port);
    let chain = r#"import json,sys
i=json.load(sys.stdin)
a=[{'type':'rexec_run','command':'echo rexec-$((6*7)); echo oops >&2'}] if i['event_type_id']=='rexec_connected' else []
print(json.dumps({'actions':a}))"#;
    let handlers = Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":chain}}),
    ]);
    let (state, id) = client(
        "rexec",
        remote.clone(),
        json!({"user": USER, "password": PASSWORD}),
        handlers.clone(),
    )
    .await
    .unwrap();
    let r = wait_event(&state, id, "rexec_result", 0).await;
    assert_eq!(r["accepted"], true, "{r}");
    assert_eq!(r["stdout"], "rexec-42\n");
    assert_eq!(r["stderr"], "oops\n");

    let (state, id) = client(
        "rexec",
        remote,
        json!({"user": USER, "password": "wrong"}),
        handlers,
    )
    .await
    .unwrap();
    let r = wait_event(&state, id, "rexec_result", 0).await;
    assert_eq!(r["accepted"], false, "{r}");
    let error = r["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("incorrect"),
        "rexecd's own refusal line: {r}"
    );
}

/// The shell prompt starts the work; `stty size` proves rlogind read the window-size message
/// (the configured 33×111); the echo proves a command ran; exit ends the session.
const RLOGIN_CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='rlogin_output':
  d=e['data']
  if 'rl-42' in d: a=[{'type':'rlogin_send_line','line':'exit'}]
  elif '33 111' in d: a=[{'type':'rlogin_send_line','line':'echo rl-$((6*7))'}]
  elif d.rstrip().endswith('$') or d.rstrip().endswith('#'): a=[{'type':'rlogin_send_line','line':'stty size'}]
print(json.dumps({'actions':a}))"#;

async fn rlogin_against(daemon: &PathBuf, args: &[&str]) {
    let inetd = Inetd::start(daemon, args).await;
    let (state, id) = client(
        "rlogin",
        format!("127.0.0.1:{}", inetd.port),
        json!({"local_user": "alice", "remote_user": USER, "rows": 33, "cols": 111}),
        Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":RLOGIN_CHAIN}})]),
    )
    .await
    .unwrap_or_else(|e| panic!("{} refused the login: {e:#}", daemon.display()));
    let connected = wait_event(&state, id, "rlogin_connected", 0).await;
    assert_eq!(connected["reserved_source_port"], true);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let outs: Vec<Value> = client_events(&state, id, "rlogin_output").await;
        let all: String = outs
            .iter()
            .map(|e| e["data"].as_str().unwrap_or_default().to_string())
            .collect();
        if outs.iter().any(|e| e["closed"] == true) {
            assert!(
                all.contains("33 111"),
                "rlogind never read the window size:\n{all}"
            );
            assert!(all.contains("\nrl-42"), "{all}");
            assert!(
                outs.iter()
                    .any(|e| e["control"].to_string().contains("window_size_requested")),
                "the urgent window request was never seen: {outs:?}"
            );
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} session did not finish:\n{all}",
            daemon.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn rlogin_client_against_inetutils_rlogind_and_rsh_redone_in_rlogind() {
    require_root();
    account();
    let inetutils = require_daemon(&["grlogind", "rlogind"], INETUTILS);
    let redone = require_daemon(&["in.rlogind"], REDONE);
    rlogin_against(&inetutils, &[]).await;
    rlogin_against(&redone, &[]).await;
}
