//! The r-service servers against the real clients: GNU inetutils (`grexec`, `grsh`,
//! `grlogin` — Homebrew's names, and the names `scripts/test-peers/build-inetutils.sh` builds
//! with) and rsh-redone (`rsh-redone-rsh`, `rsh-redone-rlogin`, Debian/Ubuntu's
//! `rsh-redone-client`). Every test fails, never skips, when its client is missing.
//!
//! rexec needs no privilege and runs wherever inetutils is installed. rsh and rlogin clients
//! bind a reserved source port, which takes root, and inetutils' pair connect to the fixed
//! ports 514 and 513 (`getservbyname`), so those tests are Linux-only and run as root — the
//! `rsh` pair job runs this binary through sudo — each on its own loopback address so they
//! can share the ports. Under root they also capture loopback and hand the real clients'
//! traffic to tshark's dissectors, the urgent byte included.
use super::support::*;
use serde_json::json;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// A peer binary on PATH, or a failure that says how to install it.
pub fn require(names: &[&str], install: &str) -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for name in names {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    panic!(
        "none of {names:?} is on PATH. Install it: {install}. This test fails rather than \
         skips: a missing client would otherwise leave the evidence resting on nothing."
    );
}

pub const INETUTILS: &str = "brew install inetutils (macOS: grexec, grsh, grlogin), or on Linux \
     scripts/test-peers/build-inetutils.sh <dir> and put <dir>/bin on PATH";

const REXEC_REAL: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
c=e['command']
if c.startswith('rm'):
  a=[{'type':'rexec_refuse','message':'rm: Permission denied'}]
else:
  a=[{'type':'rexec_output','stdout':'%s ran %s\n'%(e['user'],c),'stderr':'stderr of %s\n'%c}]
print(json.dumps({'actions':a}))"#;

async fn run(program: &PathBuf, args: &[&str]) -> std::process::Output {
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("{}: {e}", program.display()));
    tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{} did not finish", program.display()))
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[tokio::test]
async fn inetutils_rexec_runs_commands_and_is_refused_a_wrong_password() {
    let rexec = require(&["grexec"], INETUTILS);
    let srv = start(
        "rexec",
        policy(REXEC_REAL),
        Some(json!({"accounts": [{"user": "alice", "password": "wonderland"}]})),
    )
    .await;
    let port = srv.port.to_string();
    let base = ["-h", "127.0.0.1", "-P", &port, "-u", "alice"];

    // With the stderr connection: stdout and stderr arrive on their own streams.
    let mut args = base.to_vec();
    args.extend(["-p", "wonderland", "uname -a"]);
    let out = run(&rexec, &args).await;
    assert!(out.status.success(), "{out:?}");
    assert_eq!(text(&out.stdout), "alice ran uname -a\n");
    assert_eq!(text(&out.stderr), "stderr of uname -a\n");

    // -n: no stderr connection, so stderr follows stdout on the main one.
    let mut args = base.to_vec();
    args.extend(["-n", "-p", "wonderland", "id"]);
    let out = run(&rexec, &args).await;
    assert!(out.status.success(), "{out:?}");
    assert_eq!(text(&out.stdout), "alice ran id\nstderr of id\n");

    // The model's refusal and NetGet's password check both reach the user as rexecd's would.
    let mut args = base.to_vec();
    args.extend(["-p", "wonderland", "rm -rf /"]);
    let out = run(&rexec, &args).await;
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(all.contains("rm: Permission denied"), "{out:?}");
    let mut args = base.to_vec();
    args.extend(["-p", "not-it", "id"]);
    let out = run(&rexec, &args).await;
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(all.contains("Login incorrect."), "{out:?}");
    assert!(!all.contains("ran id"));

    let seen = events(&srv.state, srv.id, "rexec_command").await;
    let commands: Vec<&str> = seen
        .iter()
        .map(|e| e["command"].as_str().unwrap())
        .collect();
    assert_eq!(
        commands,
        ["uname -a", "id", "rm -rf /"],
        "the wrong password never asked"
    );
    assert_eq!(seen[0]["stderr_channel"], true);
    assert_eq!(seen[1]["stderr_channel"], false);
    assert!(!access_log_text(&srv.state, srv.id)
        .await
        .contains("wonderland"));
}

#[cfg(target_os = "linux")]
mod as_root {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// Loopback addresses of their own, so the root tests can all hold ports 513 and 514.
    const RSH_HOST: &str = "127.0.0.31";
    const RLOGIN_HOST: &str = "127.0.0.32";

    pub fn require_root() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "rsh and rlogin clients bind a reserved source port and inetutils' connect to the \
             fixed ports 513/514, so this test runs as root (the rsh pair job runs the test \
             binary through sudo: CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E')"
        );
    }

    const RSH_REAL: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
if e['server_user']!='alice' or not e['reserved_source_port']:
  a=[{'type':'rsh_refuse','message':'Permission denied.'}]
else:
  a=[{'type':'rsh_output','stdout':'%s as %s ran %s\n'%(e['client_user'],e['server_user'],e['command']),'stderr':'stderr of %s\n'%e['command']}]
print(json.dumps({'actions':a}))"#;

    #[tokio::test]
    async fn inetutils_rsh_and_rsh_redone_run_commands_from_reserved_ports() {
        require_root();
        let grsh = require(&["grsh"], INETUTILS);
        let redone = require(&["rsh-redone-rsh"], "apt-get install rsh-redone-client");
        let capture = crate::helpers::live_capture::LiveCapture::start("lo");
        let srv = start_on("rsh", RSH_HOST, 514, policy(RSH_REAL), None).await;

        let out = run(&grsh, &["-l", "alice", RSH_HOST, "uname", "-a"]).await;
        assert!(out.status.success(), "{out:?}");
        assert_eq!(text(&out.stdout), "root as alice ran uname -a\n");
        assert_eq!(
            text(&out.stderr),
            "stderr of uname -a\n",
            "over the stderr connection"
        );
        let out = run(&grsh, &["-l", "root", RSH_HOST, "id"]).await;
        assert!(!out.status.success());
        assert!(text(&out.stderr).contains("Permission denied."), "{out:?}");

        let out = run(&redone, &["-p", "514", "-l", "alice", RSH_HOST, "hostname"]).await;
        assert!(out.status.success(), "{out:?}");
        assert_eq!(text(&out.stdout), "root as alice ran hostname\n");
        assert_eq!(text(&out.stderr), "stderr of hostname\n");

        let seen = events(&srv.state, srv.id, "rsh_command").await;
        assert_eq!(seen.len(), 3);
        for e in &seen {
            assert_eq!(e["reserved_source_port"], true, "{e}");
            assert_eq!(e["stderr_channel"], true, "{e}");
            assert_eq!(e["client_user"], "root");
        }

        let mut capture = capture;
        assert!(
            capture.wait_for("00:00:00:00:00:00", "rsh.command", "hostname", 10),
            "tshark never read rsh-redone's command"
        );
        capture.stop();
        let rows = capture.fields(&[
            "ip.src",
            "tcp.srcport",
            "frame.protocols",
            "_ws.expert.severity",
            "rsh.client_username",
            "rsh.server_username",
            "rsh.command",
        ]);
        judge(&rows, 514, "rsh");
        let commands: Vec<&String> = rows
            .iter()
            .filter_map(|r| r.get(7))
            .filter(|c| !c.is_empty())
            .collect();
        for want in ["uname -a", "id", "hostname"] {
            assert!(
                commands.iter().any(|c| *c == want),
                "{want} not dissected: {commands:?}"
            );
        }
    }

    /// Every packet to or from `port` must dissect as `proto` (when it carries data) with no
    /// Expert Info at Warn or above. Columns: eth.src, ip.src, tcp.srcport, protocols,
    /// severities, ...
    fn judge(rows: &[Vec<String>], port: u16, proto: &str) {
        let port = port.to_string();
        let mut dissected = 0;
        for r in rows {
            let ours = r.get(2) == Some(&port);
            let chain = r.get(3).cloned().unwrap_or_default();
            if !chain.contains(&format!(":{proto}")) {
                continue;
            }
            dissected += 1;
            let severities: Vec<u64> = r
                .get(4)
                .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
                .unwrap_or_default();
            assert!(
                severities.iter().all(|s| *s < 0x0060_0000),
                "tshark flagged a {} {proto} packet: {r:?}",
                if ours { "server" } else { "client" }
            );
        }
        assert!(dissected > 2, "no {proto} packets were dissected: {rows:?}");
    }

    /// A child on a pty of `rows`×`cols`, with everything it prints gathered by a thread.
    struct OnPty {
        pty: pty_process::blocking::Pty,
        out: Arc<Mutex<Vec<u8>>>,
        child: std::process::Child,
    }

    impl OnPty {
        fn spawn(program: &PathBuf, args: &[&str], rows: u16, cols: u16) -> Self {
            let pair = nix::pty::openpty(None, None).unwrap();
            // SAFETY: the descriptors come straight from openpty and are owned here.
            let pty = unsafe { pty_process::blocking::Pty::from_fd(pair.master) };
            let pts = unsafe { pty_process::blocking::Pts::from_fd(pair.slave) };
            pty.resize(pty_process::Size::new(rows, cols)).unwrap();
            let mut cmd = pty_process::blocking::Command::new(program);
            for a in args {
                cmd = cmd.arg(a);
            }
            cmd = cmd.env("TERM", "xterm");
            let child = cmd.spawn(pts).unwrap();
            let out = Arc::new(Mutex::new(Vec::new()));
            use std::os::fd::{AsRawFd, FromRawFd};
            let reader_fd = nix::unistd::dup(pty.as_raw_fd()).unwrap();
            // SAFETY: a fresh descriptor from dup(2), owned by this File alone.
            let mut reader = unsafe { std::fs::File::from_raw_fd(reader_fd) };
            let sink = out.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            Self { pty, out, child }
        }

        fn screen(&self) -> String {
            String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
        }

        async fn wait_for(&self, needle: &str) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            while !self.screen().contains(needle) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{needle:?} never appeared; the terminal shows:\n{}",
                    self.screen()
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        fn type_text(&mut self, s: &str) {
            self.pty.write_all(s.as_bytes()).unwrap();
            self.pty.flush().unwrap();
        }

        async fn exited(&mut self) -> bool {
            for _ in 0..200 {
                if let Ok(Some(_)) = self.child.try_wait() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        }
    }

    impl Drop for OnPty {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// rlogind's rule as a policy: alice is trusted from a reserved port, bob gives a
    /// password, anyone else is refused; then a tiny shell.
    const RLOGIN_REAL: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='rlogin_login':
  u=e['server_user']
  if u=='alice' and e['reserved_source_port']:
    a=[{'type':'rlogin_trust','banner':'Welcome alice\n','prompt':'$ '}]
  elif u=='bob':
    a=[{'type':'rlogin_ask_password','banner':'Welcome bob\n','prompt':'$ '}]
  else:
    a=[{'type':'rlogin_refuse','message':'rlogind: Permission denied.'}]
elif e['line']=='exit':
  a=[{'type':'rlogin_send_line','line':'logout'},{'type':'close_connection'}]
elif e['line']=='size':
  w=e.get('window') or {}
  a=[{'type':'rlogin_send_text','text':'rows=%s cols=%s\n$ '%(w.get('rows'),w.get('cols'))}]
else:
  a=[{'type':'rlogin_send_text','text':'you typed '+e['line']+'\n$ '}]
print(json.dumps({'actions':a}))"#;

    #[tokio::test]
    async fn inetutils_rlogin_and_rsh_redone_rlogin_sessions_through_a_pty() {
        require_root();
        let grlogin = require(&["grlogin"], INETUTILS);
        let redone = require(&["rsh-redone-rlogin"], "apt-get install rsh-redone-client");
        let capture = crate::helpers::live_capture::LiveCapture::start("lo");
        let srv = start_on(
            "rlogin",
            RLOGIN_HOST,
            513,
            policy(RLOGIN_REAL),
            Some(json!({"accounts": [{"user": "bob", "password": "builder"}]})),
        )
        .await;

        // inetutils as bob: the password path, one wrong try first.
        let mut term = OnPty::spawn(&grlogin, &["-l", "bob", RLOGIN_HOST], 30, 100);
        term.wait_for("Password: ").await;
        term.type_text("wrong\r");
        term.wait_for("Login incorrect").await;
        term.type_text("builder\r");
        term.wait_for("Welcome bob").await;
        term.wait_for("$ ").await;
        term.type_text("size\r");
        term.wait_for("rows=30 cols=100").await;
        term.type_text("hello there\r");
        term.wait_for("you typed hello there").await;
        term.type_text("exit\r");
        term.wait_for("logout").await;
        assert!(
            term.exited().await,
            "grlogin ends with the session:\n{}",
            term.screen()
        );
        assert!(
            !term.screen().contains("builder"),
            "the password was echoed"
        );
        drop(term);

        // rsh-redone as alice: trusted (from a reserved port), no password.
        let mut term = OnPty::spawn(&redone, &["-p", "513", "-l", "alice", RLOGIN_HOST], 40, 120);
        term.wait_for("Welcome alice").await;
        term.wait_for("$ ").await;
        term.type_text("size\r");
        term.wait_for("rows=40 cols=120").await;
        term.type_text("exit\r");
        term.wait_for("logout").await;
        assert!(term.exited().await, "{}", term.screen());
        drop(term);

        let logins = events(&srv.state, srv.id, "rlogin_login").await;
        assert_eq!(logins.len(), 2);
        for (l, user) in logins.iter().zip(["bob", "alice"]) {
            assert_eq!(l["client_user"], "root");
            assert_eq!(l["server_user"], user);
            assert_eq!(l["terminal"], "xterm");
            assert_eq!(l["reserved_source_port"], true, "{l}");
        }
        let lines = events(&srv.state, srv.id, "rlogin_line").await;
        let typed: Vec<&str> = lines.iter().map(|e| e["line"].as_str().unwrap()).collect();
        assert_eq!(typed, ["size", "hello there", "exit", "size", "exit"]);

        let mut capture = capture;
        assert!(
            capture.wait_for("00:00:00:00:00:00", "rlogin.window_size.cols", "120", 10),
            "tshark never read rsh-redone's window size"
        );
        capture.stop();
        let rows = capture.fields(&[
            "ip.src",
            "tcp.srcport",
            "frame.protocols",
            "_ws.expert.severity",
            "rlogin.server_user_name",
            "rlogin.window_size.cols",
            "rlogin.control_message",
        ]);
        judge(&rows, 513, "rlogin");
        let flat = rows.concat();
        assert!(flat.iter().any(|f| f == "bob"), "{rows:?}");
        assert!(
            flat.iter().any(|f| f == "100"),
            "grlogin's window size: {rows:?}"
        );
        assert!(
            flat.iter().any(|f| f == "0x80"),
            "the urgent TIOCPKT_WINDOW byte: {rows:?}"
        );
    }
}
