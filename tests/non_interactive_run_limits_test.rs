//! Non-interactive runs end when they should: `--run-for`, `--exit-after-events`, every server
//! served, a `--load`ed client kept alive until it disconnects, and a failed start reported as
//! a failure.
//!
//! Drives the real binary (`CARGO_BIN_EXE_netget`) with `--load` files, because every one of
//! these is about when the *process* exits and with what status. No model: every server and
//! client here is answered by a static handler, and `--ollama-url` points at a closed port so
//! an accidental model call would fail loudly rather than reach a real backend.
//!
//! Each child runs in its own temp directory (netget writes `netget.log` into its working
//! directory) and is tied to this test binary's life by `child_guard`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test non_interactive_run_limits_test -- --test-threads=100


#[path = "helpers/child_guard.rs"]
mod child_guard;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A spawned netget with its stdout lines streamed to a channel.
struct Netget {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    _dir: PathBuf,
}

impl Netget {
    fn spawn(name: &str, actions: serde_json::Value, extra: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "netget-run-limits-{}-{}-{}",
            name,
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("run.netget");
        std::fs::write(&file, serde_json::json!({ "actions": actions }).to_string())
            .expect("write load file");

        let mut args = vec![
            "--load".to_string(),
            file.to_string_lossy().to_string(),
            "--ollama-url".to_string(),
            "http://127.0.0.1:1".to_string(),
            "--log-level".to_string(),
            "error".to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));

        let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
            .args(&args)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn netget");
        child_guard::tie_child(child.id());

        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines: rx,
            seen: Vec::new(),
            _dir: dir,
        }
    }

    /// Wait for a stdout line containing `needle`; returns it.
    fn wait_line(&mut self, needle: &str, within: Duration) -> String {
        if let Some(line) = self.seen.iter().find(|l| l.contains(needle)) {
            return line.clone();
        }
        let deadline = Instant::now() + within;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(_) => break,
            }
        }
        panic!(
            "no stdout line containing {needle:?} within {within:?}; saw:\n{}",
            self.seen.join("\n")
        );
    }

    /// Every stdout line so far containing `needle`, draining what has arrived.
    fn lines_containing(&mut self, needle: &str) -> Vec<String> {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen
            .iter()
            .filter(|l| l.contains(needle))
            .cloned()
            .collect()
    }

    fn exited(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    /// Wait for the process to exit; panics (and kills it) if it does not within `within`.
    fn wait_exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.exited() {
                child_guard::untie_child(self.child.id());
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                child_guard::untie_child(self.child.id());
                panic!(
                    "netget did not exit within {within:?}; stdout:\n{}",
                    self.seen.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn stderr(&mut self) -> String {
        let mut err = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut err);
        }
        err
    }

    /// Assert the process is still running throughout `window`.
    fn assert_alive_for(&mut self, window: Duration, why: &str) {
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            if let Some(status) = self.exited() {
                panic!(
                    "netget exited ({status}) but {why}; stdout:\n{}",
                    self.seen.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Netget {
    fn drop(&mut self) {
        if self.exited().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        child_guard::untie_child(self.child.id());
    }
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn port_in(line: &str) -> u16 {
    line.rsplit(':')
        .next()
        .and_then(|p| {
            p.trim_end_matches('.')
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no port in {line:?}"))
}

/// A TCP echo server answered by a static handler — no model.
fn echo_server() -> serde_json::Value {
    serde_json::json!({
        "type": "open_server",
        "protocol": "tcp",
        "port": 0,
        "instruction": "echo",
        "event_handlers": [{
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [
                {"type": "send_tcp_data", "data": "{{event.data}}"}
            ]}
        }]
    })
}

fn exchange(port: u16, line: &[u8]) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(line).expect("write");
    let mut buf = vec![0u8; line.len()];
    stream.read_exact(&mut buf).expect("echo arrives");
    assert_eq!(buf, line, "the echo handler answered");
}

#[test]
fn run_for_exits_zero_when_the_duration_elapses() {
    let began = Instant::now();
    let mut netget = Netget::spawn(
        "run-for",
        serde_json::json!([echo_server()]),
        &["--run-for", "2"],
    );
    netget.wait_line("is running on 127.0.0.1:", Duration::from_secs(20));
    let running = Instant::now();
    // RunLimits begins inside the non-interactive runner, after process launch, argument
    // parsing, logging and settings loading. Charging those unrelated startup costs to its
    // two-second scheduling allowance made a healthy run fail at 4.06s under suite load.
    // Once the server is running, at most the requested two seconds remain. Keep the same
    // two-second scheduling allowance, and measure teardown separately so a slow shutdown
    // cannot hide in a generous process-start timeout.
    netget.wait_line("--run-for 2s elapsed", Duration::from_secs(4));
    let deadline = Instant::now();
    let status = netget.wait_exit(Duration::from_secs(2));
    let exited = Instant::now();
    eprintln!(
        "run-for phases: launch/startup={:?}, running-to-deadline={:?}, shutdown={:?}, total={:?}",
        running.duration_since(began),
        deadline.duration_since(running),
        exited.duration_since(deadline),
        exited.duration_since(began),
    );
    assert!(status.success(), "exit status {status}");
    assert!(
        exited.duration_since(began) >= Duration::from_secs(2),
        "--run-for 2 must not end the run early"
    );
}

#[test]
fn restored_global_task_keeps_cli_alive_and_reaches_the_task_ticker() {
    let mut netget = Netget::spawn(
        "global-task-only",
        serde_json::json!([{
            "type": "restore_session",
            "session": {
                "version": 2,
                "resources": [],
                "global_tasks": [{
                    "task_id": "restored-global-fixture",
                    "recurring": false,
                    "delay_secs": 1,
                    "instruction": "model availability failure is expected in this fixture"
                }]
            }
        }]),
        &["--run-for", "3"],
    );
    netget.wait_line("Configuration loaded successfully", Duration::from_secs(20));
    netget.assert_alive_for(
        Duration::from_millis(200),
        "a future global task keeps the run alive",
    );
    // The fixture endpoint is 127.0.0.1:1. Observing dispatch proves the ticker
    // runs; model availability can fail without contacting an actual model.
    netget.wait_line(
        "[TASK] Executing task 'restored-global-fixture'",
        Duration::from_secs(10),
    );
    assert!(netget.wait_exit(Duration::from_secs(10)).success());
}

/// Two servers, `--exit-after-events 2`: both are reported and served, the first exchange does
/// not end the run, the second (on the other server) does.
#[test]
fn exit_after_events_counts_events_across_every_server() {
    let mut netget = Netget::spawn(
        "events",
        serde_json::json!([echo_server(), echo_server()]),
        &["--exit-after-events", "2"],
    );
    netget.wait_line("Waiting for connections", Duration::from_secs(20));
    let running = netget.lines_containing("is running on 127.0.0.1:");
    assert_eq!(
        running.len(),
        2,
        "every server is reported, not only the first: {:?}",
        netget.seen
    );
    let first = port_in(&running[0]);
    let second = port_in(&running[1]);
    assert_ne!(first, second);

    exchange(second, b"one\n");
    netget.assert_alive_for(
        Duration::from_millis(600),
        "one handled event must not satisfy --exit-after-events 2",
    );
    exchange(first, b"two\n");
    let status = netget.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "exit status {status}");
    assert!(
        !netget.lines_containing("--exit-after-events 2").is_empty(),
        "the run says why it stopped: {:?}",
        netget.seen
    );
}

/// A `--load`ed client keeps the process alive while it is connected, and the process exits
/// once the client disconnects.
#[test]
fn loaded_client_runs_until_it_disconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let mut netget = Netget::spawn(
        "client",
        serde_json::json!([{
            "type": "open_client",
            "protocol": "tcp",
            "remote_addr": format!("127.0.0.1:{port}"),
            "instruction": "say nothing",
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
            ]
        }]),
        &[],
    );
    listener.set_nonblocking(false).expect("blocking listener");
    let (peer, _) = listener.accept().expect("the client connects");
    netget.wait_line("Configuration loaded successfully", Duration::from_secs(20));
    netget.assert_alive_for(
        Duration::from_secs(1),
        "a loaded client that is still connected must keep the run alive",
    );

    drop(peer);
    let status = netget.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "exit status {status}");
}

/// A server that cannot start makes the run fail rather than report success.
#[test]
fn a_server_that_fails_to_start_exits_non_zero() {
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = taken.local_addr().expect("addr").port();
    let mut netget = Netget::spawn(
        "fail",
        serde_json::json!([{
            "type": "open_server", "protocol": "tcp", "port": port, "instruction": "echo"
        }]),
        &["--run-for", "30"],
    );
    let status = netget.wait_exit(Duration::from_secs(20));
    let stderr = netget.stderr();
    assert!(
        !status.success(),
        "a failed start must exit non-zero; stdout: {:?} stderr: {stderr}",
        netget.seen
    );
    assert!(
        stderr.contains("failed to start"),
        "the failure is reported: {stderr}"
    );
    drop(taken);
}
