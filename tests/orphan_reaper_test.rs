//! The test suite must not leave `netget` processes behind when it is killed.
//!
//! Measured 16 September 2026: **78 orphaned `netget` processes** alive on one
//! machine, all at PPID 1, accumulated over ten hours — 73 from
//! `/tmp/vfull/debug/netget` and five from `/tmp/netget-eval-target/debug/netget`,
//! both ordinary `CARGO_TARGET_DIR`s. They hold loopback ports, memory and file
//! descriptors, and they make every later measurement dishonest: a whole day of
//! "load-sensitive flakes" was investigated on a machine quietly carrying dozens
//! of them.
//!
//! Two mechanisms, tested separately here because they fail in different ways:
//!
//! - **The death tie** (`child_guard::arm_death_tie`) — the hard-kill half. A
//!   `Drop` guard cannot be the whole answer, because `Drop` does not run when
//!   the test binary is `SIGKILL`ed. `sigkilled_parent_takes_its_child_with_it`
//!   proves the tie by actually `SIGKILL`ing a parent.
//! - **The sweeper** (`child_guard::is_orphaned_test_netget`) — for what is
//!   already loose. Its predicate is unit-tested below against real `ps` lines,
//!   including the operator's own live `--mcp` session, because `CLAUDE.md`'s
//!   standing rule is that netget processes are never killed and this is the one
//!   narrow exception.
//!
//! # The shape of the hard-kill test
//!
//! A test cannot `SIGKILL` itself and then assert anything, so it re-executes
//! **its own binary** as a worker: the worker runs one hidden `#[test]` (gated on
//! `NETGET_REAP_WORKER`), spawns a child under a death tie, prints the child's
//! pid, and then blocks forever. The outer test reads that pid, `SIGKILL`s the
//! worker, and watches for the child to disappear.
//!
//! `SIGKILL` on the worker is the point: it is the one signal a process cannot
//! handle, so nothing in the worker — not `Drop`, not a panic hook, not an
//! atexit handler — can be what cleans up. Whatever kills the child is outside
//! the worker, which is exactly the claim under test.

// The whole shared harness, because the netget half of this test drives the real
// `start_netget` path — mock Ollama and all. netget refuses to start without a
// reachable backend, so a hand-rolled spawn of the binary exits within a second
// and the test then passes for the wrong reason. It did exactly that once: with
// the reaper deliberately neutered to prove the test could fail, the netget case
// still went green, because its child had died on its own.
mod helpers;

use helpers::child_guard;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// The sweeper's predicate
// ---------------------------------------------------------------------------

/// The maintainer's own session, copied from `ps` on the machine where the 78
/// orphans were found. It satisfies the target-directory rule by construction —
/// `<repo>/target/release/netget` — so the `--mcp` clause is the *only* thing
/// standing between the sweeper and killing the operator's work.
const OPERATOR_MCP_SESSION: &str =
    "/Users/matus/dev/netget/target/release/netget --mcp --openai-url http://127.0.0.1:3625 \
     --model qwen3:8b";

#[test]
fn the_sweeper_never_matches_the_operators_mcp_session() {
    // With a live parent — the normal case.
    assert!(!child_guard::is_orphaned_test_netget(
        8061,
        OPERATOR_MCP_SESSION
    ));

    // And orphaned, which is the case that matters: if the operator's shell or
    // editor exits, their netget reparents to 1 and satisfies both other
    // clauses. `--mcp` must still save it.
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        OPERATOR_MCP_SESSION
    ));

    // The HTTP variant of the same session.
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/Users/matus/dev/netget/target/debug/netget --mcp-http 8931"
    ));
}

#[test]
fn the_sweeper_matches_the_orphans_that_were_actually_found() {
    // 73 of the 78 looked like this: CARGO_TARGET_DIR=/tmp/vfull, so the path
    // has no `target` component at all and only the profile directory says what
    // it is.
    assert!(child_guard::is_orphaned_test_netget(
        1,
        "/tmp/vfull/debug/netget --model qwen3.8:27b-mlx --log-level debug \
         --listen-addr 127.0.0.1 --llm-max-concurrent 1000 listen on port 0 via tcp"
    ));

    // The other five.
    assert!(child_guard::is_orphaned_test_netget(
        1,
        "/tmp/netget-eval-target/debug/netget --server dns --port 41234 serve example.com"
    ));

    // An in-repo debug build, which is what a plain `cargo test` produces.
    assert!(child_guard::is_orphaned_test_netget(
        1,
        "/Users/matus/dev/netget/target/debug/netget --log-level debug"
    ));

    // No arguments at all is still an orphan.
    assert!(child_guard::is_orphaned_test_netget(
        1,
        "/tmp/vreap/debug/netget"
    ));
}

#[test]
fn the_sweeper_leaves_everything_else_alone() {
    // A live parent is the first and cheapest exclusion.
    assert!(!child_guard::is_orphaned_test_netget(
        40123,
        "/tmp/vfull/debug/netget --server tcp --port 0"
    ));

    // An installed binary is not a test build, whoever its parent is.
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/Users/matus/bin/netget --server tcp"
    ));
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/usr/local/bin/netget"
    ));

    // A build under a target dir that is not netget.
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/tmp/vfull/debug/deps/server-1a2b3c4d --test-threads=100"
    ));
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/Users/matus/dev/netget/target/debug/netget-fuzz"
    ));

    // Something merely *mentioning* netget. `cargo` itself is the live example:
    // it runs from a target-adjacent path with netget all over its arguments.
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "cargo test --manifest-path /Users/matus/dev/netget/Cargo.toml"
    ));
    assert!(!child_guard::is_orphaned_test_netget(
        1,
        "/bin/sh -c /tmp/vfull/debug/netget --server tcp"
    ));

    // Degenerate input must not become a kill.
    assert!(!child_guard::is_orphaned_test_netget(1, ""));
    assert!(!child_guard::is_orphaned_test_netget(1, "   "));
    assert!(!child_guard::is_orphaned_test_netget(1, "netget"));
}

/// The predicate is only half the sweeper; the other half is reading `ps`
/// correctly, and a parser that silently produced nothing would make the
/// predicate untestable in production. So: assert the table parses, and *report*
/// rather than assert on what it matches.
#[test]
fn the_sweeper_reads_the_real_process_table() {
    let table = child_guard::process_table();
    assert!(
        table.len() > 5,
        "ps returned {} rows, which means it was not parsed at all",
        table.len()
    );
    // Every row must have a plausible pid and a non-empty command.
    for row in table.iter().take(20) {
        assert!(row.pid > 0, "bad pid in row {:?}", row);
        assert!(!row.cmdline.is_empty(), "empty cmdline in row {:?}", row);
    }

    // Report rather than assert: a run that starts with orphans present is
    // exactly the situation the sweeper exists for, and failing here would blame
    // this test for someone else's killed run.
    for row in child_guard::find_orphaned_netget() {
        println!(
            "[reap] note: orphan present before this test: pid={} {}",
            row.pid, row.cmdline
        );
    }
}

// ---------------------------------------------------------------------------
// The death tie, proved by actually killing a parent
// ---------------------------------------------------------------------------

/// Env var that turns a re-execution of this binary into the worker.
const WORKER_ENV: &str = "NETGET_REAP_WORKER";

/// What the worker prints so the outer test can find the pid.
const PID_MARKER: &str = "REAPER_TEST_CHILD_PID=";

fn pid_is_alive(pid: u32) -> bool {
    // `kill(pid, 0)` succeeds while the pid exists and we may signal it.
    // SAFETY: signal 0 sends nothing; it only performs the permission and
    // existence check.
    unsafe { libc::kill(pid as libc::c_int, 0) == 0 }
}

/// Run this binary again, executing only `test_name`, with the worker env set.
///
/// Returns (worker process, the child pid it reported).
fn spawn_worker(test_name: &str) -> (std::process::Child, u32) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut worker = Command::new(exe)
        .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env(WORKER_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("re-exec this test binary as a worker");

    // The worker is itself a child of a test binary, and this test is as capable
    // of being killed as any other. Tie it too, or a killed run of *this* file
    // leaves behind exactly what it is testing for.
    child_guard::tie_child(worker.id());

    let stdout = worker.stdout.take().expect("worker stdout");

    // Read on a thread and wait on a channel. A `read_line` against a worker
    // that never speaks blocks forever, so a deadline checked *after* the read
    // is no deadline at all — the first version of this test sat in it for the
    // full 600s harness timeout.
    let (tx, rx) = std::sync::mpsc::channel::<u32>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    // `find`, not `strip_prefix`: libtest writes `test <name> ...`
                    // with no newline, so the worker's own line lands on the end
                    // of it. Anchoring at the start of the line finds nothing.
                    if let Some(at) = line.find(PID_MARKER) {
                        let rest = &line[at + PID_MARKER.len()..];
                        let digits: String =
                            rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if let Ok(pid) = digits.parse::<u32>() {
                            let _ = tx.send(pid);
                            return;
                        }
                    }
                }
            }
        }
    });

    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(pid) => (worker, pid),
        Err(e) => {
            hard_kill(worker.id());
            let _ = worker.wait();
            child_guard::untie_child(worker.id());
            panic!("worker never reported a child pid: {e}");
        }
    }
}

fn hard_kill(pid: u32) {
    // SAFETY: a `SIGKILL` to a pid this test spawned and still owns.
    unsafe {
        libc::kill(pid as libc::c_int, libc::SIGKILL);
    }
}

fn assert_gone_within(pid: u32, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if !pid_is_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Do not leave the thing we are complaining about running.
    hard_kill(pid);
    panic!("child pid {pid} was still alive {budget:?} after its parent was SIGKILLed");
}

/// The claim, proved on a `/bin/sleep`: a `SIGKILL`ed parent still takes its
/// child with it.
///
/// `/bin/sleep` rather than netget because the tie is protocol-agnostic and this
/// test must run at every feature set, including the six-protocol CI gate. The
/// netget version is below, gated on a feature that gives it something to serve.
#[test]
fn sigkilled_parent_takes_its_child_with_it() {
    if std::env::var(WORKER_ENV).is_ok() {
        worker_body(WorkerChild::Sleep);
        return;
    }

    let (mut worker, child_pid) = spawn_worker("sigkilled_parent_takes_its_child_with_it");
    assert!(
        pid_is_alive(child_pid),
        "the worker's child was not running to begin with"
    );

    // The hard way: no `Drop`, no unwinding, no handler can run in the worker.
    hard_kill(worker.id());
    let _ = worker.wait();
    child_guard::untie_child(worker.id());

    assert_gone_within(child_pid, Duration::from_secs(10));
}

/// The same claim on the real `netget` binary, which is the process that was
/// actually orphaning.
///
/// Feature-gated because it needs a protocol to serve; `tcp` is in the blocking
/// CI feature set and in the default build.
#[test]
fn sigkilled_parent_takes_its_netget_with_it() {
    if std::env::var(WORKER_ENV).is_ok() {
        worker_body(WorkerChild::NetGet);
        return;
    }

    let (mut worker, child_pid) = spawn_worker("sigkilled_parent_takes_its_netget_with_it");
    assert!(
        pid_is_alive(child_pid),
        "the worker's netget was not running to begin with"
    );

    hard_kill(worker.id());
    let _ = worker.wait();
    child_guard::untie_child(worker.id());

    assert_gone_within(child_pid, Duration::from_secs(10));
}

enum WorkerChild {
    Sleep,
    NetGet,
}

/// The worker: spawn a long-lived child under a death tie, say what its pid is,
/// and then block until something kills us.
///
/// Nothing here may clean up on exit — that is the whole point. The tie is
/// deliberately leaked with `std::mem::forget` so that even an orderly unwind
/// could not disarm it.
fn worker_body(kind: WorkerChild) {
    let pid = match kind {
        WorkerChild::Sleep => {
            let child = Command::new("/bin/sleep")
                .arg("600")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("worker could not spawn /bin/sleep");
            let pid = child.id();
            // Armed here rather than by the harness, because this case is about
            // the mechanism alone and must run at any feature set.
            let tie = child_guard::arm_death_tie(pid).expect("could not arm a death tie");
            // Leak both, so nothing about this process's exit path can be
            // credited with the kill.
            std::mem::forget(tie);
            std::mem::forget(child);
            pid
        }
        WorkerChild::NetGet => spawn_harness_netget(),
    };

    // Give the child a moment to actually be running before we announce it.
    std::thread::sleep(Duration::from_millis(300));

    println!("{PID_MARKER}{pid}");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    std::thread::sleep(Duration::from_secs(600));
}

/// Start a real netget through the real harness and leak it.
///
/// `start_netget` is what every e2e suite calls, so this exercises the tie
/// exactly as the suite arms it — mock Ollama included, without which netget
/// exits immediately with "Ollama is not available".
fn spawn_harness_netget() -> u32 {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime");
    let instance = rt.block_on(async {
        helpers::netget::start_netget(
            helpers::NetGetConfig::new("echo whatever arrives")
                .with_log_level("error")
                .with_extra_args([
                    "--server".to_string(),
                    "tcp".to_string(),
                    "--port".to_string(),
                    "0".to_string(),
                ]),
        )
        .await
        .expect("harness could not start netget")
    });
    let pid = instance.child.id().expect("netget pid");
    // Leak the instance *and* its runtime: `NetGetInstance::drop` kills the child
    // and disarms the tie, which is precisely what must not happen here.
    std::mem::forget(instance);
    std::mem::forget(rt);
    pid
}
