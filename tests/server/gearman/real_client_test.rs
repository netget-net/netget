//! Gearman against real, independent clients: the gearmand project's `gearman(1)` and
//! `gearadmin(1)`.
//!
//! Both are built on libgearman (C++, BSD; Homebrew `gearman`, Ubuntu `gearman-tools`), which
//! NetGet neither links nor wrote. `gearman` frames `SUBMIT_JOB`, waits for `JOB_CREATED`, then
//! prints `WORK_DATA` and `WORK_COMPLETE` payloads and progress from `WORK_STATUS`, and exits 1
//! on `WORK_FAIL`; `gearadmin` speaks the text admin protocol. They are run as subprocesses and
//! what they printed, and how they exited, are asserted.
//!
//! **These tests FAIL, they do not skip, when the binaries are absent.** A skip gate returns
//! `Ok(())` on a runner without them and the rating built on it rests on nothing;
//! `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The worker is a Python script handler (`common::WORKER_SCRIPT`), so the script-driven cases
//! are deterministic; the last test puts a mocked model behind the same client. The first test
//! records its connection through a relay and runs the pcap oracle with Wireshark's own
//! `gearman` dissector.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::real_client --test-threads=100

use super::common::{self, manual_handler, req, worker_handler, Chunk, Peer, Recorder};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::gearman::wire;
use std::time::Duration;

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
fn require_tool(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        if let Some(found) = path
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|candidate| candidate.exists())
        {
            return found.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These tests drive the gearmand project's own gearman and gearadmin clients against \
         NetGet's Gearman server, and they are the only independent check that our packets \
         and admin answers are what libgearman expects. Skipping would leave the Gearman \
         evidence resting on nothing, so this is a failure and not a skip. Install with \
         `brew install gearman` (macOS) or `apt-get install -y gearman-tools` (Debian/Ubuntu)."
    );
}

/// Run a tool against `port`; returns (exit code, stdout, stderr).
async fn run(tool: &str, port: u16, args: &[&str]) -> (i32, String, String) {
    let bin = require_tool(tool);
    let mut command = tokio::process::Command::new(&bin);
    command
        .arg("-h")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .args(args)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .unwrap_or_else(|_| panic!("{tool} {args:?} did not exit within 120s"))
        .expect("run the client");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- {tool} -h 127.0.0.1 -p {port} {} (exit {:?}) ---\n{stdout}{stderr}",
        args.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), stdout, stderr)
}

#[tokio::test]
async fn gearman_runs_a_job_and_the_pcap_oracle_reads_clean_gearman() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![worker_handler()], None).await;
    let relay = Recorder::start(port).await;

    let (code, out, err) = run("gearman", relay.port, &["-f", "reverse", "hello world"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("partial:") && out.contains("dlrow olleh"),
        "gearman printed the WORK_DATA and WORK_COMPLETE payloads: {out}"
    );
    assert!(
        out.contains("50% Complete"),
        "gearman parsed WORK_STATUS 1/2: {out}"
    );

    // Everything that crossed the wire, read by Wireshark's own gearman dissector.
    let chunks = relay.finished(30).await;
    let mut oracle = PcapOracle::tcp("gearman");
    for chunk in &chunks {
        oracle = match chunk {
            Chunk::ToServer(b) => oracle.to_server(b),
            Chunk::FromServer(b) => oracle.from_server(b),
        };
    }
    oracle.assert_clean();
}

#[tokio::test]
async fn gearman_priorities_background_failure_and_ping() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![worker_handler()], None).await;

    for (flag, expected) in [
        (None, "normal/fg/3"),
        (Some("-I"), "high/fg/3"),
        (Some("-L"), "low/fg/3"),
    ] {
        let mut args: Vec<&str> = flag.into_iter().collect();
        args.extend(["-f", "describe", "abc"]);
        let (code, out, err) = run("gearman", port, &args).await;
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        assert_eq!(
            out, expected,
            "{args:?}: the model saw the priority the flag chose"
        );
    }

    // A function the worker does not provide: WORK_FAIL, which gearman exits 1 on.
    let (code, _out, err) = run("gearman", port, &["-f", "nosuch", "x"]).await;
    assert_eq!(code, 1, "WORK_FAIL must exit non-zero: {err}");
    assert!(err.contains("Job failed"), "{err}");

    // An exception, to a client that did not ask for exceptions, arrives as WORK_FAIL.
    let (code, _out, err) = run("gearman", port, &["-f", "explode", "x"]).await;
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("Job failed"), "{err}");

    // Background: JOB_CREATED only; the worker still runs it.
    common::drain(&mut rx);
    let (code, out, err) = run("gearman", port, &["-b", "-f", "describe", "abc"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.is_empty(),
        "nothing follows JOB_CREATED for a background job: {out}"
    );
    common::wait_for_log(&mut rx, "background=true", 30).await;

    // `gearman --ping` sends ECHO_REQ. Ping mode arrived after gearmand 1.1.19, which is what
    // Ubuntu 22.04 (the registry-audit runner) ships, so ask the client itself before relying on
    // it. Where it is absent the ECHO path is still asserted byte for byte by e2e_test.rs and
    // connection_bounds_test.rs; only this third-party reading of it is unavailable, and the
    // line below says so rather than passing silently.
    let help = std::process::Command::new(require_tool("gearman"))
        .arg("--help")
        .output()
        .expect("run gearman --help");
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    if help.contains("Ping mode") {
        let (code, out, err) = run("gearman", port, &["--ping"]).await;
        assert_eq!(code, 0, "ECHO_REQ answered with ECHO_RES: {out}{err}");
    } else {
        eprintln!(
            "NOTE: this gearman client has no ping mode (gearmand <= 1.1.19), so ECHO_REQ is not \
             read back by a third-party client here; e2e_test.rs asserts the ECHO_RES bytes"
        );
    }
}

#[tokio::test]
async fn gearadmin_reads_the_jobs_in_flight_and_the_version() {
    // Named literally so the evidence scanner sees this file drives gearadmin as well.
    let _ = require_tool("gearadmin");
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![manual_handler()], None).await;

    // A job parked for a human stays in flight.
    let mut client = Peer::connect(port).await;
    client
        .send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    let (t, args, _) = client.packet(10).await;
    // The job enters the in-flight table before JOB_CREATED is written.
    assert_eq!(t, wire::JOB_CREATED);

    let (code, out, err) = run("gearadmin", port, &["--status"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        out, "reverse\t1\t1\t0\n.\n",
        "one reverse job, running, and no worker connections"
    );

    let (code, out, err) = run("gearadmin", port, &["--workers"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(out, ".\n");

    let (code, out, err) = run("gearadmin", port, &["--server-version"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.starts_with("netget-"), "{out}");

    // GET_STATUS from another connection sees the job too.
    let mut other = Peer::connect(port).await;
    other.send(&req(wire::GET_STATUS, &[&args[0]])).await;
    let (t, status, _) = other.packet(10).await;
    assert_eq!(t, wire::STATUS_RES);
    assert_eq!(
        status[1..],
        [b"1".to_vec(), b"1".to_vec(), b"0".to_vec(), b"0".to_vec()]
    );
}

#[tokio::test]
async fn a_gearman_worker_is_refused_rather_than_left_waiting() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![worker_handler()], None).await;
    let (_code, out, err) = run("gearman", port, &["-w", "-f", "reverse", "-c", "1"]).await;
    assert!(
        format!("{out}{err}").contains("GEARMAN_ERROR")
            || format!("{out}{err}").contains("not_supported"),
        "the worker was told, not left waiting for a job: {out}{err}"
    );
}

/// The model path behind the same real client.
#[tokio::test]
async fn gearman_prints_a_result_the_model_wrote() -> E2EResult<()> {
    let _ = require_tool("gearman");
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via gearman. A job server.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via gearman")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gearman",
                    "instruction": "Upper-case every workload"
                }]))
                .expect_calls(1)
                .and()
                .on_event("gearman_job_submitted")
                .respond_with_actions_from_event(|e| {
                    let w = e["workload"].as_str().unwrap_or("").to_uppercase();
                    serde_json::json!([{"type": "complete_gearman_job", "result": w}])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let (code, out, err) = run("gearman", server.port, &["-f", "upper", "quiet please"]).await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(out, "QUIET PLEASE");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
