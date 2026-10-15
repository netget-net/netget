//! Beanstalkd against a real, independent client: `greenstalk`.
//!
//! `greenstalk` 2.1 (MIT, `pip install greenstalk`) is a Python beanstalkd client with its own
//! reply parser: it splits the status line, raises a typed exception per error word, reads
//! `RESERVED`/`FOUND`/`OK` payloads by the byte count and checks the trailing CRLF, and decodes
//! the YAML of `stats` and `list-tubes` itself (as ASCII — a non-ASCII byte in a stats report
//! is an exception there). NetGet neither links nor wrote it; it is run as a subprocess and
//! what it *returned or raised* is asserted.
//!
//! **These tests FAIL, they do not skip, when python3 or greenstalk is absent.** A skip gate
//! returns `Ok(())` on a runner without the library and the rating built on it rests on
//! nothing; `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The queue is a Python script handler (`common::QUEUE_SCRIPT`), so the script-driven cases
//! are deterministic and consult no model. The last test puts a mocked model behind the same
//! client, because the model path is the one the protocol exists for.
//!
//! No pcap oracle: this Wireshark build has no beanstalkd dissector (`tshark -G protocols`
//! lists none).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::real_client --test-threads=100

use super::common::{self, queue_handler, RESERVED_BODY_PREFIX, RESERVED_BODY_SUFFIX};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

/// Drives one greenstalk session through every command it has and prints one JSON object of
/// what each call returned, or the name of the exception it raised.
const SESSION_DRIVER: &str = r#"import json, sys
import greenstalk
port = int(sys.argv[1])
out = {}
def raised(f):
    try:
        f()
        return None
    except greenstalk.Error as e:
        return type(e).__name__
c = greenstalk.Client(('127.0.0.1', port), use='images', watch=['images', 'video'])
out['using'] = c.using()
out['watching'] = sorted(c.watching())
out['put'] = c.put('hello queue', priority=5, delay=0, ttr=30)
try:
    c.put('bury-me please')
    out['put_buried'] = None
except greenstalk.BuriedError as e:
    out['put_buried'] = e.id
job = c.reserve()
out['reserved'] = [job.id, job.body]
c.touch(job)
c.release(job, priority=7, delay=1)
c.bury(job, priority=9)
c.kick_job(job)
out['kick'] = c.kick(10)
c.delete(job)
out['delete_404'] = raised(lambda: c.delete(404))
p = c.peek(42)
out['peek'] = [p.id, p.body]
r = c.reserve_job(77)
out['reserve_job'] = [r.id, r.body]
out['stats'] = c.stats()
out['stats_tube'] = c.stats_tube('images')
out['stats_tube_missing'] = raised(lambda: c.stats_tube('nosuch'))
out['stats_job'] = c.stats_job(42)
out['tubes'] = c.tubes()
c.pause_tube('images', 5)
c.watch('empty')
c.ignore('images')
c.ignore('video')
out['not_ignored'] = raised(lambda: c.ignore('empty'))
out['reserve_timeout'] = raised(lambda: c.reserve(timeout=1))
out['too_big'] = raised(lambda: c.put('x' * 65536))
out['after_too_big'] = c.put('still in step')
c.close()
print(json.dumps(out))
"#;

/// Puts then reserves once; for the mocked-model case.
const PUT_RESERVE_DRIVER: &str = r#"import json, sys
import greenstalk
c = greenstalk.Client(('127.0.0.1', int(sys.argv[1])))
out = {'put': c.put('thumbnail 12')}
job = c.reserve()
out['reserved'] = [job.id, job.body]
c.close()
print(json.dumps(out))
"#;

/// Fail, never skip, when the client is missing — naming it and how to install it.
/// Named `require_tool("…")` in spirit: the evidence scanner finds `import greenstalk` in the
/// drivers above.
fn require_greenstalk() {
    let probe = std::process::Command::new("python3")
        .args(["-c", "import greenstalk"])
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        other => panic!(
            "the Python beanstalkd client `greenstalk` is not importable ({other:?}). These \
             tests drive it against NetGet's Beanstalkd server, and it is the only independent \
             check that our replies, byte counts and YAML are acceptable to a client we did not \
             write. Skipping would leave the Beanstalkd evidence resting on nothing, so this is \
             a failure and not a skip. Install with `python3 -m pip install greenstalk`."
        ),
    }
}

async fn run_driver(driver: &str, port: u16) -> Value {
    require_greenstalk();
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-c")
        .arg(driver)
        .arg(port.to_string())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .expect("the greenstalk driver did not finish within 120s")
        .expect("run python3");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- python3 -c <greenstalk driver> {port} (exit {:?}) ---\n{stdout}{stderr}",
        output.status.code()
    );
    assert!(
        output.status.success(),
        "greenstalk raised something the driver did not expect: {stderr}"
    );
    serde_json::from_str(stdout.trim()).expect("driver prints JSON")
}

#[tokio::test]
async fn greenstalk_drives_every_command_and_parses_every_reply() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![queue_handler()], None).await;
    let out = run_driver(SESSION_DRIVER, port).await;

    // Answered by NetGet from the connection's own tube state.
    assert_eq!(out["using"], "images", "{out}");
    assert_eq!(
        out["watching"],
        serde_json::json!(["images", "video"]),
        "greenstalk ignored `default` after watching its two tubes: {out}"
    );

    // put: greenstalk parsed `INSERTED <id>` and `BURIED <id>`.
    assert_eq!(out["put"], 1000 + "hello queue".len(), "{out}");
    assert_eq!(out["put_buried"], 900, "{out}");

    // reserve: greenstalk read exactly <bytes> bytes, checked the CRLF after them, and
    // decoded UTF-8 — the embedded CRLF and reply line stayed body.
    let expected_body = format!("{RESERVED_BODY_PREFIX}images{RESERVED_BODY_SUFFIX}");
    assert_eq!(
        out["reserved"],
        serde_json::json!([42, expected_body]),
        "{out}"
    );

    assert_eq!(out["kick"], 3, "KICKED <count> parsed: {out}");
    assert_eq!(out["delete_404"], "NotFoundError", "{out}");
    assert_eq!(
        out["peek"],
        serde_json::json!([42, "peeked in images"]),
        "{out}"
    );
    assert_eq!(
        out["reserve_job"],
        serde_json::json!([77, "reserved by id"]),
        "{out}"
    );

    // stats: greenstalk's own YAML reader, ints parsed as ints.
    let stats = &out["stats"];
    assert_eq!(stats["current-jobs-ready"], 3, "{out}");
    assert_eq!(stats["current-jobs-reserved"], 1, "{out}");
    assert_eq!(stats["total-jobs"], 42, "{out}");
    assert_eq!(stats["version"], "1.13", "{out}");
    assert_eq!(stats["draining"], "false", "{out}");
    assert_eq!(stats["hostname"], "netget-queue", "{out}");
    assert_eq!(out["stats_tube"]["name"], "images", "{out}");
    assert_eq!(out["stats_tube"]["current-jobs-ready"], 2, "{out}");
    assert_eq!(out["stats_tube_missing"], "NotFoundError", "{out}");
    assert_eq!(out["stats_job"]["id"], 42, "{out}");
    assert_eq!(out["stats_job"]["state"], "reserved", "{out}");
    assert_eq!(
        out["tubes"],
        serde_json::json!(["default", "images", "video"]),
        "{out}"
    );

    // NetGet's own refusals, each read as the exception upstream would have raised.
    assert_eq!(out["not_ignored"], "NotIgnoredError", "{out}");
    assert_eq!(
        out["reserve_timeout"], "TimedOutError",
        "the model left the reserve waiting and NetGet answered TIMED_OUT at the worker's \
         timeout: {out}"
    );
    assert_eq!(out["too_big"], "JobTooBigError", "{out}");
    assert_eq!(
        out["after_too_big"],
        1000 + "still in step".len(),
        "after JOB_TOO_BIG the server skipped the body and the connection stayed in step: {out}"
    );
}

/// The model path, behind the same real client.
#[tokio::test]
async fn greenstalk_reads_a_job_the_model_handed_out() -> E2EResult<()> {
    require_greenstalk();
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via beanstalkd. A thumbnail queue.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("via beanstalkd")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "beanstalkd",
                        "instruction": "A thumbnail queue"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("beanstalkd_put")
                    .respond_with_actions_from_event(|e| {
                        serde_json::json!([{
                            "type": "insert_beanstalkd_job",
                            "job_id": 500 + e["body_bytes"].as_u64().unwrap_or(0)
                        }])
                    })
                    .expect_calls(1)
                    .and()
                    .on_event("beanstalkd_reserve")
                    .respond_with_actions(serde_json::json!([{
                        "type": "reserve_beanstalkd_job",
                        "job_id": 7,
                        "body": "{\"thumbnail\": 12, \"width\": 128}"
                    }]))
                    .expect_calls(1)
                    .and()
            });

    let server = start_netget_server(config).await?;
    let out = run_driver(PUT_RESERVE_DRIVER, server.port).await;
    assert_eq!(out["put"], 500 + "thumbnail 12".len(), "{out}");
    assert_eq!(
        out["reserved"],
        serde_json::json!([7, "{\"thumbnail\": 12, \"width\": 128}"]),
        "{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
