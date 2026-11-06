//! The test-fixture helpers — `crates/netget-fixture` (Rust) and `sdk/python/netget_fixture`
//! (Python) — driven against this tree's own binary.
//!
//! Both helpers start `netget --load … --ready-file …`, wait for the readiness report and hand
//! back the bound addresses. Everything here is answered by static and script handlers with
//! the model pointed at a closed port, so no test reaches an LLM.
//!
//! The Python half runs `python3 -m unittest` and `python3 -m pytest` over
//! `sdk/python/tests/`, and FAILS rather than skips when either is missing: a skipped helper
//! test is a helper nobody has run.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test fixture_helpers_test

use netget_fixture::{Error, NetGet};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn builder() -> netget_fixture::Builder {
    NetGet::builder()
        .binary(env!("CARGO_BIN_EXE_netget"))
        .no_model()
        .max_lifetime(Duration::from_secs(120))
        .args(["--log-level", "error"])
}

fn echo_server() -> serde_json::Value {
    json!({
        "type": "open_server", "protocol": "tcp", "port": 0, "instruction": "echo",
        "event_handlers": [{
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [
                {"type": "send_tcp_data", "data": "{{event.data}}"}
            ]}
        }]
    })
}

fn http_server() -> serde_json::Value {
    json!({
        "type": "open_server", "protocol": "http", "port": 0, "instruction": "api",
        "event_handlers": [{
            "event_pattern": "http_request",
            "handler": {"type": "static", "actions": [{
                "type": "send_http_response", "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"id\": 7, \"name\": \"Ada\"}"
            }]}
        }]
    })
}

fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response");
    response
}

/// Two servers on port 0 from inline actions; both addresses come back and both answer
/// immediately.
#[test]
fn rust_helper_starts_inline_actions_and_returns_bound_addresses() {
    let netget = builder()
        .actions(json!([echo_server(), http_server()]))
        .start()
        .expect("netget starts");
    assert_eq!(netget.servers().len(), 2, "{:?}", netget.servers());
    let tcp = netget.addr("tcp");
    let http = netget.addr("HTTP");
    assert_ne!(tcp.port(), 0);
    assert_ne!(tcp, http);

    let mut stream = TcpStream::connect(tcp).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"ping\n").unwrap();
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).expect("echo");
    assert_eq!(&echoed, b"ping\n");

    let response = http_get(http, "/users/7");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains(r#"{"id": 7, "name": "Ada"}"#),
        "{response}"
    );
}

/// A `.netget` file on disk, given by a relative path, is resolved against the caller's
/// directory, not NetGet's private one. Dropping the helper stops the process and removes
/// its working directory.
#[test]
fn rust_helper_loads_a_file_and_cleans_up_on_drop() {
    let dir = std::env::temp_dir().join(format!("netget-fixture-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("mock.netget");
    std::fs::write(&file, json!({"actions": [echo_server()]}).to_string()).unwrap();
    let relative = pathdiff(&file);

    let netget = builder()
        .config_file(&relative)
        .start()
        .expect("netget starts");
    let addr = netget.addr("tcp");
    let work_dir = netget.work_dir().to_path_buf();
    assert!(work_dir.join("ready.json").exists());
    drop(netget);

    assert!(!work_dir.exists(), "the working directory is removed");
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err(),
        "the process is gone, so nothing listens on {addr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A configuration that cannot start is an error carrying NetGet's own explanation, returned
/// as soon as the process exits rather than after the ready timeout.
#[test]
fn rust_helper_reports_a_failed_start() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let started = std::time::Instant::now();
    let result = builder()
        .actions(json!([{
            "type": "open_server", "protocol": "tcp", "port": port, "instruction": "echo"
        }]))
        .ready_timeout(Duration::from_secs(60))
        .start();
    match result {
        Err(Error::Exited { stderr, .. }) => {
            assert!(stderr.contains("failed to start"), "{stderr}")
        }
        Err(other) => panic!("expected Exited, got {other}"),
        Ok(_) => panic!("a port already in use must not report ready"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the exit is noticed, not waited out"
    );
}

/// The helper is synchronous and works from an async test.
#[tokio::test]
async fn rust_helper_works_from_a_tokio_test() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let netget = builder()
        .actions(json!([echo_server()]))
        .start()
        .expect("netget starts");
    let mut stream = tokio::net::TcpStream::connect(netget.addr("tcp"))
        .await
        .unwrap();
    stream.write_all(b"async\n").await.unwrap();
    let mut echoed = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("in time")
        .unwrap();
    assert_eq!(&echoed, b"async\n");
}

/// `file` relative to the current directory, so the test exercises the relative-path case.
fn pathdiff(file: &Path) -> std::path::PathBuf {
    let cwd = std::env::current_dir().unwrap();
    let mut up = std::path::PathBuf::new();
    for _ in cwd.components().skip(1) {
        up.push("..");
    }
    up.join(file.strip_prefix("/").unwrap())
}

fn python_sdk_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("sdk/python")
}

fn run_python(args: &[&str], what: &str) {
    let output = Command::new("python3")
        .args(args)
        .current_dir(python_sdk_dir())
        .env("NETGET_BIN", env!("CARGO_BIN_EXE_netget"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        // Only the plugins named with `-p`: a broken third-party pytest plugin installed on the
        // machine (one was, on the machine this was written on) must not fail this test.
        .env("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
        .output()
        .unwrap_or_else(|e| {
            panic!("python3 is required for the Python fixture tests and could not be run: {e}")
        });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{what} failed ({}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    eprintln!("{what}:\n{stdout}{stderr}");
}

/// The context manager and its error paths, with nothing but the standard library.
#[test]
fn python_helper_unittest_suite_passes() {
    run_python(
        &[
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_*.py",
            "-v",
        ],
        "python3 -m unittest",
    );
}

/// The pytest plugin's `netget` fixture. Needs pytest; install it with `pip install pytest`.
#[test]
fn python_helper_pytest_plugin_passes() {
    let probe = Command::new("python3")
        .args(["-c", "import pytest"])
        .output()
        .expect("python3 runs");
    assert!(
        probe.status.success(),
        "pytest is required for the pytest-plugin test (python3 -m pip install pytest): {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    run_python(
        &[
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "netget_fixture.pytest_plugin",
            "tests/pytest_plugin_check.py",
        ],
        "python3 -m pytest",
    );
}
