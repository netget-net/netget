//! CLI argument surface tests
//!
//! These cover the parts of `src/cli/args.rs` that are easy to regress
//! silently. No Ollama, no network, no LLM calls.

use clap::Parser;
use netget::cli::Args;

/// The death tie that keeps a spawned `netget` from outliving this binary.
///
/// Pulled in by path rather than through `mod helpers;` because this file needs exactly one
/// module out of the shared harness and nothing else in it: `child_guard.rs` depends only on
/// `std` and `libc`, so it compiles standalone. `Drop` alone is not enough — it does not run
/// when the test binary is `SIGKILL`ed, aborts, or is interrupted, which is precisely how 78
/// orphaned `netget` processes accumulated on one machine in ten hours.
#[path = "helpers/child_guard.rs"]
mod child_guard;

/// `--log-level` defaults to `debug` in development builds, `info` in release.
///
/// Dev builds used to default to `trace`, the level at which NetGet writes
/// whole network payloads and whole LLM prompts into `netget.log` - 481 MB in
/// a day, and credentials off the wire along with it. The test binary is a dev
/// build, so `debug` is the value under test here.
#[test]
fn default_log_level_is_not_trace() {
    let args = Args::try_parse_from(["netget"]).expect("default args parse");
    if cfg!(debug_assertions) {
        assert_eq!(args.log_level, "debug");
    } else {
        assert_eq!(args.log_level, "info");
    }
}

/// `--load <FILE>` must actually produce the file's actions.
///
/// Deliberately a `#[tokio::test]`: `get_actions_json()` runs inside the
/// process-wide runtime in production (`#[tokio::main]` -> `cli::run()`), and
/// the previous implementation built a second runtime and `block_on`-ed there,
/// which panics on a thread already driving one. Running this from a plain
/// `#[test]` would not have caught it.
#[tokio::test]
async fn load_flag_reads_actions_from_file() {
    let dir = std::env::temp_dir().join(format!("netget-load-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("config.netget");
    std::fs::write(
        &path,
        r#"{"actions": [{"type": "open_server", "protocol": "tcp", "port": 0, "instruction": "echo"}]}"#,
    )
    .expect("write actions file");

    let args = Args::try_parse_from(["netget", "--load", path.to_str().unwrap()])
        .expect("args with --load parse");

    let actions = args
        .get_actions_json()
        .expect("--load must be readable")
        .expect("--load must yield actions");

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["type"], "open_server");

    // A prompt is not expected alongside --load
    assert!(args.get_prompt().expect("get_prompt").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `.netget` extension is optional on the command line.
#[tokio::test]
async fn load_flag_appends_netget_extension_when_needed() {
    let dir = std::env::temp_dir().join(format!("netget-load-ext-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("saved.netget");
    std::fs::write(
        &path,
        r#"{"actions": [{"type": "show_message", "message": "hi"}]}"#,
    )
    .expect("write actions file");

    let without_ext = dir.join("saved");
    let args = Args::try_parse_from(["netget", "--load", without_ext.to_str().unwrap()])
        .expect("args parse");

    let actions = args
        .get_actions_json()
        .expect("--load must resolve saved -> saved.netget")
        .expect("actions");
    assert_eq!(actions[0]["type"], "show_message");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing `--load` file is an error, not a panic and not a silent skip.
#[tokio::test]
async fn load_flag_reports_missing_file() {
    let args = Args::try_parse_from(["netget", "--load", "/nonexistent/netget-does-not-exist"])
        .expect("args parse");
    let err = args
        .get_actions_json()
        .expect_err("missing --load file must error");
    assert!(
        err.to_string().contains("Failed to read"),
        "unexpected error: {err}"
    );
}

/// A prompt piped on stdin must reach the non-interactive path.
///
/// `cli::run()` asks for actions JSON and then for a prompt; when both read
/// stdin directly, the first read drained it and the piped prompt was lost,
/// so `echo "..." | netget` died with "Cannot start in interactive mode
/// without a terminal" even though --help advertises `cat prompt.txt | netget`.
///
/// Spawns the real binary because the bug only exists across two calls in one
/// process. `--ollama-url` points at a closed port, so the run fails at the
/// model check - which is proof the prompt was accepted.
#[test]
fn piped_stdin_prompt_is_not_swallowed() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args(["--ollama-url", "http://127.0.0.1:1", "--log-level", "error"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn netget");
    let pid = child.id();
    child_guard::tie_child(pid);

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"listen on port 0 via tcp\n")
        .expect("write prompt");
    drop(child.stdin.take());

    let out = child.wait_with_output().expect("wait for netget");
    // Waited for, so it is gone; release the tie before its pid can be recycled.
    child_guard::untie_child(pid);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("Cannot start in interactive mode"),
        "piped prompt was discarded: {combined}"
    );
}

/// `--api-key` keeps working (it just warns), and still wins over the
/// environment so existing callers are not silently switched to another key.
#[test]
fn api_key_flag_still_resolves() {
    let args = Args::try_parse_from([
        "netget",
        "--openai-url",
        "https://api.example.com",
        "--model",
        "gpt-4o",
        "--api-key",
        "sk-from-the-flag",
    ])
    .expect("args parse");
    assert_eq!(args.resolve_api_key().as_deref(), Some("sk-from-the-flag"));
}

/// `--client` gives clients the deterministic entry point servers already had.
#[test]
fn client_flags_parse() {
    let args = Args::try_parse_from([
        "netget",
        "--client",
        "redis",
        "--connect",
        "127.0.0.1:6379",
        "--client-params",
        r#"{"db": 0}"#,
    ])
    .expect("client args parse");

    assert_eq!(args.client_protocol.as_deref(), Some("redis"));
    assert_eq!(args.client_addr.as_deref(), Some("127.0.0.1:6379"));
    assert_eq!(
        args.parse_client_params().expect("params parse"),
        Some(serde_json::json!({"db": 0}))
    );
    assert!(args
        .parse_client_handlers()
        .expect("handlers parse")
        .is_none());
}

/// `--connect` without `--client` is a usage error, not a silently ignored flag.
#[test]
fn connect_requires_client() {
    assert!(Args::try_parse_from(["netget", "--connect", "127.0.0.1:6379"]).is_err());
}

/// Trailing text becomes the client's instruction; without it, a default.
#[test]
fn client_instruction_comes_from_trailing_args() {
    let args = Args::try_parse_from([
        "netget",
        "--client",
        "tcp",
        "--connect",
        "127.0.0.1:9000",
        "read",
        "the",
        "banner",
    ])
    .expect("client args parse");
    assert_eq!(
        args.client_instruction("TCP", "127.0.0.1:9000"),
        "read the banner"
    );

    let bare = Args::try_parse_from(["netget", "--client", "tcp", "--connect", "127.0.0.1:9000"])
        .expect("client args parse");
    assert!(bare
        .client_instruction("TCP", "127.0.0.1:9000")
        .contains("TCP client connected to 127.0.0.1:9000"));
}

/// Malformed JSON on the client flags fails with a message naming the flag.
#[test]
fn client_json_flags_reject_malformed_input() {
    let bad_params = Args::try_parse_from([
        "netget",
        "--client",
        "redis",
        "--connect",
        "127.0.0.1:6379",
        "--client-params",
        "[1,2,3]",
    ])
    .expect("args parse");
    let err = bad_params
        .parse_client_params()
        .expect_err("array is not an object");
    assert!(err.to_string().contains("--client-params"));

    let bad_handlers = Args::try_parse_from([
        "netget",
        "--client",
        "redis",
        "--connect",
        "127.0.0.1:6379",
        "--client-handlers",
        "{not json",
    ])
    .expect("args parse");
    let err = bad_handlers
        .parse_client_handlers()
        .expect_err("malformed JSON must error");
    assert!(err.to_string().contains("--client-handlers"));
}

/// `--restart-check on|off` reaches the client `--client` starts, through the same overrides
/// `--history` and `--batching` do, and is refused where no client is started.
#[test]
fn restart_check_flag_parses_and_applies_to_the_client() {
    let parse = |value: &str| {
        Args::try_parse_from([
            "netget",
            "--client",
            "redis",
            "--connect",
            "127.0.0.1:6379",
            "--restart-check",
            value,
        ])
    };
    let off = parse("off").expect("off parses");
    assert_eq!(off.restart_check, Some(false));
    assert_eq!(
        off.client_conversation_overrides().restart_check,
        Some(false)
    );
    assert_eq!(parse("ON").expect("on parses").restart_check, Some(true));
    assert!(parse("maybe").is_err(), "only on or off");

    let unset =
        Args::try_parse_from(["netget", "--client", "redis", "--connect", "x:1"]).expect("parses");
    assert_eq!(unset.client_conversation_overrides().restart_check, None);

    assert!(off.validate_restart_check().is_ok());

    // Refused where no client is started, whether clap or the run catches it.
    for argv in [
        &["netget", "--restart-check", "off", "--server", "tcp"][..],
        &["netget", "--restart-check", "off"][..],
    ] {
        let refused = match Args::try_parse_from(argv) {
            Err(_) => true,
            Ok(args) => args.validate_restart_check().is_err(),
        };
        assert!(refused, "{argv:?}: nothing reads --restart-check there");
    }
}
