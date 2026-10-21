//! What happens when the model fails, is slow or describes too much, when the overlay fills,
//! and when the server stops or dies: every case ends in an errno or an unmount, never a hang.
use super::support::*;
use serde_json::json;
use std::time::{Duration, Instant};

fn describe_root(entries: serde_json::Value) -> serde_json::Value {
    json!({"event_pattern": "fuse_describe_directory", "handler": {"type": "static",
        "actions": [{"type": "fuse_directory", "entries": entries}]}})
}

fn allow_everything() -> serde_json::Value {
    json!({"event_pattern": "*", "handler": {"type": "static", "actions": [{"type": "fuse_allow"}]}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_model_is_eio_promptly_and_three_attempts_at_most() {
    // No handler: every event goes to the model, whose endpoint refuses connections.
    let m = mount(None, json!({"decision_timeout_secs": 60})).await;
    let _diag = OnFailure(&m);
    for _ in 0..5 {
        let started = Instant::now();
        m.fails(r#"ls "$M""#, "Input/output error").await;
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a failed model is answered at once, not at the deadline: {:?}",
            started.elapsed()
        );
    }
    // getattr on the root needs nothing from the model.
    m.ok(r#"stat "$M""#).await;
    assert_eq!(
        m.events("fuse_describe_directory").await.len(),
        3,
        "the root is asked about three times, then fails for good without asking"
    );
    // A change inside a directory that failed is EIO without a model call.
    m.fails(r#"mkdir "$M/x""#, "Input/output error").await;
    assert_eq!(m.events("fuse_mkdir").await.len(), 0);
    let log = m.log.lock().unwrap().join("\n");
    assert!(
        log.contains("decision=fail_closed_llm_error"),
        "the failure is tagged: {log}"
    );
    m.stop().await;
}

/// A python handler that answers descriptions at once and sleeps through every write.
const SLOW_WRITES: &str = r#"import json,sys,time
i=json.load(sys.stdin); t=i['event_type_id']
if t=='fuse_describe_directory':
  a={'type':'fuse_directory','entries':[{'name':'slow','kind':'dir'},{'name':'f.txt','kind':'file','text':'before'}]} if i['event']['path']=='/' else None
  if a is None:
    time.sleep(20); a={'type':'fuse_directory','entries':[]}
else:
  time.sleep(20); a={'type':'fuse_allow'}
print(json.dumps({'actions':[a]}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_model_is_eio_at_the_deadline_and_changes_nothing() {
    let m = mount(policy(SLOW_WRITES), json!({"decision_timeout_secs": 2})).await;
    let _diag = OnFailure(&m);
    m.ok(r#"ls "$M""#).await;
    // A description that misses the deadline.
    let started = Instant::now();
    m.fails(r#"ls "$M/slow""#, "Input/output error").await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1500) && waited < Duration::from_secs(10),
        "the process waited for the deadline and no longer: {waited:?}"
    );
    // A write that misses the deadline: EIO, and the file is as it was.
    let started = Instant::now();
    m.fails(
        r#"printf after | dd of="$M/f.txt" conv=notrunc status=none"#,
        "Input/output error",
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(m.ok(r#"cat "$M/f.txt""#).await, b"before");
    let log = m.log.lock().unwrap().join("\n");
    assert!(
        log.contains("operation=write") && log.contains("decision=fail_closed_deadline"),
        "the deadline is tagged: {log}"
    );
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endless_tree_stops_at_the_depth_bound() {
    // Every directory holds a directory `d` and a file `f`: an infinite tree, which the depth
    // bound cuts at 64 directories.
    let m = mount(
        Some(vec![describe_root(json!([
            {"name": "d", "kind": "dir"},
            {"name": "f", "kind": "file", "text": "x"}
        ]))]),
        json!({}),
    )
    .await;
    let _diag = OnFailure(&m);
    let out = m.sh(r#"find "$M" -name f | wc -l"#).await;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "64",
        "a file at every depth from 1 to 64: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = m.sh(r#"find "$M" > /dev/null"#).await;
    assert!(
        String::from_utf8_lossy(&err.stderr).contains("Input/output error"),
        "the directory at depth 64 cannot be described: {:?}",
        String::from_utf8_lossy(&err.stderr)
    );
    let described = m.events("fuse_describe_directory").await;
    let depths: Vec<u64> = described
        .iter()
        .map(|e| e["depth"].as_u64().unwrap())
        .collect();
    assert_eq!(
        *depths.iter().max().unwrap(),
        64,
        "nothing deeper than the bound is ever asked about"
    );
    assert!(
        described.len() <= 64 + 3,
        "64 descriptions and at most three attempts at the 65th: {}",
        described.len()
    );
    let log = m.log.lock().unwrap().join("\n");
    assert!(log.contains("64 directories deep"), "{log}");
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn too_many_entries_in_one_answer_are_refused_whole() {
    let entries: Vec<_> = (0..4097)
        .map(|i| json!({"name": format!("f{i}"), "kind": "file"}))
        .collect();
    let m = mount(Some(vec![describe_root(json!(entries))]), json!({})).await;
    let _diag = OnFailure(&m);
    m.fails(r#"ls "$M""#, "Input/output error").await;
    m.fails(r#"stat "$M/f1""#, "Input/output error").await;
    let log = m.log.lock().unwrap().join("\n");
    assert!(log.contains("at most 4096 entries"), "{log}");
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_overlay_cap_is_enospc_and_removal_frees_it() {
    let m = mount(
        Some(vec![describe_root(json!([])), allow_everything()]),
        json!({"max_overlay_bytes": 1048576}),
    )
    .await;
    let _diag = OnFailure(&m);
    m.fails(
        r#"dd if=/dev/zero of="$M/big" bs=65536 count=32 status=none"#,
        "No space left on device",
    )
    .await;
    assert_eq!(m.text(r#"stat -c '%s' "$M/big""#).await, "1048576");
    assert_eq!(m.text(r#"stat -f -c '%f' "$M""#).await, "0");
    // The refused write took nothing: a 1-byte write into a new page is still refused.
    m.fails(
        r#"printf z | dd of="$M/big" bs=1 seek=2000000 conv=notrunc status=none"#,
        "No space left on device",
    )
    .await;
    assert_eq!(m.text(r#"stat -c '%s' "$M/big""#).await, "1048576");
    m.ok(r#"rm "$M/big""#).await;
    assert_eq!(m.text(r#"stat -f -c '%f' "$M""#).await, "256");
    m.ok(r#"dd if=/dev/zero of="$M/again" bs=65536 count=8 status=none"#)
        .await;
    assert_eq!(m.text(r#"stat -c '%s' "$M/again""#).await, "524288");
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_only_mount_refuses_changes_without_asking() {
    let m = mount(
        Some(vec![describe_root(json!([
            {"name": "README.txt", "kind": "file", "text": "hello\n"}
        ]))]),
        json!({"read_only": true}),
    )
    .await;
    let _diag = OnFailure(&m);
    assert_eq!(m.ok(r#"cat "$M/README.txt""#).await, b"hello\n");
    m.fails(r#"touch "$M/new""#, "Read-only file system").await;
    m.fails(r#"rm "$M/README.txt""#, "Read-only file system")
        .await;
    m.fails(r#"mkdir "$M/d""#, "Read-only file system").await;
    m.fails(
        r#"printf x | dd of="$M/README.txt" conv=notrunc status=none"#,
        "Read-only file system",
    )
    .await;
    let census = m.census().await;
    assert_eq!(
        census.keys().collect::<Vec<_>>(),
        vec!["fuse_describe_directory"],
        "{census:?}"
    );
    m.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_unmounts_even_while_the_mount_is_busy() {
    // An existing directory: after the stop it is an ordinary empty directory again.
    let m = mount(
        Some(vec![describe_root(
            json!([{"name": "f", "kind": "file", "text": "x"}]),
        )]),
        json!({}),
    )
    .await;
    let _diag = OnFailure(&m);
    // Keep the mount busy: a shell whose working directory is inside it.
    let mut busy = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(r#"cd "$M" && exec sleep 60"#)
        .env("M", &m.path)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    assert!(
        eventually(10, || std::fs::read_link(format!(
            "/proc/{}/cwd",
            busy.id().unwrap()
        ))
        .is_ok_and(|p| p == m.path))
        .await
    );
    m.stop().await;
    assert!(
        eventually(10, || !mounted_at(&m.path)).await,
        "stop unmounts a busy mount (lazily)"
    );
    let entries = std::fs::read_dir(&m.path).unwrap().count();
    assert_eq!(entries, 0, "the mount point is an empty directory again");
    m.ok(r#"ls -la "$M/..""#).await;
    let _ = busy.kill().await;

    // A mount point the server created is removed again.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("made-by-netget");
    let m = mount_at(
        dir,
        path.clone(),
        Some(vec![describe_root(json!([]))]),
        json!({}),
    )
    .await;
    m.stop().await;
    assert!(
        eventually(10, || !path.exists()).await,
        "the made directory is gone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_daemon_leaves_no_mount_behind() {
    require_fuse();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnt");
    std::fs::create_dir(&path).unwrap();
    let params = json!({"mount_point": path.to_string_lossy()}).to_string();
    let err_path = dir.path().join("netget.err");
    let err_file = std::fs::File::create(&err_path).unwrap();
    // The binary checks its model backend at startup; an empty mock answers that and nothing
    // else (the root's description is never asked for here).
    let backend = crate::helpers::mock_ollama::MockOllamaServer::start(
        crate::helpers::mock_builder::MockLlmBuilder::new().build(),
    )
    .await
    .unwrap();
    let url = backend.base_url();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--model",
            "qwen3-coder:30b",
            "--ollama-url",
            &url,
            "--server",
            "fuse",
            "--server-params",
            &params,
            "Be a filesystem",
        ])
        // Not a terminal, so netget would read stdin to its end as part of the prompt.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(err_file)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().expect("a running child has a pid");
    // OS-level half of the cleanup: if this test binary dies, the child goes with it. See
    // `tests/helpers/child_guard.rs`.
    crate::helpers::child_guard::tie_child(pid);
    eventually(60, || {
        mounted_at(&path) || child.try_wait().ok().flatten().is_some()
    })
    .await;
    let up = mounted_at(&path);
    if !up {
        let _ = child.start_kill();
        let _ = child.wait().await;
        crate::helpers::child_guard::untie_child(pid);
        panic!(
            "netget --server fuse did not mount: {}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
    }
    let ok = sh_in(r#"stat -c %F "$M""#, &path, dir.path()).await;
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "directory");
    // SIGKILL: no destructor runs. The unmount watchdog (and, on fuse3 3.17 and later,
    // fusermount3's own auto_unmount) is what cleans up.
    child.start_kill().unwrap();
    let _ = child.wait().await;
    crate::helpers::child_guard::untie_child(pid);
    if !eventually(20, || !mounted_at(&path)).await {
        let why = unmount_diagnostics(&path).await;
        // Leave no stale mount on the machine whatever happened.
        let _ = tokio::process::Command::new("fusermount3")
            .args(["-u", "-z", "--"])
            .arg(&path)
            .status()
            .await;
        panic!(
            "the mount outlived the killed process by 20 s\n{why}\nnetget's stderr:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
    }
    let started = Instant::now();
    let ls = sh_in(r#"ls -la "$M/..""#, &path, dir.path()).await;
    assert!(ls.status.success() && started.elapsed() < Duration::from_secs(5));
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
}

/// What a mount that outlived its daemon needs explaining with: the mount table's FUSE lines,
/// every fusermount3 and watchdog process, and the kernel's last words (AppArmor denials among
/// them).
async fn unmount_diagnostics(path: &std::path::Path) -> String {
    let mut out = String::new();
    for l in std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("fuse"))
    {
        out.push_str(&format!("mountinfo: {l}\n"));
    }
    let probe = sh_in(
        r#"ls -la "$M" 2>&1; ps -eo pid,ppid,pgid,sid,user,args | grep -E 'fusermount|netget-fuse-watchdog|PID' | grep -v grep; fusermount3 --version 2>&1; (dmesg 2>&1 || true) | tail -40; (journalctl -k --no-pager -n 40 2>&1 | grep -i -E 'apparmor|fuse' || true)"#,
        path,
        path.parent().unwrap_or(path),
    )
    .await;
    out.push_str(&String::from_utf8_lossy(&probe.stdout));
    out.push_str(&String::from_utf8_lossy(&probe.stderr));
    out
}
