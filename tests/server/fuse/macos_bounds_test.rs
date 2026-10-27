//! macOS: what happens when the model fails or is slow, on a read-only mount, and when the
//! server stops or dies, through FUSE-T. Every case ends in an errno or an unmount, never a
//! hang. And FUSE-T missing is refused at startup with the cask to install.
//!
//! The mount tests mount FUSE-T, so `require_fuse` fails unless `NETGET_FUSE_MACOS_MOUNT=1` (see
//! `support::MACOS_MOUNT_GATE` for why); no CI job runs them, and each is run by hand on its own,
//! with a mount of its own. The refusal test mounts nothing — it points FUSE-T's server path at a
//! file that does not exist — so it runs anywhere.
use super::support::*;
use serde_json::json;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_model_is_eio_promptly_on_macos() {
    // No handler: every event goes to the model, whose endpoint refuses connections.
    let m = mount(None, json!({"decision_timeout_secs": 60})).await;
    let _diag = OnFailure(&m);
    for _ in 0..3 {
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
    assert!(
        m.events("fuse_describe_directory").await.len() <= 3,
        "at most three attempts at the root"
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
    assert!(eventually(20, || !mounted_at(&m.path)).await);
}

/// Descriptions at once; every write and the description of `/slow` sleep past the deadline.
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
async fn a_slow_model_is_eio_at_the_deadline_on_macos() {
    let m = mount(policy(SLOW_WRITES), json!({"decision_timeout_secs": 2})).await;
    let _diag = OnFailure(&m);
    m.ok(r#"ls "$M""#).await;
    let started = Instant::now();
    m.fails(r#"ls "$M/slow""#, "Input/output error").await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1500) && waited < Duration::from_secs(15),
        "the process waited for the deadline and no longer: {waited:?}"
    );
    // A write that misses the deadline: EIO (at close, when the NFS client writes back).
    let started = Instant::now();
    m.fails(
        r#"printf after | dd of="$M/f.txt" conv=notrunc"#,
        "Input/output error",
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(15));
    let log = m.log.lock().unwrap().join("\n");
    assert!(
        log.contains("operation=write") && log.contains("decision=fail_closed_deadline"),
        "the deadline is tagged: {log}"
    );
    m.stop().await;
    assert!(eventually(20, || !mounted_at(&m.path)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_only_mount_refuses_changes_without_asking_on_macos() {
    let m = mount(
        Some(vec![
            json!({"event_pattern": "fuse_describe_directory", "handler": {"type":
            "static", "actions": [{"type": "fuse_directory", "entries": [
                {"name": "f.txt", "kind": "file", "text": "kept\n"}]}]}}),
        ]),
        json!({"read_only": true}),
    )
    .await;
    let _diag = OnFailure(&m);
    assert_eq!(m.ok(r#"cat "$M/f.txt""#).await, b"kept\n");
    m.fails(r#"touch "$M/new""#, "Read-only file system").await;
    m.fails(r#"rm "$M/f.txt""#, "Read-only file system").await;
    m.fails(r#"mkdir "$M/d""#, "Read-only file system").await;
    m.fails(r#"printf x >> "$M/f.txt""#, "Read-only file system")
        .await;
    let census = m.census().await;
    assert_eq!(
        census.keys().collect::<Vec<_>>(),
        vec!["fuse_describe_directory"],
        "no change was put to the model: {census:?}"
    );
    m.stop().await;
    assert!(eventually(20, || !mounted_at(&m.path)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_unmounts_even_while_the_mount_is_busy_on_macos() {
    let dir = tempfile::tempdir().unwrap();
    // The server creates this mount point, so it removes it again.
    let path = dir.path().join("made");
    let m = mount_at(
        dir,
        path.clone(),
        Some(vec![json!({"event_pattern": "*", "handler": {"type": "static", "actions": [
            {"type": "fuse_directory", "entries": [{"name": "d", "kind": "dir", "entries": []}]}]}})]),
        json!({}),
    )
    .await;
    let _diag = OnFailure(&m);
    // A process whose working directory is inside the mount.
    let mut busy = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(r#"cd "$M/d" && echo inside && exec sleep 120"#)
        .env("M", &m.path)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut line = String::new();
    {
        use tokio::io::AsyncBufReadExt;
        let mut out = tokio::io::BufReader::new(busy.stdout.take().unwrap());
        tokio::time::timeout(Duration::from_secs(20), out.read_line(&mut line))
            .await
            .expect("the busy process reports in")
            .unwrap();
    }
    assert_eq!(
        line.trim(),
        "inside",
        "the busy process is inside the mount"
    );
    let started = Instant::now();
    m.stop().await;
    assert!(
        eventually(20, || !mounted_at(&path)).await,
        "stop unmounts a busy mount"
    );
    assert!(started.elapsed() < Duration::from_secs(25));
    let parent = sh_in(r#"ls -la "$M/..""#, &path, m.dir.path()).await;
    assert!(parent.status.success());
    assert!(
        eventually(10, || !path.exists()).await,
        "the mount point the server made is gone"
    );
    let _ = busy.start_kill();
    let _ = busy.wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_daemon_leaves_no_mount_behind_on_macos() {
    require_fuse();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnt");
    std::fs::create_dir(&path).unwrap();
    let params = json!({"mount_point": path.to_string_lossy()}).to_string();
    let err_path = dir.path().join("netget.err");
    let err_file = std::fs::File::create(&err_path).unwrap();
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
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(err_file)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().expect("a running child has a pid");
    crate::helpers::child_guard::tie_child(pid);
    eventually(60, || {
        mounted_at(&path) || child.try_wait().ok().flatten().is_some()
    })
    .await;
    if !mounted_at(&path) {
        let _ = child.start_kill();
        let _ = child.wait().await;
        crate::helpers::child_guard::untie_child(pid);
        macos_diagnostics(40);
        panic!(
            "netget --server fuse did not mount: {}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
    }
    let ok = sh_in(r#"stat -f %HT "$M""#, &path, dir.path()).await;
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "Directory");
    // SIGKILL: no destructor runs. FUSE-T's server notices its stream closing and unmounts,
    // and NetGet's watchdog unmounts (forcibly, retrying) whatever that leaves.
    child.start_kill().unwrap();
    let _ = child.wait().await;
    crate::helpers::child_guard::untie_child(pid);
    if !eventually(45, || !mounted_at(&path)).await {
        macos_diagnostics(60);
        let _ = std::process::Command::new("/sbin/umount")
            .arg("-f")
            .arg(&path)
            .status();
        panic!(
            "the mount outlived the killed process by 45 s\nnetget's stderr:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
    }
    let started = Instant::now();
    let ls = sh_in(r#"ls -la "$M/..""#, &path, dir.path()).await;
    assert!(ls.status.success() && started.elapsed() < Duration::from_secs(5));
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
}

/// FUSE-T missing is refused before anything is registered, naming the cask. Mounts nothing:
/// `FUSE_NFSSRV_PATH` points FUSE-T's server path at a file that does not exist, which is the
/// path the dependency probe and the backend both read. Safe to run anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_fuse_t_is_refused_at_startup_naming_the_cask() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("never");
    let params = json!({"mount_point": path.to_string_lossy()}).to_string();
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
        .env("FUSE_NFSSRV_PATH", dir.path().join("no-go-nfsv4"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().expect("a running child has a pid");
    crate::helpers::child_guard::tie_child(pid);
    let out = tokio::time::timeout(Duration::from_secs(60), async {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        use tokio::io::AsyncReadExt;
        let (mut o, mut e) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let _ = tokio::join!(o.read_to_end(&mut stdout), e.read_to_end(&mut stderr));
        let status = child.wait().await.unwrap();
        (status, stdout, stderr)
    })
    .await;
    crate::helpers::child_guard::untie_child(pid);
    let (status, stdout, stderr) = out.expect("netget exits when its only server cannot start");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(!status.success(), "a start that failed exits non-zero");
    assert!(
        said.contains("brew install --cask macos-fuse-t/cask/fuse-t"),
        "the refusal names the cask: {said}"
    );
    assert!(
        said.contains("no-go-nfsv4"),
        "and the path it looked at: {said}"
    );
    // The startup gate's wording: refused by the dependency probe, before spawn() runs.
    assert!(
        said.contains("Cannot start FUSE server") && said.contains("must be installed"),
        "refused by the startup dependency gate: {said}"
    );
    assert!(!path.exists(), "nothing was created at the mount point");
    assert!(!mounted_at(&path));
}
