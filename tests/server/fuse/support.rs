//! Shared harness for the FUSE suites: an in-process FUSE server whose model is a python script
//! or static handlers (the LLM endpoint is unreachable, so an event nothing covers exercises the
//! fail-closed path), and ordinary tools run against the mount as separate processes.
//!
//! The kernel's FUSE driver is the client, and the processes reading the mount are coreutils,
//! findutils and Python: NetGet's own code is nowhere on the reading side. Every tool runs as a
//! subprocess (never a std::fs call on the test's runtime threads), because a process doing I/O
//! on the mount blocks until the daemon in this same process answers.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub fn policy(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub fn fusermount3() -> PathBuf {
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    dirs.extend(["/usr/bin".into(), "/bin".into(), "/usr/sbin".into()]);
    for d in dirs {
        let p = d.join("fusermount3");
        if p.is_file() {
            return p;
        }
    }
    panic!(
        "fusermount3 is not installed. It is the setuid helper that mounts the filesystem the \
         kernel's FUSE driver talks to, and skipping would leave the FUSE server's evidence \
         resting on nothing. Install it with: apt-get install fuse3 (dnf install fuse3 on Fedora)"
    );
}

pub fn require_fuse() {
    fusermount3();
    assert!(
        Path::new("/dev/fuse").exists(),
        "/dev/fuse does not exist: load the module with modprobe fuse (and apt-get install fuse3)"
    );
}

pub struct Mounted {
    pub state: AppState,
    pub id: ServerId,
    pub path: PathBuf,
    pub dir: tempfile::TempDir,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Mounted {
    /// What the model was shown, per event type, oldest first.
    pub async fn events(&self, event_type: &str) -> Vec<Value> {
        let mut all: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == event_type)
            .map(|e| e["request"].clone())
            .collect();
        all.reverse();
        all
    }

    /// The paths of the events of a type, oldest first.
    pub async fn paths(&self, event_type: &str) -> Vec<String> {
        self.events(event_type)
            .await
            .iter()
            .map(|e| e["path"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// Every event type the model was shown, with how many times.
    pub async fn census(&self) -> std::collections::BTreeMap<String, usize> {
        let mut m = std::collections::BTreeMap::new();
        for e in self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
        {
            let v = serde_json::to_value(&e).unwrap();
            *m.entry(v["event_type"].as_str().unwrap_or_default().to_string())
                .or_default() += 1;
        }
        m
    }

    /// A shell command with `$M` the mount point and `$T` a scratch directory outside it.
    pub async fn sh(&self, cmd: &str) -> Output {
        sh_in(cmd, &self.path, self.dir.path()).await
    }

    /// `sh`, asserting it succeeded; its stdout.
    pub async fn ok(&self, cmd: &str) -> Vec<u8> {
        let out = self.sh(cmd).await;
        assert!(
            out.status.success(),
            "`{cmd}` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// `sh`, asserting it failed with `message` (an strerror text) on stderr.
    pub async fn fails(&self, cmd: &str, message: &str) {
        let out = self.sh(cmd).await;
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && err.contains(message),
            "`{cmd}` should fail with {message:?}; status {}, stderr {err:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
    }

    pub async fn text(&self, cmd: &str) -> String {
        String::from_utf8_lossy(&self.ok(cmd).await)
            .trim_end()
            .to_string()
    }

    pub async fn stop(&self) {
        self.state.remove_server(self.id).await;
    }
}

pub async fn sh_in(cmd: &str, mount: &Path, scratch: &Path) -> Output {
    tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .env("M", mount)
            .env("T", scratch)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("`{cmd}` did not finish in 120 s"))
    .unwrap_or_else(|e| panic!("running `{cmd}`: {e}"))
}

/// Whether a FUSE filesystem is mounted at `p`, from the mount table.
pub fn mounted_at(p: &Path) -> bool {
    netget::server::fuse::is_fuse_mounted(p)
}

/// Mount the FUSE server on a fresh empty directory with these handlers and startup parameters
/// (`mount_point` is filled in).
pub async fn mount(handlers: Option<Vec<Value>>, params: Value) -> Mounted {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("mnt");
    std::fs::create_dir(&path).unwrap();
    mount_at(dir, path, handlers, params).await
}

pub async fn mount_at(
    dir: tempfile::TempDir,
    path: PathBuf,
    handlers: Option<Vec<Value>>,
    mut params: Value,
) -> Mounted {
    require_fuse();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if line != "__UPDATE_UI__" {
                sink.lock().unwrap().push(line);
            }
        }
    });
    params["mount_point"] = json!(path.to_string_lossy());
    let id = ServerForm {
        protocol: "fuse".into(),
        port: None,
        host: None,
        instruction: Some("Be a filesystem".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| {
        diagnostics(&path, &log);
        panic!("starting fuse: {e}")
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                // A mount has no listening socket, so Running is the signal, not local_addr.
                if matches!(s.status, netget::state::server::ServerStatus::Running) {
                    return;
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    diagnostics(&path, &log);
                    panic!("fuse failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        diagnostics(&path, &log);
        panic!("fuse did not report started within 30 s")
    });
    assert!(mounted_at(&path), "the mount is live once spawn returned");
    Mounted {
        state,
        id,
        path,
        dir,
        log,
    }
}

/// Print what a failure needs to be understood without a rerun: the mount table's FUSE lines,
/// the kernel's last words and the daemon's own log.
pub fn diagnostics(path: &Path, log: &Arc<Mutex<Vec<String>>>) {
    eprintln!("---- FUSE diagnostics for {}", path.display());
    for l in std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("fuse"))
    {
        eprintln!("mountinfo: {l}");
    }
    match std::process::Command::new("dmesg").output() {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let lines: Vec<&str> = text.lines().collect();
            for l in &lines[lines.len().saturating_sub(30)..] {
                eprintln!("dmesg: {l}");
            }
            if !o.status.success() {
                eprintln!("dmesg: {}", String::from_utf8_lossy(&o.stderr).trim());
            }
        }
        Err(e) => eprintln!("dmesg: {e}"),
    }
    for l in log.lock().map(|l| l.clone()).unwrap_or_default() {
        eprintln!("daemon: {l}");
    }
    eprintln!("---- end of FUSE diagnostics");
}

/// Prints the diagnostics if the test panics while it is alive.
pub struct OnFailure<'a>(pub &'a Mounted);

impl Drop for OnFailure<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            diagnostics(&self.0.path, &self.0.log);
        }
    }
}

/// Wait for a condition, polling; false if it did not hold within `secs`.
pub async fn eventually(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if f() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
