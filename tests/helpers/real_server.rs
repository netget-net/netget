//! A real third-party **server**, spawned for one test and killed however the test ends.
//!
//! # Why this exists
//!
//! A NetGet *client* proves itself against a server nobody in this repository wrote. Pointing
//! NetGet's redis client at NetGet's redis server proves only that the two halves agree, which
//! is what they were both written to do — the circular case the root `CLAUDE.md` names under
//! "The client bar". The evidence has to be `mosquitto`, `redis-server`, `etcd`, `nginx`: a
//! binary with its own parser and its own opinions.
//!
//! `tests/client/nats/e2e_test.rs` did this first, by hand, for `nats-server`. This module is
//! that pattern made reusable, so the next client costs a builder call rather than eighty lines
//! of process management.
//!
//! # What it guarantees
//!
//! * **It fails, never skips, when the binary is absent.** The error names the binary, the
//!   Homebrew formula and the Ubuntu package. A `SKIP: … not installed` that returns `Ok(())`
//!   is a silent pass wherever the suite actually runs, and a maturity rating resting on one
//!   rests on nothing.
//! * **It owns a fresh temporary directory** for the server's config and data (`{dir}` in args
//!   and config files), deleted when the guard drops.
//! * **It waits for readiness by evidence, not by sleeping**: a line in the server's own log
//!   matching a regex, and/or a TCP connect to the port succeeding.
//! * **It kills the whole process group on drop**, including during a panic's unwinding, and
//!   arms an OS-level [`DeathTie`](super::child_guard::DeathTie) so a hard-killed test binary
//!   (which runs no `Drop` at all) still takes the server with it.
//! * **It keeps the server's stdout and stderr**, so a failing test can print what the server
//!   said. [`RealServer::with_log`] appends the log to an error; `Drop` prints it when the test
//!   is panicking.
//!
//! # Ports, and the race this cannot close
//!
//! Where a server can bind port 0 itself and report the port it got (`etcd` does, in its
//! `serving client traffic` log line), use [`PortSource::FromLog`]: there is then no window in
//! which anything else can take the port.
//!
//! Most servers cannot. `mosquitto`'s `listener 0` means a *unix socket*, `redis-server
//! --port 0` means "do not listen on TCP" and exits, and `nginx` never reports what it bound.
//! For those, [`PortSource::Probe`] binds `127.0.0.1:0`, reads the port the kernel chose,
//! drops the probe and hands the number to the server. **Between the drop and the server's own
//! bind, another process can take that port.** Under `--test-threads=100` that is not
//! hypothetical — `CLAUDE.md` records the same race in the shared startup path. The guard
//! narrows it rather than denying it:
//!
//! * readiness requires the server's own "I am listening" log line, so a port taken by a
//!   *different* process cannot read as ready merely because something accepts a connection;
//! * a server that exits before readiness with "address already in use" (or its equivalents)
//!   in its log is retried on a fresh port, up to [`BIND_ATTEMPTS`] times.
//!
//! What remains is a server that binds successfully while some unrelated listener shares the
//! port through `SO_REUSEPORT`, which none of the servers used here enable.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;

use super::child_guard::{arm_death_tie, DeathTie};
use super::common::E2EResult;

/// How many fresh probe ports to try when a server loses the bind race.
pub const BIND_ATTEMPTS: usize = 5;

/// Directories searched after `PATH`. Ubuntu installs `mosquitto`, `nginx`, `slapd`, `sshd`
/// and `mysqld` into `/usr/sbin`, Homebrew installs `mosquitto` into `/opt/homebrew/sbin` and
/// keeps `slapd` under openldap's `libexec` — none of which is on every user's `PATH`.
const FALLBACK_DIRS: &[&str] = &[
    "/opt/homebrew/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/opt/openldap/libexec",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/local/opt/openldap/libexec",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    // Heimdal's KDC: Debian/Ubuntu's heimdal-kdc, and the one macOS ships inside its framework.
    "/usr/lib/heimdal-servers",
    "/System/Library/PrivateFrameworks/Heimdal.framework/Helpers",
];

/// Directories searched **before** `PATH`. Homebrew's `krb5` is keg-only: MIT's `kadmin.local`,
/// `kvno` and `ktutil` live under `opt/krb5` and never on `PATH`, while macOS ships Apple's own
/// Heimdal-compatible `kadmin.local` in `/usr/sbin`, which `PATH` would find first and which
/// cannot administer an MIT database. Only binaries that exist here are affected, and every one
/// of them is MIT krb5's.
const PREFERRED_DIRS: &[&str] = &[
    "/opt/homebrew/opt/krb5/sbin",
    "/opt/homebrew/opt/krb5/bin",
    "/usr/local/opt/krb5/sbin",
    "/usr/local/opt/krb5/bin",
];

/// Where Debian and Ubuntu put PostgreSQL's server binaries: `/usr/lib/postgresql/<major>/bin`,
/// never on `PATH` (only the client wrappers are). Searched newest major first.
const POSTGRESQL_LIB_DIR: &str = "/usr/lib/postgresql";

/// Where to get a binary, for the error a missing one produces.
#[derive(Clone, Copy, Debug)]
pub struct InstallHint {
    /// The Homebrew formula (`brew install <brew>`).
    pub brew: &'static str,
    /// The Ubuntu package (`sudo apt-get install <apt>`), or a sentence when apt's is unusable.
    pub apt: &'static str,
}

/// The error for a third-party binary that could not be run, naming how to install it.
///
/// Use it for the *client* tools a test drives too (`redis-cli`, `mosquitto_sub`, `etcdctl`),
/// so every missing binary in these suites fails the same way and says the same things.
pub fn missing_binary(
    binary: &str,
    hint: InstallHint,
    cause: impl std::fmt::Display,
) -> Box<dyn std::error::Error> {
    format!(
        "could not run the third-party binary `{binary}`: {cause}.\n\
         This test is independent evidence for a NetGet client's maturity rating, so it FAILS \
         rather than skipping: a skip-when-missing gate is a silent pass, and the rating would \
         then rest on nothing.\n\
         Install it with `brew install {brew}` (macOS) or `sudo apt-get install {apt}` (Ubuntu), \
         then re-run.",
        brew = hint.brew,
        apt = hint.apt,
    )
    .into()
}

/// Resolve `binary` against `PATH`, then [`FALLBACK_DIRS`]. `None` when it is nowhere.
pub fn find_binary(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        let p = PathBuf::from(binary);
        return p.is_file().then_some(p);
    }
    let path_dirs = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default();
    PREFERRED_DIRS
        .iter()
        .map(PathBuf::from)
        .chain(path_dirs)
        .chain(FALLBACK_DIRS.iter().map(PathBuf::from))
        .chain(postgresql_bin_dirs())
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

/// `/usr/lib/postgresql/<major>/bin` for every installed major, newest first.
fn postgresql_bin_dirs() -> Vec<PathBuf> {
    let mut majors: Vec<(u32, PathBuf)> = std::fs::read_dir(POSTGRESQL_LIB_DIR)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let major = e.file_name().to_str()?.parse::<u32>().ok()?;
                    Some((major, e.path().join("bin")))
                })
                .collect()
        })
        .unwrap_or_default();
    majors.sort_by_key(|(major, _)| std::cmp::Reverse(*major));
    majors.into_iter().map(|(_, dir)| dir).collect()
}

/// A command run to completion in the server's temporary directory before the server starts
/// (`initdb`, `mysqld --initialize-insecure`, `ssh-keygen`).
struct SetupCommand {
    binary: String,
    hint: InstallHint,
    args: Vec<String>,
}

/// How the server's listening port is decided.
pub enum PortSource {
    /// Probe for a free port, substitute it for `{port}`, and retry on a lost bind race.
    Probe,
    /// The server binds port 0 itself; the first capture group of this regex, matched
    /// against its log, is the port it got. No race.
    FromLog(Regex),
}

/// Builder for [`RealServer`]. Start with [`RealServer::builder`].
pub struct RealServerBuilder {
    binary: String,
    hint: InstallHint,
    args: Vec<String>,
    env: Vec<(String, String)>,
    setup_env: Vec<(String, String)>,
    files: Vec<(String, String)>,
    setup: Vec<SetupCommand>,
    port: PortSource,
    extra_ports: usize,
    ready_log: Option<Regex>,
    ready_tcp: bool,
    timeout: Duration,
    #[cfg(unix)]
    graceful_stop: Option<(nix::sys::signal::Signal, Duration)>,
}

impl RealServerBuilder {
    /// Run `binary args…` to completion in the server's temporary directory before the server
    /// starts, after the [`config_file`](Self::config_file)s are written. The same placeholders
    /// as [`args`](Self::args) are substituted. Setup commands run in the order given; a
    /// non-zero exit fails the start with the command's output, and a missing binary fails it
    /// with [`missing_binary`] naming `hint`.
    ///
    /// For the servers whose data directory must exist before they will start: `initdb`,
    /// `mysqld --initialize-insecure`, and `ssh-keygen` for a host key.
    pub fn setup_command<I, S>(mut self, binary: &str, hint: InstallHint, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.setup.push(SetupCommand {
            binary: binary.to_string(),
            hint,
            args: args.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Command-line arguments. `{port}`, `{port1}`…`{portN}` and `{dir}` are substituted.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable for the server process. The same placeholders as
    /// [`args`](Self::args) are substituted into `value`.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Set an environment variable for the [`setup_command`](Self::setup_command)s only (MIT's
    /// `kdb5_util` and `kadmin.local` find their realm through `KRB5_CONFIG` and
    /// `KRB5_KDC_PROFILE`). The same placeholders as [`args`](Self::args) are substituted.
    pub fn setup_env(mut self, key: &str, value: &str) -> Self {
        self.setup_env.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Write a file into the server's temporary directory before it starts. The same
    /// placeholders as [`args`](Self::args) are substituted into `contents`.
    pub fn config_file(mut self, relative_name: &str, contents: &str) -> Self {
        self.files
            .push((relative_name.to_string(), contents.to_string()));
        self
    }

    /// Decide the port by reading it out of the server's log (see [`PortSource::FromLog`]).
    ///
    /// # Panics
    /// If `regex` does not compile — a bug in the test, not a runtime condition.
    pub fn port_from_log(mut self, regex: &str) -> Self {
        self.port = PortSource::FromLog(Regex::new(regex).expect("port regex must compile"));
        self
    }

    /// Probe `n` additional free ports, substituted as `{port1}`…`{portN}`.
    pub fn extra_ports(mut self, n: usize) -> Self {
        self.extra_ports = n;
        self
    }

    /// Readiness requires a log line matching `regex`. Strongly preferred with
    /// [`PortSource::Probe`]; see the module docs for why.
    ///
    /// # Panics
    /// If `regex` does not compile.
    pub fn ready_when_log_matches(mut self, regex: &str) -> Self {
        self.ready_log = Some(Regex::new(regex).expect("readiness regex must compile"));
        self
    }

    /// Do not additionally require a TCP connect to the port (on by default).
    pub fn without_tcp_readiness(mut self) -> Self {
        self.ready_tcp = false;
        self
    }

    /// On drop, send `signal` to the server and give it `grace` to exit on its own before the
    /// process group is killed.
    ///
    /// For a server that leaves something *outside* its temporary directory behind when it is
    /// SIGKILLed. PostgreSQL is the case: every postmaster holds a small System V shared memory
    /// segment keyed to its data directory, only a clean shutdown removes it, and macOS allows
    /// 32 segments system-wide (`kern.sysv.shmmni`) — so a suite that SIGKILLs a postmaster per
    /// test stops being able to start one after a few runs. `SIGINT` is its fast shutdown,
    /// which disconnects clients rather than waiting for them.
    #[cfg(unix)]
    pub fn graceful_stop(mut self, signal: nix::sys::signal::Signal, grace: Duration) -> Self {
        self.graceful_stop = Some((signal, grace));
        self
    }

    /// How long to wait for readiness (default 30s).
    pub fn startup_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Spawn the server and wait until it is ready.
    pub async fn start(self) -> E2EResult<RealServer> {
        let Some(program) = find_binary(&self.binary) else {
            return Err(missing_binary(
                &self.binary,
                self.hint,
                "not found on PATH or in any of the usual install directories",
            ));
        };

        let attempts = match self.port {
            PortSource::Probe => BIND_ATTEMPTS,
            PortSource::FromLog(_) => 1,
        };

        let mut last_error = String::new();
        for attempt in 1..=attempts {
            match self.try_start(&program).await? {
                Attempt::Ready(server) => return Ok(server),
                Attempt::LostBindRace(log) => {
                    last_error = format!(
                        "attempt {attempt}/{attempts}: `{}` lost the race for its probed port. \
                         Its log:\n{log}",
                        self.binary
                    );
                    eprintln!("[real_server] {last_error}\n[real_server] retrying on a fresh port");
                }
            }
        }
        Err(format!(
            "`{}` could not bind a probed port in {attempts} attempts. Last:\n{last_error}",
            self.binary
        )
        .into())
    }

    async fn try_start(&self, program: &Path) -> E2EResult<Attempt> {
        let dir = tempfile::Builder::new()
            .prefix(&format!("netget-real-{}-", self.binary.replace('/', "_")))
            .tempdir()?;
        let dir_str = dir.path().to_string_lossy().to_string();

        let port = match self.port {
            PortSource::Probe => Some(probe_port()?),
            PortSource::FromLog(_) => None,
        };
        let extra: Vec<u16> = (0..self.extra_ports)
            .map(|_| probe_port())
            .collect::<std::io::Result<_>>()?;

        let substitute = |text: &str| -> String {
            let mut out = text.replace("{dir}", &dir_str);
            // Highest index first, so `{port1}` is not eaten by a `{port10}` substitution.
            for (i, p) in extra.iter().enumerate().rev() {
                out = out.replace(&format!("{{port{}}}", i + 1), &p.to_string());
            }
            if let Some(p) = port {
                out = out.replace("{port}", &p.to_string());
            }
            out
        };

        for (name, contents) in &self.files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, substitute(contents))?;
        }
        for step in &self.setup {
            let Some(setup_program) = find_binary(&step.binary) else {
                return Err(missing_binary(
                    &step.binary,
                    step.hint,
                    "not found on PATH or in any of the usual install directories",
                ));
            };
            let mut command = Command::new(setup_program);
            command
                .args(step.args.iter().map(|a| substitute(a)))
                .envs(self.setup_env.iter().map(|(k, v)| (k, substitute(v))))
                .current_dir(dir.path())
                .stdin(Stdio::null());
            let (binary, hint) = (step.binary.clone(), step.hint);
            let output = tokio::task::spawn_blocking(move || command.output())
                .await
                .map_err(|e| format!("setup `{binary}` task failed: {e}"))?
                .map_err(|e| missing_binary(&step.binary, hint, e))?;
            if !output.status.success() {
                return Err(format!(
                    "setup step `{}` for `{}` exited with {}.\nstdout:\n{}\nstderr:\n{}",
                    step.binary,
                    self.binary,
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
        }
        let args: Vec<String> = self.args.iter().map(|a| substitute(a)).collect();

        let mut command = Command::new(program);
        command
            .args(&args)
            .envs(self.env.iter().map(|(k, v)| (k, substitute(v))))
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group, so the kill on drop reaches anything the server forks —
        // nginx's workers, for one — and not just the pid we hold.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let mut child = command
            .spawn()
            .map_err(|e| missing_binary(&self.binary, self.hint, e))?;
        let tie = arm_death_tie(child.id());

        let log = Arc::new(Mutex::new(String::new()));
        if let Some(out) = child.stdout.take() {
            capture(out, log.clone());
        }
        if let Some(err) = child.stderr.take() {
            capture(err, log.clone());
        }

        let mut server = RealServer {
            binary: self.binary.clone(),
            port: port.unwrap_or(0),
            extra_ports: extra.clone(),
            dir,
            child,
            log,
            tie,
            #[cfg(unix)]
            graceful_stop: self.graceful_stop,
        };

        let deadline = Instant::now() + self.timeout;
        let mut log_ready = self.ready_log.is_none();
        loop {
            let text = server.log();

            if let PortSource::FromLog(re) = &self.port {
                if server.port == 0 {
                    if let Some(p) = re
                        .captures(&text)
                        .and_then(|c| c.get(1))
                        .and_then(|m| m.as_str().parse::<u16>().ok())
                    {
                        server.port = p;
                    }
                }
            }
            if !log_ready {
                log_ready = self.ready_log.as_ref().is_some_and(|re| re.is_match(&text));
            }

            if let Ok(Some(status)) = server.child.try_wait() {
                // Give the reader threads a moment to drain what the server said last.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let text = server.log();
                if matches!(self.port, PortSource::Probe) && lost_bind_race(&text) {
                    return Ok(Attempt::LostBindRace(text));
                }
                return Err(format!(
                    "`{}` exited with {status} before it was ready. Its log:\n{text}",
                    self.binary
                )
                .into());
            }

            if log_ready && server.port != 0 {
                let tcp_ok = !self.ready_tcp
                    || tokio::net::TcpStream::connect(("127.0.0.1", server.port))
                        .await
                        .is_ok();
                if tcp_ok {
                    return Ok(Attempt::Ready(server));
                }
            }

            if Instant::now() >= deadline {
                return Err(format!(
                    "`{}` was not ready within {:?} (log line seen: {log_ready}, port: {}). \
                     Its log:\n{}",
                    self.binary,
                    self.timeout,
                    server.port,
                    server.log()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

enum Attempt {
    Ready(RealServer),
    LostBindRace(String),
}

/// A running third-party server. Killed, with its process group, when dropped.
pub struct RealServer {
    binary: String,
    /// The port the server is listening on, on 127.0.0.1.
    pub port: u16,
    /// Additional probed ports, in `{port1}`… order.
    pub extra_ports: Vec<u16>,
    dir: tempfile::TempDir,
    child: Child,
    log: Arc<Mutex<String>>,
    tie: Option<DeathTie>,
    #[cfg(unix)]
    graceful_stop: Option<(nix::sys::signal::Signal, Duration)>,
}

impl RealServer {
    /// Start describing a server. `binary` is looked up on `PATH` and then in the usual
    /// install directories; `hint` is what the error says when it is in neither.
    pub fn builder(binary: &str, hint: InstallHint) -> RealServerBuilder {
        RealServerBuilder {
            binary: binary.to_string(),
            hint,
            args: Vec::new(),
            env: Vec::new(),
            setup_env: Vec::new(),
            files: Vec::new(),
            setup: Vec::new(),
            port: PortSource::Probe,
            extra_ports: 0,
            ready_log: None,
            ready_tcp: true,
            timeout: Duration::from_secs(30),
            #[cfg(unix)]
            graceful_stop: None,
        }
    }

    /// `127.0.0.1:<port>`.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The temporary directory the server was started in.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Everything the server has written to stdout and stderr so far.
    pub fn log(&self) -> String {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Wait until the server's own log contains `needle`. The server's log is often the only
    /// place a fact is visible from outside NetGet — which subscriptions a broker holds, what a
    /// request carried — so it is a legitimate thing to wait on, not just to print.
    pub async fn wait_for_log(&self, needle: &str, timeout: Duration) -> E2EResult<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.log().contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "`{}` never logged {needle:?} within {timeout:?}",
                    self.binary
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Whether the server process is still alive.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Pass `result` through, appending the server's own log to an error.
    ///
    /// Wrap a test body with it so a failure shows what the third-party server saw — which is
    /// usually the fastest route to *why* it refused what NetGet sent.
    pub fn with_log<T>(&self, result: E2EResult<T>) -> E2EResult<T> {
        result.map_err(|e| {
            format!(
                "{e}\n\n--- `{}` log (port {}) ---\n{}",
                self.binary,
                self.port,
                self.log()
            )
            .into()
        })
    }
}

impl Drop for RealServer {
    fn drop(&mut self) {
        let pid = self.child.id() as i32;
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, killpg, Signal};
            use nix::unistd::Pid;
            if let Some((signal, grace)) = self.graceful_stop {
                if kill(Pid::from_raw(pid), signal).is_ok() {
                    let deadline = Instant::now() + grace;
                    while Instant::now() < deadline {
                        if !matches!(self.child.try_wait(), Ok(None)) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Only after the kill: disarming first would leave a window with nothing watching.
        if let Some(mut tie) = self.tie.take() {
            tie.disarm();
        }
        if std::thread::panicking() {
            eprintln!(
                "\n--- `{}` log (port {}) ---\n{}",
                self.binary,
                self.port,
                self.log()
            );
        }
    }
}

/// Bind `127.0.0.1:0`, read the port, release it. See the module docs for the race.
fn probe_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Whether a server's log says it could not bind because the port was taken.
fn lost_bind_race(log: &str) -> bool {
    let lower = log.to_ascii_lowercase();
    lower.contains("address already in use") || lower.contains("eaddrinuse")
}

/// Copy a pipe into the shared log buffer, line by line, until EOF.
fn capture<R: Read + Send + 'static>(pipe: R, log: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Ok(mut l) = log.lock() {
                        l.push_str(&String::from_utf8_lossy(&line));
                    }
                }
            }
        }
    });
}

/// A long-running third-party **client** tool (`mosquitto_sub`, say) whose output a test reads
/// line by line while it runs. Killed on drop.
///
/// The test builds the `Command` itself, so the binary name stays a literal
/// `Command::new("…")` in the test file — which is what `scripts/beta_evidence_table.py` and
/// `tests/real_client_evidence_is_run_test.rs` read to learn which peer a suite drives.
pub struct ToolProcess {
    binary: String,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl ToolProcess {
    /// Spawn `command` with stdout and stderr captured. `binary` and `hint` are for the error
    /// when it cannot be run.
    pub fn spawn(mut command: Command, binary: &str, hint: InstallHint) -> E2EResult<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| missing_binary(binary, hint, e))?;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let pipes: Vec<Box<dyn Read + Send>> = [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        .collect();
        for pipe in pipes {
            let lines = lines.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(pipe);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(mut l) = lines.lock() {
                        l.push(line);
                    }
                }
            });
        }
        Ok(Self {
            binary: binary.to_string(),
            child,
            lines,
        })
    }

    /// Every line printed so far, stdout and stderr interleaved as they arrived.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Wait until some line satisfies `pred` and return it; an error listing everything the
    /// tool printed if none does in time.
    pub async fn wait_for_line<F>(
        &self,
        what: &str,
        timeout: Duration,
        pred: F,
    ) -> E2EResult<String>
    where
        F: Fn(&str) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(found) = self.lines().into_iter().find(|l| pred(l)) {
                return Ok(found);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "`{}` never printed {what} within {timeout:?}. It printed:\n{}",
                    self.binary,
                    self.lines().join("\n")
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for ToolProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a third-party client tool to completion and return its stdout. A non-zero exit is an
/// error carrying the tool's stderr; a tool that cannot be run is [`missing_binary`].
///
/// Runs on the blocking pool: a tool that waits on NetGet must not stall the runtime the mock
/// model answers on.
pub async fn run_tool(command: Command, binary: &str, hint: InstallHint) -> E2EResult<String> {
    let mut command = command;
    let output = tokio::task::spawn_blocking(move || command.stdin(Stdio::null()).output())
        .await
        .map_err(|e| format!("`{binary}` task failed: {e}"))?
        .map_err(|e| missing_binary(binary, hint, e))?;
    if !output.status.success() {
        return Err(format!(
            "`{binary}` exited with {}.\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
