//! Run NetGet as a mock service inside a Rust test.
//!
//! [`NetGet::builder`] starts the `netget` binary on a `.netget` file or an inline list of
//! actions, waits until every server it was asked for is listening, and hands back the
//! addresses they actually bound — so a configuration can use `"port": 0` and never race
//! another test for a port. Dropping the [`NetGet`] kills the process and removes its working
//! directory.
//!
//! ```no_run
//! use netget_fixture::NetGet;
//! use serde_json::json;
//! use std::io::{Read, Write};
//!
//! let netget = NetGet::builder()
//!     .actions(json!([{
//!         "type": "open_server", "protocol": "tcp", "port": 0, "instruction": "echo",
//!         "event_handlers": [{
//!             "event_pattern": "tcp_data_received",
//!             "handler": {"type": "static", "actions": [
//!                 {"type": "send_tcp_data", "data": "{{event.data}}"}
//!             ]}
//!         }]
//!     }]))
//!     .no_model()
//!     .start()
//!     .expect("netget starts");
//!
//! let mut stream = std::net::TcpStream::connect(netget.addr("tcp")).unwrap();
//! stream.write_all(b"ping\n").unwrap();
//! let mut echoed = [0u8; 5];
//! stream.read_exact(&mut echoed).unwrap();
//! assert_eq!(&echoed, b"ping\n");
//! ```
//!
//! # How readiness is known
//!
//! The helper passes `--ready-file <path>`. NetGet writes that file — atomically, so it is
//! never seen half-written — once every server in the configuration has bound its socket and
//! every client has connected, and the helper parses it. If the process exits first (a port
//! already in use, an unknown protocol, a bad handler), [`Builder::start`] returns
//! [`Error::Exited`] carrying NetGet's own stderr.
//!
//! # Which binary
//!
//! [`Builder::binary`] if given, else the `NETGET_BIN` environment variable, else `netget` on
//! `PATH`. Inside NetGet's own repository, integration tests pass
//! `env!("CARGO_BIN_EXE_netget")`.
//!
//! # Determinism
//!
//! Answer events with `static` or `script` handlers and call [`Builder::no_model`], which
//! points NetGet at a closed port: an event no handler matches then fails closed instead of
//! reaching whatever model happens to be running on the machine.
//!
//! # Async tests
//!
//! The API is synchronous and blocks only while NetGet starts (typically well under a
//! second). It is fine to call from `#[tokio::test]`; NetGet is a separate process, so
//! blocking the test's runtime thread briefly cannot stall the service under test.

use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One server from NetGet's readiness report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// NetGet's instance id (`#1`, `#2`, … in its own output).
    pub id: u32,
    /// Registry name, e.g. `TCP`, `HTTP`, `Redis`.
    pub protocol: String,
    /// The bound address, or `None` for a server with no listening socket (a pipe, a device).
    pub address: Option<SocketAddr>,
}

/// One client from NetGet's readiness report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// NetGet's instance id.
    pub id: u32,
    /// Registry name.
    pub protocol: String,
    /// The address it was told to connect to.
    pub remote_addr: String,
    /// `Connected`, `Connecting`, `Disconnected` or `Error`.
    pub status: String,
}

/// Why [`Builder::start`] failed.
#[derive(Debug)]
pub enum Error {
    /// The binary could not be started, or the working directory could not be prepared.
    Io(std::io::Error),
    /// NetGet exited before it reported ready. `stderr` is what it printed.
    Exited { status: String, stderr: String },
    /// No readiness report within the timeout. The process has been killed.
    Timeout { after: Duration, stderr: String },
    /// The readiness report did not parse.
    BadReport(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "could not start netget: {e}"),
            Error::Exited { status, stderr } => {
                write!(f, "netget exited ({status}) before it was ready: {stderr}")
            }
            Error::Timeout { after, stderr } => {
                write!(f, "netget was not ready within {after:?}; stderr: {stderr}")
            }
            Error::BadReport(why) => write!(f, "unreadable --ready-file report: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

enum Config {
    None,
    File(PathBuf),
    Actions(serde_json::Value),
}

/// Configures and starts a [`NetGet`]. See the crate documentation.
pub struct Builder {
    binary: Option<PathBuf>,
    config: Config,
    args: Vec<OsString>,
    ready_timeout: Duration,
    no_model: bool,
    max_lifetime: Option<Duration>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            binary: None,
            config: Config::None,
            args: Vec::new(),
            ready_timeout: Duration::from_secs(30),
            no_model: false,
            max_lifetime: None,
        }
    }
}

impl Builder {
    /// The `netget` binary to run. Overrides `NETGET_BIN` and `PATH`.
    pub fn binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary = Some(path.into());
        self
    }

    /// Load this `.netget` file (`{"actions": [...]}` or a saved session). A relative path is
    /// resolved against the current directory, not NetGet's private working directory.
    pub fn config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config = Config::File(path.into());
        self
    }

    /// Load these actions: either an array of actions or a whole `{"actions": [...]}`
    /// document. Written to a `.netget` file in NetGet's working directory.
    pub fn actions(mut self, actions: serde_json::Value) -> Self {
        self.config = Config::Actions(actions);
        self
    }

    /// One extra command-line argument, e.g. `--log-level`.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Extra command-line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Point NetGet at a closed port for its model, so nothing is answered by an LLM. Use with
    /// configurations whose every event is matched by a static or script handler.
    pub fn no_model(mut self) -> Self {
        self.no_model = true;
        self
    }

    /// How long to wait for the readiness report. Default 30 seconds.
    pub fn ready_timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = timeout;
        self
    }

    /// End the NetGet process after this long even if the test never drops it (`--run-for`).
    /// A backstop for a test binary that is killed before its destructors run.
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = Some(lifetime);
        self
    }

    /// Start NetGet and wait until it reports ready.
    pub fn start(self) -> Result<NetGet, Error> {
        let dir = WorkDir::create()?;
        let config = match self.config {
            Config::None => None,
            Config::File(path) => Some(absolute(&path)?),
            Config::Actions(value) => {
                let document = if value.is_array() {
                    serde_json::json!({ "actions": value })
                } else {
                    value
                };
                let path = dir.path.join("fixture.netget");
                std::fs::write(&path, document.to_string())?;
                Some(path)
            }
        };
        let ready_file = dir.path.join("ready.json");
        let stdout = std::fs::File::create(dir.path.join("stdout.log"))?;
        let stderr = std::fs::File::create(dir.path.join("stderr.log"))?;

        let binary = self
            .binary
            .or_else(|| std::env::var_os("NETGET_BIN").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("netget"));
        let mut command = Command::new(&binary);
        if let Some(config) = &config {
            command.arg("--load").arg(config);
        }
        command.arg("--ready-file").arg(&ready_file);
        if self.no_model {
            command.args(["--ollama-url", "http://127.0.0.1:1"]);
        }
        if let Some(lifetime) = self.max_lifetime {
            command
                .arg("--run-for")
                .arg(lifetime.as_secs().max(1).to_string());
        }
        command
            .args(&self.args)
            // NetGet writes netget.log into its working directory.
            .current_dir(&dir.path)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        let child = command.spawn().map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", binary.display()),
            ))
        })?;

        let mut netget = NetGet {
            child,
            dir,
            servers: Vec::new(),
            clients: Vec::new(),
        };
        let report = netget.wait_ready(&ready_file, self.ready_timeout)?;
        netget.servers = parse_servers(&report)?;
        netget.clients = parse_clients(&report)?;
        Ok(netget)
    }
}

/// A running NetGet process. Killed, and its working directory removed, when dropped.
pub struct NetGet {
    child: Child,
    dir: WorkDir,
    servers: Vec<Server>,
    clients: Vec<Client>,
}

impl NetGet {
    /// Start configuring one.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Every server, in the order NetGet started them.
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// Every client, in the order NetGet started them.
    pub fn clients(&self) -> &[Client] {
        &self.clients
    }

    /// The first server of `protocol` (case-insensitive: `"redis"` matches `Redis`).
    pub fn server(&self, protocol: &str) -> Option<&Server> {
        self.servers
            .iter()
            .find(|s| s.protocol.eq_ignore_ascii_case(protocol))
    }

    /// The bound address of the first server of `protocol`.
    ///
    /// # Panics
    ///
    /// If there is no such server, or it has no listening socket — in a test, either is a
    /// configuration mistake worth a loud failure naming what did start.
    pub fn addr(&self, protocol: &str) -> SocketAddr {
        match self.server(protocol) {
            Some(Server {
                address: Some(addr),
                ..
            }) => *addr,
            Some(_) => panic!("the {protocol} server has no listening socket"),
            None => panic!(
                "no {protocol} server; started: {:?}",
                self.servers
                    .iter()
                    .map(|s| s.protocol.as_str())
                    .collect::<Vec<_>>()
            ),
        }
    }

    /// The process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// NetGet's working directory: `netget.log`, `stdout.log`, `stderr.log` and the
    /// configuration live here until the process is dropped.
    pub fn work_dir(&self) -> &Path {
        &self.dir.path
    }

    /// Everything NetGet has printed to stdout so far. With a static handler every exchange
    /// shows up here, which is how a test can assert on what the mock saw.
    pub fn stdout(&self) -> String {
        read_lossy(&self.dir.path.join("stdout.log"))
    }

    /// Everything NetGet has printed to stderr so far.
    pub fn stderr(&self) -> String {
        read_lossy(&self.dir.path.join("stderr.log"))
    }

    /// The contents of `netget.log` so far.
    pub fn log(&self) -> String {
        read_lossy(&self.dir.path.join("netget.log"))
    }

    /// Whether the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn wait_ready(
        &mut self,
        ready_file: &Path,
        timeout: Duration,
    ) -> Result<serde_json::Value, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            // The file is renamed into place complete, so existing means readable in full.
            if let Ok(text) = std::fs::read_to_string(ready_file) {
                return serde_json::from_str(&text).map_err(|e| Error::BadReport(e.to_string()));
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(Error::Exited {
                    status: status.to_string(),
                    stderr: self.stderr(),
                });
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(Error::Timeout {
                    after: timeout,
                    stderr: self.stderr(),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for NetGet {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn create() -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "netget-fixture-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn absolute(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn parse_servers(report: &serde_json::Value) -> Result<Vec<Server>, Error> {
    let list = report["servers"]
        .as_array()
        .ok_or_else(|| Error::BadReport("no servers array".into()))?;
    list.iter()
        .map(|s| {
            let address = match s["address"].as_str() {
                Some(a) => Some(
                    a.parse()
                        .map_err(|e| Error::BadReport(format!("address {a:?}: {e}")))?,
                ),
                None => None,
            };
            Ok(Server {
                id: s["id"].as_u64().unwrap_or(0) as u32,
                protocol: s["protocol"].as_str().unwrap_or_default().to_string(),
                address,
            })
        })
        .collect()
}

fn parse_clients(report: &serde_json::Value) -> Result<Vec<Client>, Error> {
    let list = report["clients"]
        .as_array()
        .ok_or_else(|| Error::BadReport("no clients array".into()))?;
    Ok(list
        .iter()
        .map(|c| Client {
            id: c["id"].as_u64().unwrap_or(0) as u32,
            protocol: c["protocol"].as_str().unwrap_or_default().to_string(),
            remote_addr: c["remote_addr"].as_str().unwrap_or_default().to_string(),
            status: c["status"].as_str().unwrap_or_default().to_string(),
        })
        .collect())
}
