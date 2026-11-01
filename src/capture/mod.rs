//! Packet capture: NetGet writes a pcap of what an instance's sockets carried.
//!
//! NetGet owns the sockets, so it can record every byte a server or client read and wrote
//! without libpcap, an interface or any privilege. It never sees packets, only the bytes
//! `read()` returned and `write()` accepted, so the IP/TCP/UDP headers are synthesised
//! from the connection's real 4-tuple ([`pcap`]): a TCP stream opens with SYN, SYN-ACK,
//! ACK, its sequence numbers advance by exactly the bytes carried, and it closes with a
//! FIN per direction, so Wireshark's "Follow TCP Stream" reassembles it. The file is
//! classic pcap, `LINKTYPE_RAW`.
//!
//! # Turning it on
//!
//! Per instance, with `capture` on `ServerForm` / `ClientForm` (and therefore MCP
//! `start_*` / `update_*`, the dashboard and `.netget` session files) or `open_server` /
//! `open_client`: `true` writes `netget-<server|client>-<id>-<protocol>.pcap` in the
//! capture directory, a string names the file, `false` stops it. `--capture <dir>` makes
//! `<dir>` the capture directory and records every instance the process starts. Starting
//! and stopping are hot: connections already open are picked up at their next read or
//! write, opening their stream in the file at that point.
//!
//! # Where the bytes come from
//!
//! There is no central seam carrying payloads — the shared connection accounting
//! (`AppState::update_connection_stats`) sees counts, not bytes — so a protocol opts in:
//!
//! * a TCP protocol wraps its accepted (or connected) stream in [`tcp::CapturedStream`]
//!   before anything reads it — [`tcp::CapturedStream::server`] /
//!   [`tcp::CapturedStream::client`] — and keeps using it exactly as it used the
//!   `TcpStream`: it is `AsyncRead + AsyncWrite`, so `tokio::io::split`, hyper's
//!   `TokioIo` and a TLS acceptor all take it. A TLS protocol wraps the TCP stream
//!   *under* TLS and so records ciphertext, as a real capture would.
//! * a UDP protocol takes a [`udp::UdpTap`] once and calls `inbound` after each
//!   `recv_from` and `outbound` after each successful `send_to`.
//!
//! [`adopted`] lists the protocols that do; for any other the capture file stays empty and
//! [`CaptureStatus::adopted`] says why.
//!
//! # Bounds
//!
//! Packets reach the file through a bounded queue to a writer thread
//! ([`writer::CHANNEL_CAPACITY`]); when it is full the packet is dropped and counted, never
//! waited for. A file is bounded at [`DEFAULT_MAX_FILE_BYTES`] and then rotated: the newest
//! traffic is always at the path, the file before it at `<path>.1`.

pub mod pcap;
pub mod tcp;
pub mod udp;
pub mod writer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::state::{ClientId, ServerId};
use writer::CaptureWriter;

/// A capture file is rotated when it would grow past this.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The protocols whose sockets feed a capture. Everything else accepts `capture` and writes
/// a file with a header and no packets, which [`CaptureStatus::adopted`] reports.
pub fn adopted(kind: OwnerKind, protocol: &str) -> bool {
    let name = protocol.trim().to_ascii_lowercase();
    match kind {
        OwnerKind::Server => matches!(
            name.as_str(),
            "tcp" | "telnet" | "http" | "redis" | "dns" | "udp"
        ),
        OwnerKind::Client => matches!(name.as_str(), "tcp"),
    }
}

/// Which instance a capture belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureOwner {
    Server(ServerId),
    Client(ClientId),
}

/// Server or client, without the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    Server,
    Client,
}

impl CaptureOwner {
    pub fn kind(&self) -> OwnerKind {
        match self {
            CaptureOwner::Server(_) => OwnerKind::Server,
            CaptureOwner::Client(_) => OwnerKind::Client,
        }
    }

    fn label(&self) -> (&'static str, u32) {
        match self {
            CaptureOwner::Server(id) => ("server", id.as_u32()),
            CaptureOwner::Client(id) => ("client", id.as_u32()),
        }
    }
}

/// What a caller asks for: `true` (the default file), `false` (stop), or a file path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CaptureSpec {
    Toggle(bool),
    Path(String),
}

impl CaptureSpec {
    /// Read `capture` from a JSON value: a boolean or a non-empty string.
    pub fn from_value(value: &serde_json::Value) -> anyhow::Result<Self> {
        match value {
            serde_json::Value::Bool(b) => Ok(CaptureSpec::Toggle(*b)),
            serde_json::Value::String(s) if !s.trim().is_empty() => {
                Ok(CaptureSpec::Path(s.trim().to_string()))
            }
            other => anyhow::bail!(
                "capture must be true, false or a file path for the pcap, not {other}"
            ),
        }
    }

    pub fn is_on(&self) -> bool {
        !matches!(self, CaptureSpec::Toggle(false))
    }
}

/// What a start asks of capture: an explicit spec, and whether it came from an action (the
/// model's `open_server`, a `.netget` file) rather than from the operator — an action may only
/// name a file in the capture directory. The default asks for nothing, which leaves
/// `--capture <dir>` to decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureRequest {
    pub spec: Option<CaptureSpec>,
    pub from_action: bool,
}

impl CaptureRequest {
    /// The operator's own `capture` (a form, an MCP tool).
    pub fn operator(spec: Option<CaptureSpec>) -> Self {
        Self {
            spec,
            from_action: false,
        }
    }

    /// `capture` read from an action.
    pub fn action(spec: Option<CaptureSpec>) -> Self {
        Self {
            spec,
            from_action: true,
        }
    }
}

/// Where a capture stands, for `server_status` / `client_status`, the dashboard and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureStatus {
    pub path: String,
    /// Packets written, synthesised handshakes and FINs included.
    pub packets: u64,
    /// Payload bytes written (headers excluded).
    pub bytes: u64,
    /// Packets dropped because the writer's queue was full or the file could not be
    /// written.
    pub dropped: u64,
    /// Times the file reached its bound and was rotated to `<path>.1`.
    pub rotations: u64,
    pub max_file_bytes: u64,
    /// The first write error, if any; the capture stops writing after one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether this protocol feeds its capture. `false` means the file will stay empty.
    pub adopted: bool,
}

/// One instance's hook into capture, shared by every connection it has. Exists whether or
/// not a capture is running, so a capture started later reaches connections already open.
#[derive(Default)]
pub struct CaptureSlot {
    writer: RwLock<Option<Arc<CaptureWriter>>>,
    ip_id: AtomicU64,
}

impl CaptureSlot {
    pub(crate) fn current(&self) -> Option<Arc<CaptureWriter>> {
        self.writer.read().ok().and_then(|w| w.clone())
    }

    /// Whether a capture is running — the cheap check before building a packet.
    pub fn is_active(&self) -> bool {
        self.writer.read().map(|w| w.is_some()).unwrap_or(false)
    }

    pub(crate) fn next_ip_id(&self) -> u16 {
        self.ip_id.fetch_add(1, Ordering::Relaxed) as u16
    }
}

struct Entry {
    slot: Arc<CaptureSlot>,
    protocol: String,
}

/// Every instance's capture slot, and the process-wide capture settings.
pub struct CaptureRegistry {
    entries: Mutex<HashMap<CaptureOwner, Entry>>,
    /// `--capture <dir>`: the capture directory, and the instruction to record every
    /// instance this process starts.
    capture_all_dir: RwLock<Option<PathBuf>>,
    max_file_bytes: AtomicU64,
}

impl Default for CaptureRegistry {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capture_all_dir: RwLock::new(None),
            max_file_bytes: AtomicU64::new(DEFAULT_MAX_FILE_BYTES),
        }
    }
}

impl CaptureRegistry {
    /// The slot a protocol records into. Created on first use; cheap to call per connection.
    pub fn slot(&self, owner: CaptureOwner) -> Arc<CaptureSlot> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .entry(owner)
            .or_insert_with(|| Entry {
                slot: Arc::new(CaptureSlot::default()),
                protocol: String::new(),
            })
            .slot
            .clone()
    }

    /// `--capture <dir>`: record every instance started from now on into `dir`, which is
    /// created if missing. `None` turns that off.
    pub fn set_capture_all_dir(&self, dir: Option<PathBuf>) -> anyhow::Result<()> {
        if let Some(dir) = &dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("--capture: cannot create directory {}: {e}", dir.display())
            })?;
        }
        *self
            .capture_all_dir
            .write()
            .unwrap_or_else(|e| e.into_inner()) = dir;
        Ok(())
    }

    pub fn capture_all_dir(&self) -> Option<PathBuf> {
        self.capture_all_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The bound a newly started capture's file is rotated at.
    pub fn set_max_file_bytes(&self, bytes: u64) {
        self.max_file_bytes
            .store(bytes.max(4096), Ordering::Relaxed);
    }

    /// The directory a `true` capture and a relative path are placed in: the `--capture`
    /// directory, else the working directory.
    pub fn directory(&self) -> PathBuf {
        self.capture_all_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    /// The file a `true` capture of `owner` writes.
    pub fn default_path(&self, owner: CaptureOwner, protocol: &str) -> PathBuf {
        let (kind, id) = owner.label();
        let proto: String = protocol
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        self.directory()
            .join(format!("netget-{kind}-{id}-{proto}.pcap"))
    }

    /// Resolve what `spec` names. `restricted` is for paths that did not come from the
    /// operator directly — the model's `open_server`, a `.netget` file's actions — which may
    /// only name a file inside the capture directory, never a path elsewhere on disk.
    pub fn resolve_path(
        &self,
        owner: CaptureOwner,
        protocol: &str,
        spec: &CaptureSpec,
        restricted: bool,
    ) -> anyhow::Result<Option<PathBuf>> {
        match spec {
            CaptureSpec::Toggle(false) => Ok(None),
            CaptureSpec::Toggle(true) => Ok(Some(self.default_path(owner, protocol))),
            CaptureSpec::Path(p) => {
                let path = Path::new(p);
                if restricted {
                    let plain = path.components().count() == 1
                        && matches!(
                            path.components().next(),
                            Some(std::path::Component::Normal(_))
                        );
                    if !plain {
                        anyhow::bail!(
                            "capture from an action may only name a file in the capture \
                             directory ({}), not a path: {p}",
                            self.directory().display()
                        );
                    }
                }
                Ok(Some(if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    self.directory().join(path)
                }))
            }
        }
    }

    /// Refuse, before anything starts, a `spec` that cannot be written: a directory that
    /// does not exist, a path that is a directory, or an existing file that is not a pcap.
    pub fn preflight(&self, spec: &CaptureSpec, restricted: bool) -> anyhow::Result<()> {
        // The owner only shapes the default file name, which cannot make it unwritable.
        let probe = CaptureOwner::Server(ServerId::new(0));
        let Some(path) = self.resolve_path(probe, "probe", spec, restricted)? else {
            return Ok(());
        };
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            anyhow::bail!("packet capture writes a file, and the browser build has no file system");
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if !dir.is_dir() {
                anyhow::bail!(
                    "cannot capture to {}: directory {} does not exist",
                    path.display(),
                    dir.display()
                );
            }
            if matches!(spec, CaptureSpec::Path(_)) {
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.is_dir() {
                        anyhow::bail!("cannot capture to {}: it is a directory", path.display());
                    }
                    if meta.len() > 0 {
                        use std::io::Read;
                        let mut head = [0u8; pcap::GLOBAL_HEADER_LEN];
                        let n = std::fs::File::open(&path)
                            .and_then(|mut f| f.read(&mut head))
                            .unwrap_or(0);
                        if pcap::header_kind(&head[..n]) == pcap::HeaderKind::NotPcap {
                            anyhow::bail!(
                                "cannot capture to {}: the file exists and is not a pcap, \
                                 and NetGet will not overwrite it",
                                path.display()
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    }

    /// Start (or move) `owner`'s capture to `path`, replacing one already running. With
    /// `append`, an existing NetGet capture at `path` is extended rather than truncated.
    pub async fn start(
        &self,
        owner: CaptureOwner,
        protocol: &str,
        path: &Path,
        append: bool,
    ) -> anyhow::Result<PathBuf> {
        let slot = self.slot(owner);
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(e) = entries.get_mut(&owner) {
                e.protocol = protocol.to_string();
            }
        }
        let previous = slot
            .writer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(prev) = previous {
            close(prev.clone()).await;
            // A capture moved to another file before it carried a packet — typically the
            // default file `--capture` gave an instance that was then given its own — leaves
            // nothing behind but a header, so it goes.
            if prev.path != path && prev.stats.packets.load(Ordering::Relaxed) == 0 {
                let _ = std::fs::remove_file(&prev.path);
            }
        }
        let writer = CaptureWriter::open(path, append, self.max_file_bytes.load(Ordering::Relaxed))
            .map_err(|e| anyhow::anyhow!("cannot capture to {}: {e}", path.display()))?;
        let path = writer.path.clone();
        *slot.writer.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(writer));
        tracing::info!(
            "packet capture of {protocol} {owner:?} writing {}",
            path.display()
        );
        Ok(path)
    }

    /// Apply a caller's `spec` to `owner`: start, move or stop its capture. Returns the file
    /// now being written, if any.
    pub async fn apply(
        &self,
        owner: CaptureOwner,
        protocol: &str,
        spec: &CaptureSpec,
        restricted: bool,
    ) -> anyhow::Result<Option<PathBuf>> {
        match self.resolve_path(owner, protocol, spec, restricted)? {
            None => {
                self.stop(owner).await;
                Ok(None)
            }
            Some(path) => {
                // Asking again for the file already being written changes nothing; it must
                // not truncate what has been captured so far.
                if self
                    .status(owner)
                    .is_some_and(|s| Path::new(&s.path) == path)
                {
                    return Ok(Some(path));
                }
                Ok(Some(self.start(owner, protocol, &path, false).await?))
            }
        }
    }

    /// The hook every server and client start passes through, after the instance is
    /// registered and before its protocol binds or connects, so the file holds its traffic
    /// from the first byte. An explicit `request` wins; without one, `--capture <dir>` starts
    /// the default capture. An explicit capture that cannot start is an error, and the start
    /// fails with it: the caller asked for a recorded instance.
    pub async fn begin(
        &self,
        owner: CaptureOwner,
        protocol: &str,
        request: &CaptureRequest,
    ) -> anyhow::Result<Option<PathBuf>> {
        match &request.spec {
            Some(spec) => self.apply(owner, protocol, spec, request.from_action).await,
            None => {
                self.start_if_capturing_all(owner, protocol).await;
                Ok(self.status(owner).map(|s| PathBuf::from(s.path)))
            }
        }
    }

    /// Under `--capture <dir>`, start `owner`'s default capture; otherwise nothing.
    pub async fn start_if_capturing_all(&self, owner: CaptureOwner, protocol: &str) {
        if self.capture_all_dir().is_none() {
            return;
        }
        let path = self.default_path(owner, protocol);
        if let Err(e) = self.start(owner, protocol, &path, false).await {
            tracing::error!("--capture: {e}");
        }
    }

    /// Stop `owner`'s capture, writing out what is queued. Returns its final counts.
    pub async fn stop(&self, owner: CaptureOwner) -> Option<CaptureStatus> {
        let slot = {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries.get(&owner).map(|e| e.slot.clone())
        }?;
        let writer = slot
            .writer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take()?;
        close(writer.clone()).await;
        Some(self.status_of(owner, &writer))
    }

    /// The instance is gone: stop its capture and drop its slot.
    pub async fn forget(&self, owner: CaptureOwner) -> Option<CaptureStatus> {
        let status = self.stop(owner).await;
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&owner);
        status
    }

    /// Where `owner`'s capture stands, if one is running.
    pub fn status(&self, owner: CaptureOwner) -> Option<CaptureStatus> {
        let slot = {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries.get(&owner).map(|e| e.slot.clone())
        }?;
        let writer = slot.current()?;
        Some(self.status_of(owner, &writer))
    }

    fn status_of(&self, owner: CaptureOwner, writer: &CaptureWriter) -> CaptureStatus {
        let protocol = self
            .entries
            .lock()
            .ok()
            .and_then(|e| e.get(&owner).map(|e| e.protocol.clone()))
            .unwrap_or_default();
        let s = &writer.stats;
        CaptureStatus {
            path: writer.path.display().to_string(),
            packets: s.packets.load(Ordering::Relaxed),
            bytes: s.bytes.load(Ordering::Relaxed),
            dropped: s.dropped.load(Ordering::Relaxed),
            rotations: s.rotations.load(Ordering::Relaxed),
            max_file_bytes: writer.max_file_bytes,
            error: s.error.lock().ok().and_then(|e| e.clone()),
            adopted: adopted(owner.kind(), &protocol),
        }
    }
}

/// Write out and close a writer that has been taken out of its slot. Packets submitted by a
/// connection that still held it are dropped and counted.
async fn close(writer: Arc<CaptureWriter>) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = tokio::task::spawn_blocking(move || writer.close_blocking()).await;
    }
    #[cfg(target_arch = "wasm32")]
    {
        drop(writer);
    }
}
