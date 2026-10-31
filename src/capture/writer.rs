//! The file side of a capture: one writer thread per capturing instance, fed through a
//! bounded channel so a protocol never waits on the disk.
//!
//! A full channel drops the packet and counts it ([`CaptureStats::dropped`]) rather than
//! blocking the connection that produced it. TCP sequence numbers still advance over a
//! dropped segment, so Wireshark reports the gap ("previous segment not captured") instead
//! of reassembling a stream that never happened.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use super::pcap;

/// Packets that may wait for the writer before new ones are dropped.
pub const CHANNEL_CAPACITY: usize = 8192;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) enum Msg {
    Packet { micros: u64, data: Vec<u8> },
    Close,
}

/// Counters a capture keeps while it runs. All monotonic.
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub dropped: AtomicU64,
    pub rotations: AtomicU64,
    pub error: Mutex<Option<String>>,
}

/// A running capture. Held by the instance's slot; a connection borrows it per packet.
pub(crate) struct CaptureWriter {
    /// Distinguishes this file from an earlier one on the same instance, so a connection
    /// that outlives a stop/start opens its stream again (SYN, SYN-ACK, ACK) in the new file.
    pub generation: u64,
    pub path: PathBuf,
    pub max_file_bytes: u64,
    pub stats: Arc<CaptureStats>,
    tx: SyncSender<Msg>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl CaptureWriter {
    /// Open (or extend) `path` and start its writer thread. Synchronous because every
    /// reason a capture cannot start — a missing directory, a permission, a file that is
    /// not a capture — belongs in the caller's answer rather than in a log line later.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn open(path: &Path, append: bool, max_file_bytes: u64) -> anyhow::Result<Self> {
        use std::io::{Read, Seek, SeekFrom, Write};

        let mut existing_len = 0u64;
        let mut appendable = false;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.is_dir() {
                anyhow::bail!("capture path {} is a directory", path.display());
            }
            if meta.len() > 0 {
                let mut head = [0u8; pcap::GLOBAL_HEADER_LEN];
                let mut f = std::fs::File::open(path)?;
                let n = f.read(&mut head)?;
                match pcap::header_kind(&head[..n]) {
                    pcap::HeaderKind::NotPcap => anyhow::bail!(
                        "capture path {} already exists and is not a pcap file; NetGet will \
                         not overwrite it",
                        path.display()
                    ),
                    pcap::HeaderKind::OtherPcap => {}
                    pcap::HeaderKind::Appendable => {
                        appendable = true;
                        existing_len = meta.len();
                    }
                }
            }
        }

        let mut file = if append && appendable {
            let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
            f.seek(SeekFrom::End(0))?;
            f
        } else {
            existing_len = 0;
            std::fs::File::create(path)?
        };
        if existing_len == 0 {
            file.write_all(&pcap::global_header())?;
            file.flush()?;
            existing_len = pcap::GLOBAL_HEADER_LEN as u64;
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
        let stats = Arc::new(CaptureStats::default());
        let thread_stats = stats.clone();
        let thread_path = path.to_path_buf();
        let join = std::thread::Builder::new()
            .name("netget-capture".into())
            .spawn(move || {
                run(
                    rx,
                    file,
                    existing_len,
                    thread_path,
                    max_file_bytes,
                    thread_stats,
                )
            })?;
        Ok(Self {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            path: path.to_path_buf(),
            max_file_bytes,
            stats,
            tx,
            join: Mutex::new(Some(join)),
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn open(_path: &Path, _append: bool, _max_file_bytes: u64) -> anyhow::Result<Self> {
        anyhow::bail!("packet capture writes a file, and the browser build has no file system")
    }

    /// Queue one IP packet. Never blocks: a full queue drops the packet and counts it.
    pub fn submit(&self, data: Vec<u8>) {
        let micros = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        match self.tx.try_send(Msg::Packet { micros, data }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Write out everything queued, close the file and wait for the thread. Blocking; call
    /// it off the async runtime.
    pub fn close_blocking(&self) {
        let _ = self.tx.send(Msg::Close);
        if let Some(join) = self.join.lock().ok().and_then(|mut j| j.take()) {
            let _ = join.join();
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn run(
    rx: Receiver<Msg>,
    file: std::fs::File,
    mut written: u64,
    path: PathBuf,
    max_file_bytes: u64,
    stats: Arc<CaptureStats>,
) {
    use std::io::{BufWriter, Write};

    let mut out = Some(BufWriter::with_capacity(256 * 1024, file));
    let fail = |stats: &CaptureStats, e: String| {
        tracing::error!("packet capture: {e}");
        if let Ok(mut slot) = stats.error.lock() {
            slot.get_or_insert(e);
        }
    };
    let mut handle = |msg: Msg, out: &mut Option<BufWriter<std::fs::File>>| -> bool {
        let (micros, data) = match msg {
            Msg::Close => return false,
            Msg::Packet { micros, data } => (micros, data),
        };
        let Some(w) = out.as_mut() else {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        let record_len = (pcap::RECORD_HEADER_LEN + data.len()) as u64;
        // Rotate before a record would take the file past its bound, keeping one
        // predecessor: the newest traffic is always at `path`, the file before it at
        // `path.1`, and the disk holds at most two bounds' worth.
        if written + record_len > max_file_bytes && written > pcap::GLOBAL_HEADER_LEN as u64 {
            let _ = w.flush();
            *out = None;
            let previous = rotated_path(&path);
            let reopened = std::fs::rename(&path, &previous)
                .and_then(|_| std::fs::File::create(&path))
                .and_then(|mut f| {
                    f.write_all(&pcap::global_header())?;
                    Ok(f)
                });
            match reopened {
                Ok(f) => {
                    *out = Some(BufWriter::with_capacity(256 * 1024, f));
                    written = pcap::GLOBAL_HEADER_LEN as u64;
                    stats.rotations.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    fail(&stats, format!("rotating {}: {e}", path.display()));
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        let Some(w) = out.as_mut() else {
            return true;
        };
        let header = pcap::record_header(micros, data.len());
        match w.write_all(&header).and_then(|_| w.write_all(&data)) {
            Ok(()) => {
                written += record_len;
                stats.packets.fetch_add(1, Ordering::Relaxed);
                stats.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                fail(&stats, format!("writing {}: {e}", path.display()));
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                *out = None;
            }
        }
        true
    };

    'outer: while let Ok(msg) = rx.recv() {
        if !handle(msg, &mut out) {
            break;
        }
        // Drain what is already waiting, then flush once: the file is whole at a record
        // boundary whenever the queue is empty, so a reader never needs the capture stopped.
        while let Ok(msg) = rx.try_recv() {
            if !handle(msg, &mut out) {
                break 'outer;
            }
        }
        if let Some(w) = out.as_mut() {
            if let Err(e) = w.flush() {
                fail(&stats, format!("flushing {}: {e}", path.display()));
            }
        }
    }
    if let Some(mut w) = out {
        let _ = w.flush();
    }
}

/// Where a rotated file goes: `capture.pcap` → `capture.pcap.1`.
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}
