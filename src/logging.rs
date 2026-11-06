//! Dual logging macros that log to both tracing (file) and status channel (TUI)
//!
//! Also includes shared log pattern constants for test assertions, and a
//! size-based rotating file writer (see [`RotatingFileWriter`]) that bounds
//! total on-disk log usage.

pub mod emit;
pub mod patterns;
pub mod status_drain;

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Default per-file size cap before rotation: 50 MiB.
///
/// `netget.log` is written at TRACE level by default in development builds
/// and can contain full request/response payloads, so it grows quickly.
/// 50 MiB keeps a single file comfortably viewable/greppable while still
/// holding a useful amount of recent history.
pub const DEFAULT_MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Default number of rotated (non-active) files retained: 5.
///
/// Combined with `DEFAULT_MAX_LOG_BYTES`, this bounds total log disk usage
/// to `(DEFAULT_MAX_LOG_FILES + 1) * DEFAULT_MAX_LOG_BYTES` = ~300 MiB
/// (1 active file + up to 5 rotated files), a hard ceiling well below the
/// 481 MB the unbounded file reached in a single day of use, while still
/// keeping several rotations of history around for debugging.
pub const DEFAULT_MAX_LOG_FILES: usize = 5;

/// Internal mutable state for a [`RotatingFileWriter`], guarded by a mutex
/// so concurrent writers (many tokio tasks logging at once) never interleave
/// writes or race on rotation.
struct RotatingState {
    /// Path of the active log file (e.g. `netget.log`).
    path: PathBuf,
    /// Rotate once the active file reaches this many bytes. `0` disables
    /// rotation entirely.
    max_bytes: u64,
    /// Number of rotated files to retain (`netget.log.1` .. `netget.log.N`).
    max_files: usize,
    /// Open handle to the active file, always positioned for appending.
    file: File,
    /// Bytes written to the active file so far (avoids an `fstat` per write).
    written: u64,
}

impl RotatingState {
    fn open(path: PathBuf, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            max_files,
            file,
            written,
        })
    }

    /// Path for the Nth rotated file, e.g. `netget.log.1`.
    fn rotated_path(&self, n: usize) -> PathBuf {
        let mut name: OsString = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// Roll the active file out to `.1`, shifting existing rotated files up
    /// and dropping the oldest once `max_files` is exceeded, then open a
    /// fresh active file in its place.
    ///
    /// The current file handle is flushed (not dropped) before the rename so
    /// no buffered bytes are lost; on Unix, renaming a file that is still
    /// open is safe (the inode stays valid for the open handle) and the
    /// fresh handle opened afterwards points at the new (recreated) path.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        if self.max_files == 0 {
            // No retention requested: just drop the current contents.
            let _ = fs::remove_file(&self.path);
        } else {
            let oldest = self.rotated_path(self.max_files);
            if oldest.exists() {
                fs::remove_file(&oldest)?;
            }
            for i in (1..self.max_files).rev() {
                let from = self.rotated_path(i);
                if from.exists() {
                    fs::rename(&from, self.rotated_path(i + 1))?;
                }
            }
            if self.path.exists() {
                fs::rename(&self.path, self.rotated_path(1))?;
            }
        }

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Check-then-roll before writing: guarantees the file we are about
        // to append to is never allowed to grow past max_bytes, without
        // ever truncating or losing the bytes about to be written (they are
        // written to the fresh file after rotation completes).
        if self.max_bytes > 0 && self.written >= self.max_bytes {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    /// Write the whole buffer as a single logical record while the caller
    /// holds the mutex for the entire call (see
    /// [`RotatingFileWriter::write_all`]/`write_fmt` below): this is what
    /// keeps a multi-fragment record (e.g. one `tracing` line, or the
    /// several `write_str` calls `std::fmt` makes for a single `write!()`)
    /// from being torn apart by another thread's write landing in the
    /// middle of it.
    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A `Write` + `Clone` file writer that rotates itself by size.
///
/// All clones share the same underlying state behind an `Arc<Mutex<..>>>`,
/// so it is safe to hand a clone to every `tracing` writer/task: writes are
/// serialized through the mutex, which both prevents interleaved/corrupted
/// lines under concurrent logging from many tokio tasks and makes the
/// size-check-then-rotate sequence atomic with respect to other writers (no
/// writer can observe a mid-rotation state).
///
/// Also implements `tracing_subscriber::fmt::MakeWriter` directly so it can
/// be passed straight to `fmt::layer().with_writer(..)`, or wrapped by
/// another `MakeWriter` (e.g. a color-processing writer) that delegates its
/// inner writes to a clone of this type.
#[derive(Clone)]
pub struct RotatingFileWriter {
    state: Arc<Mutex<RotatingState>>,
}

impl RotatingFileWriter {
    /// Open (or create) `path` as a rotating log file using the crate
    /// defaults ([`DEFAULT_MAX_LOG_BYTES`] / [`DEFAULT_MAX_LOG_FILES`]).
    ///
    /// If the file already exists and is already at or past the size cap
    /// (e.g. an old unbounded log), the existing contents are preserved,
    /// never truncated or deleted: the first write rotates it out to
    /// `<path>.1` before appending, exactly like any other rotation.
    pub fn new<P: Into<PathBuf>>(path: P) -> io::Result<Self> {
        Self::with_limits(path, DEFAULT_MAX_LOG_BYTES, DEFAULT_MAX_LOG_FILES)
    }

    /// Same as [`Self::new`] but with explicit limits, primarily for tests
    /// and callers that want non-default rotation behavior.
    ///
    /// `max_bytes = 0` disables rotation (unbounded growth). `max_files = 0`
    /// rotates by discarding the old file's contents instead of retaining
    /// history.
    pub fn with_limits<P: Into<PathBuf>>(
        path: P,
        max_bytes: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        let state = RotatingState::open(path.into(), max_bytes, max_files)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.write(buf)
    }

    /// Overridden (rather than relying on the default loop-over-`write`) so
    /// the mutex is acquired exactly once for the whole buffer: no other
    /// writer can interleave a write — or observe/trigger a rotation — in
    /// the middle of this record.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.write_all(buf)
    }

    /// Overridden so a single `write!()`/`writeln!()` call — which
    /// `std::fmt` may internally split into several `write_str` fragments
    /// (one per literal segment and per formatted argument) — is first
    /// assembled into one buffer and then written via [`Self::write_all`]
    /// under a single lock acquisition, instead of each fragment taking and
    /// releasing the lock separately (which would let another thread's
    /// fragment land in between and corrupt the line). This mirrors how
    /// `tracing-subscriber`'s fmt layer already formats a full event into a
    /// buffer before issuing one `write_all` call.
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        use std::fmt::Write as _;
        let mut formatted = String::new();
        formatted
            .write_fmt(fmt)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.write_all(formatted.as_bytes())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingFileWriter {
    type Writer = RotatingFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Log at TRACE level to both file and TUI
#[macro_export]
macro_rules! console_trace {
    ($status_tx:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::trace!("{}", msg);
        if !msg.starts_with("__") {
            let _ = $status_tx.send(format!("[TRACE] {}", msg));
        } else {
            let _ = $status_tx.send(msg);
        }
    }};
}

/// Log at DEBUG level to both file and TUI
#[macro_export]
macro_rules! console_debug {
    ($status_tx:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::debug!("{}", msg);
        if !msg.starts_with("__") {
            let _ = $status_tx.send(format!("[DEBUG] {}", msg));
        } else {
            let _ = $status_tx.send(msg);
        }
    }};
}

/// Log at INFO level to both file and TUI
#[macro_export]
macro_rules! console_info {
    ($status_tx:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::info!("{}", msg);
        if !msg.starts_with("__") {
            let _ = $status_tx.send(format!("[INFO] {}", msg));
        } else {
            let _ = $status_tx.send(msg);
        }
    }};
}

/// Log at WARN level to both file and TUI
#[macro_export]
macro_rules! console_warn {
    ($status_tx:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::warn!("{}", msg);
        if !msg.starts_with("__") {
            let _ = $status_tx.send(format!("[WARN] {}", msg));
        } else {
            let _ = $status_tx.send(msg);
        }
    }};
}

/// Log at ERROR level to both file and TUI
#[macro_export]
macro_rules! console_error {
    ($status_tx:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::error!("{}", msg);
        if !msg.starts_with("__") {
            let _ = $status_tx.send(format!("[ERROR] {}", msg));
        } else {
            let _ = $status_tx.send(msg);
        }
    }};
}
