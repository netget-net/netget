//! Setup utilities for logging and terminal initialization

use anyhow::Result;
use crossterm::event::PopKeyboardEnhancementFlags;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use std::io::{self, Write};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use super::Args;
use crate::logging::RotatingFileWriter;

/// Custom writer that applies bright cyan color to TRACE level logs.
///
/// Writes through a [`RotatingFileWriter`], which bounds total on-disk log
/// size. It carries its own `Arc<Mutex<_>>` and is `Clone`, so this wrapper
/// holds it directly rather than adding a second layer of locking.
struct ColoredLogWriter {
    inner: RotatingFileWriter,
}

impl ColoredLogWriter {
    fn new(file: RotatingFileWriter) -> Self {
        Self { inner: file }
    }
}

impl Write for ColoredLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Convert to string to check for TRACE level
        if let Ok(s) = std::str::from_utf8(buf) {
            // Replace any ANSI color code before " TRACE" with bright cyan
            // Look for the pattern: ESC[<numbers>m TRACE
            let mut modified = String::with_capacity(s.len());
            let mut chars = s.chars().peekable();

            while let Some(ch) = chars.next() {
                if ch == '\x1b' {
                    // Start of ANSI sequence
                    let mut seq = String::from("\x1b");

                    // Collect the ANSI sequence
                    while let Some(&next_ch) = chars.peek() {
                        seq.push(next_ch);
                        chars.next();
                        if next_ch == 'm' {
                            break;
                        }
                    }

                    // Check if this is followed by " TRACE"
                    let remaining: String = chars.clone().collect();
                    if remaining.starts_with(" TRACE") {
                        // Replace with bright cyan
                        modified.push_str("\x1b[96m");
                    } else {
                        // Keep original sequence
                        modified.push_str(&seq);
                    }
                } else {
                    modified.push(ch);
                }
            }

            self.inner.write_all(modified.as_bytes())?;
            Ok(buf.len())
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Clone for ColoredLogWriter {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// MakeWriter implementation for ColoredLogWriter
struct ColoredLogWriterMaker {
    writer: ColoredLogWriter,
}

impl ColoredLogWriterMaker {
    fn new(file: RotatingFileWriter) -> Self {
        Self {
            writer: ColoredLogWriter::new(file),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ColoredLogWriterMaker {
    type Writer = ColoredLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.writer.clone()
    }
}

/// Initialize logging based on arguments
pub fn init_logging(args: &Args, is_interactive: bool) -> Result<()> {
    if args.logging_disabled() {
        // No-op subscriber when logging is explicitly disabled
        tracing_subscriber::registry()
            .with(EnvFilter::new("off"))
            .init();
    } else if is_interactive {
        // Interactive (TUI) mode: log to netget.log file with bright cyan color
        // Development builds default to TRACE, release builds default to INFO
        // Size-bounded: rotates at DEFAULT_MAX_LOG_BYTES keeping
        // DEFAULT_MAX_LOG_FILES generations. An existing oversized log is
        // rotated out on first write, never truncated.
        let log_file = RotatingFileWriter::new("netget.log")?;

        let colored_writer = ColoredLogWriterMaker::new(log_file);

        let default_level = if cfg!(debug_assertions) {
            Level::TRACE
        } else {
            Level::INFO
        };

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("netget={}", default_level)));

        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_writer(colored_writer)
                    .with_ansi(true)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_line_number(true),
            )
            .with(filter)
            .init();
    } else {
        // Non-interactive mode: log to stderr with configured level
        let log_level = args.effective_log_level();

        // Create environment filter
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("netget={log_level}")));

        // Log to stderr in non-interactive mode
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_writer(io::stderr)
                    .with_ansi(true)
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_line_number(false),
            )
            .with(filter)
            .init();
    }

    // Every entry point comes through here before doing any work, which is why the hook is
    // installed here rather than in `main`: `--mcp`, `--mcp-http` and the
    // non-interactive runner each reach `run()` by a different path and none of them touched
    // the TUI's hook. Installed *after* the subscriber, because a panic logged before there is
    // one goes exactly where the panic would have gone.
    crate::panic_log::install();

    Ok(())
}

/// Guard to reset terminal state on drop
pub struct TerminalGuard {
    enhanced_supported: bool,
}

impl TerminalGuard {
    #[allow(dead_code)]
    pub fn new(enhanced_supported: bool) -> Self {
        Self { enhanced_supported }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.enhanced_supported {
            let _ = execute!(io::stdout(), PopKeyboardEnhancementFlags);
        }
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
