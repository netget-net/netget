//! Single dual-sink logging facade.
//!
//! Historically every call site that wanted a line in both the file log and the
//! TUI wrote the two independently: a `tracing` macro for the file, and a
//! hand-typed `status_tx.send(format!("[LEVEL] …"))` for the TUI. The `[LEVEL]`
//! bracket was a *string*, unrelated to the `tracing` level next to it, so the
//! two channels routinely disagreed on the level of the same event (see the
//! logging revamp design). There was also no level filtering on the TUI stream
//! at all — a `[TRACE]` payload reached the TUI even in a release build whose
//! file log was INFO-filtered.
//!
//! [`Log`] fixes the drift structurally: one [`Level`] value drives **both** the
//! `tracing` macro and the TUI bracket prefix, so `[INFO]` on the TUI can never
//! disagree with `info!` in the file. It also encodes the CLAUDE.md level
//! convention as routing defaults (see [`default_sink`]): payloads and summaries
//! (`TRACE`/`DEBUG`) stay file-only and off the unbounded status channel unless a
//! caller explicitly opts them in.
//!
//! This is the path the per-protocol logging sweep is meant to adopt everywhere;
//! for now it is used only on the LLM request/response path
//! (`llm::conversation`, `llm::ollama_client`).
//!
//! Note: because the `tracing` macro fires inside this module, file-log lines
//! carry `netget::logging::emit` as their target rather than the originating
//! module. Level-based `EnvFilter` (`netget=…`) still applies; only the
//! module-path breadcrumb changes.

use std::fmt::Display;
use tokio::sync::mpsc::UnboundedSender;

/// Severity of a log line.
///
/// The variant name is *simultaneously* the `tracing` level and the TUI bracket
/// prefix, which is the whole point: the two cannot drift because they are read
/// off the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    /// Uppercase name, identical to the corresponding [`tracing::Level`] name.
    pub fn name(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    /// The TUI bracket prefix (e.g. `"[INFO]"`), derived from [`Self::name`] so
    /// it can never disagree with the level used for the file log.
    pub fn tui_prefix(self) -> String {
        format!("[{}]", self.name())
    }
}

/// Where a line is delivered.
///
/// The file log (via `tracing`) *always* receives the line; the TUI status
/// stream is opt-in per line via [`Sink::Both`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// File log only. The default for `DEBUG`/`TRACE`.
    FileOnly,
    /// File log and the TUI status stream.
    Both,
}

impl Sink {
    /// Whether this routing reaches the TUI status stream.
    pub fn reaches_tui(self) -> bool {
        matches!(self, Sink::Both)
    }
}

/// Default routing for a level, encoding the CLAUDE.md convention:
///
/// - `ERROR` / `WARN` / `INFO` — lifecycle and problems: [`Sink::Both`].
/// - `DEBUG` / `TRACE` — summaries and payloads: [`Sink::FileOnly`], to keep
///   high-volume detail off the unbounded status channel.
pub fn default_sink(level: Level) -> Sink {
    match level {
        Level::Error | Level::Warn | Level::Info => Sink::Both,
        Level::Debug | Level::Trace => Sink::FileOnly,
    }
}

/// A dual-sink emitter bound to an optional TUI status channel.
///
/// Construct one per call site (it borrows the channel, so it is a zero-cost
/// wrapper) and emit through it. Every method routes to the file log via
/// `tracing` and, when the [`Sink`] permits and a channel is present, to the
/// TUI with a bracket prefix that matches the level exactly.
pub struct Log<'a> {
    status_tx: Option<&'a UnboundedSender<String>>,
    payloads: bool,
}

impl<'a> Log<'a> {
    /// Bind the facade to an optional TUI status channel. `None` makes every
    /// emission file-only regardless of [`Sink`].
    pub fn new(status_tx: Option<&'a UnboundedSender<String>>) -> Self {
        Self {
            status_tx,
            payloads: true,
        }
    }

    /// Bind the facade to a status channel that is always present.
    ///
    /// Takes the channel by reference, so `Log::to(&status_tx)` reads the same whether
    /// `status_tx` is an owned sender, a `&` to one or an `Arc` around one.
    pub fn to(status_tx: &'a UnboundedSender<String>) -> Self {
        Self::new(Some(status_tx))
    }

    /// Suppress DEBUG/TRACE previews and bodies for one credential-bearing request.
    /// This is local to the emitter; it does not change shared logging settings.
    pub fn with_payloads(mut self, enabled: bool) -> Self {
        self.payloads = enabled;
        self
    }

    /// Core fan-out: log `msg` at `level`, delivered per `sink`.
    ///
    /// The file log always receives it (at the matching `tracing` level); the
    /// TUI receives `"[LEVEL] msg"` only when `sink` is [`Sink::Both`] and a
    /// channel is bound.
    pub fn emit(&self, level: Level, sink: Sink, msg: impl Display) {
        if !self.payloads && matches!(level, Level::Debug | Level::Trace) {
            return;
        }
        // Peer-derived text arrives here from every protocol. `netget.log` is read with
        // `tail -f` and the TUI paints the `[LEVEL]` copy, so a control character in it is
        // an escape sequence on a real terminal; `multiline` keeps newline and tab only.
        let text = crate::utils::sanitize::multiline(&msg.to_string());

        // File log — always, at the level that matches the TUI prefix.
        match level {
            Level::Error => tracing::error!("{}", text),
            Level::Warn => tracing::warn!("{}", text),
            Level::Info => tracing::info!("{}", text),
            Level::Debug => tracing::debug!("{}", text),
            Level::Trace => tracing::trace!("{}", text),
        }

        // TUI — opt-in; prefix derived from the SAME level.
        if sink.reaches_tui() {
            if let Some(tx) = self.status_tx {
                let _ = tx.send(format!("{} {}", level.tui_prefix(), text));
            }
        }
    }

    /// `ERROR`: something cannot proceed. Always file + TUI.
    pub fn error(&self, msg: impl Display) {
        self.emit(Level::Error, Sink::Both, msg);
    }

    /// `WARN`: degraded, retried or fell back but recovered. Always file + TUI.
    pub fn warn(&self, msg: impl Display) {
        self.emit(Level::Warn, Sink::Both, msg);
    }

    /// `INFO`: one lifecycle line. File + TUI by default; pass a [`Sink`] via
    /// [`Self::info_to`] to keep it file-only.
    pub fn info(&self, msg: impl Display) {
        self.emit(Level::Info, default_sink(Level::Info), msg);
    }

    /// `INFO` with explicit routing.
    pub fn info_to(&self, sink: Sink, msg: impl Display) {
        self.emit(Level::Info, sink, msg);
    }

    /// `DEBUG`: a summary/count/timing. File-only by default.
    pub fn debug(&self, msg: impl Display) {
        self.emit(Level::Debug, default_sink(Level::Debug), msg);
    }

    /// `DEBUG` with explicit routing (e.g. surface a summary on the TUI).
    pub fn debug_to(&self, sink: Sink, msg: impl Display) {
        self.emit(Level::Debug, sink, msg);
    }

    /// `TRACE`: a full payload. File-only by default and rarely anything else —
    /// full payloads must not be streamed to the unbounded TUI channel.
    pub fn trace(&self, msg: impl Display) {
        self.emit(Level::Trace, default_sink(Level::Trace), msg);
    }

    /// `TRACE` with explicit routing.
    pub fn trace_to(&self, sink: Sink, msg: impl Display) {
        self.emit(Level::Trace, sink, msg);
    }

    /// Log a labelled, char-safe, truncated payload preview at `TRACE`,
    /// file-only. Reuses [`crate::utils::truncate_for_log`] so a multi-byte cut
    /// point can never panic.
    pub fn payload(&self, label: &str, body: &str, max_bytes: usize) {
        self.emit(
            Level::Trace,
            Sink::FileOnly,
            format!(
                "{}: {}",
                label,
                crate::utils::truncate_for_log(body, max_bytes)
            ),
        );
    }
}
