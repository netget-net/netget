//! In-memory chat/log history for the dashboard.
//!
//! The full-screen alternate screen has no terminal scrollback, so the
//! dashboard keeps its own ring buffer of entries. Lines arrive on the same
//! unbounded status channel the rolling TUI drains, with the same `[LEVEL]`
//! prefix protocol. Unlike the rolling TUI (which drops filtered lines
//! forever), filtering happens at render time — raising the log level
//! retroactively reveals recently buffered DEBUG/TRACE lines.

use std::collections::VecDeque;

use crate::ui::app::LogLevel;

/// Ring capacity: enough scrollback for a long session without unbounded
/// growth under a log flood.
pub const CHAT_CAPACITY: usize = 5_000;

/// Lines shown per frame. Everything queued is drained each frame; past this many the rest
/// are dropped and counted (`logging::status_drain`), so a flood costs a notice rather
/// than a frozen UI or a queue that grows for as long as the flood lasts.
pub const DRAIN_CAP_PER_FRAME: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Text the user typed.
    User,
    /// Streamed model reasoning (`[REASONING]` lines).
    Reasoning,
    /// A `[LEVEL]`-prefixed log line.
    Log(LogLevel),
    /// Unprefixed output (command results, welcome text, model notes).
    System,
}

#[derive(Debug, Clone)]
pub struct ChatEntry {
    pub seq: u64,
    pub kind: EntryKind,
    pub text: String,
}

/// Scroll position: following the tail, or anchored at an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollPos {
    Follow,
    /// Anchored: `lines_up` wrapped display lines above the tail.
    Up(usize),
}

pub struct ChatState {
    pub entries: VecDeque<ChatEntry>,
    pub scroll: ScrollPos,
    /// Entries that arrived while scrolled up (drives the "[N new] ↓" pill).
    pub unseen: usize,
    next_seq: u64,
}

impl ChatState {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            scroll: ScrollPos::Follow,
            unseen: 0,
            next_seq: 1,
        }
    }

    pub fn push(&mut self, kind: EntryKind, text: impl Into<String>) {
        let text = text.into();
        self.entries.push_back(ChatEntry {
            seq: self.next_seq,
            kind,
            text,
        });
        self.next_seq += 1;
        if self.entries.len() > CHAT_CAPACITY {
            self.entries.pop_front();
        }
        if self.scroll != ScrollPos::Follow {
            self.unseen += 1;
        }
    }

    /// Parse one status-channel line into an entry, mirroring the rolling
    /// TUI's prefix protocol. Returns false for the `__UPDATE_UI__` sentinel
    /// (and other `__` control messages), which are not chat content.
    ///
    /// The dashboard routes lines between the feed and the chat with
    /// [`route_status_line`]; this pushes everything into the chat, for
    /// callers that have only one pane.
    pub fn push_status_line(&mut self, line: &str) -> bool {
        match route_status_line(line) {
            Routed::Control => false,
            Routed::Activity(level, text) => {
                self.push(EntryKind::Log(level), text);
                true
            }
            Routed::Chat(kind, text) => {
                self.push(kind, text);
                true
            }
        }
    }

    /// Whether an entry passes the current log-level filter.
    pub fn passes_filter(entry: &ChatEntry, level: LogLevel) -> bool {
        match entry.kind {
            EntryKind::Log(entry_level) => entry_level <= level,
            _ => true,
        }
    }

    pub fn scroll_to_follow(&mut self) {
        self.scroll = ScrollPos::Follow;
        self.unseen = 0;
    }

    pub fn scroll_up(&mut self, lines: usize) {
        self.scroll = match self.scroll {
            ScrollPos::Follow => ScrollPos::Up(lines),
            ScrollPos::Up(n) => ScrollPos::Up(n.saturating_add(lines)),
        };
    }

    pub fn scroll_down(&mut self, lines: usize) {
        self.scroll = match self.scroll {
            ScrollPos::Follow => ScrollPos::Follow,
            ScrollPos::Up(n) => {
                let n = n.saturating_sub(lines);
                if n == 0 {
                    self.unseen = 0;
                    ScrollPos::Follow
                } else {
                    ScrollPos::Up(n)
                }
            }
        };
    }
}

/// Where a status-channel line belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routed {
    /// `__UPDATE_UI__` and other `__` control messages: not content.
    Control,
    /// A `[LEVEL]` log line: the machine talking. Goes to the activity feed
    /// (an `[ERROR]` is mirrored into the chat too, since the person who
    /// caused it is looking there).
    Activity(LogLevel, String),
    /// The conversation: what the model reasons and says, and command output.
    Chat(EntryKind, String),
}

/// Decide which pane a status line belongs to.
pub fn route_status_line(line: &str) -> Routed {
    if crate::utils::is_status_control_line(line) {
        return Routed::Control;
    }
    if let Some(rest) = line.strip_prefix("[ERROR] ") {
        Routed::Activity(LogLevel::Error, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("[WARN] ") {
        Routed::Activity(LogLevel::Warn, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("[INFO] ") {
        Routed::Activity(LogLevel::Info, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("[DEBUG] ") {
        Routed::Activity(LogLevel::Debug, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("[TRACE] ") {
        Routed::Activity(LogLevel::Trace, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("[REASONING] ") {
        Routed::Chat(EntryKind::Reasoning, rest.to_string())
    } else if line.starts_with("[SERVER] ") || line.starts_with("[CLIENT] ") {
        // Instance lifecycle chatter ("Starting server #1 (TCP) on …"): the
        // machine talking, at INFO. The feed already derives the structured
        // version from the snapshot; the line keeps the wording for the log.
        Routed::Activity(LogLevel::Info, line.to_string())
    } else {
        Routed::Chat(EntryKind::System, line.to_string())
    }
}
