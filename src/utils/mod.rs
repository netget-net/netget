//! Utility modules

pub mod bencode;
pub mod bson_depth;
pub mod cbor_depth;
pub mod clock;
pub mod display;
pub mod file_io;
pub mod gre;
pub mod json_budget;
pub mod line_reader;
pub mod redact;
pub mod redis_keys;
pub mod resp;
pub mod sanitize;
pub mod save_load;
#[cfg(unix)]
pub mod sctp;
pub mod shutdown;
pub mod sql;
pub mod task_guard;
pub mod truncate;
pub mod wire_failure;

pub use shutdown::StopSignal;
pub use wire_failure::{prefixed_wire_failure_text, wire_failure_text, WireFailure};

pub use truncate::{
    truncate_for_llm, truncate_for_log, truncate_str, truncate_with_notice, truncate_with_suffix,
};

/// Whether a status-channel line is a control message rather than content.
///
/// The status channel carries human-readable lines (`[INFO] …`, `[ERROR] …`, chat text) and,
/// on the same stream, control sentinels such as `__UPDATE_UI__` — a protocol asking the
/// dashboard to repaint. Every consumer that shows the stream to someone (the dashboard's
/// chat, the non-interactive runner, MCP tool results and MCP's stderr) drops these; the rule
/// is the dashboard's, a leading `__`, kept here so they all share it.
pub fn is_status_control_line(line: &str) -> bool {
    line.starts_with("__")
}

#[cfg(not(target_arch = "wasm32"))]
pub mod quic;
