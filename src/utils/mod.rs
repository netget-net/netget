//! Utility modules

pub mod bencode;
pub mod bson_depth;
pub mod clock;
pub mod file_io;
pub mod gre;
pub mod json_budget;
pub mod line_reader;
pub mod redact;
pub mod redis_keys;
pub mod resp;
pub mod sanitize;
pub mod save_load;
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

#[cfg(not(target_arch = "wasm32"))]
pub mod quic;
