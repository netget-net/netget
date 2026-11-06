//! NetGet - LLM-Controlled Network Application
//!
//! A Rust CLI application that allows an LLM to control network protocols
//! and act as a server or client for various protocols (TCP, FTP, etc.).

// The browser build has no OS underneath. On wasm32 the names `tokio` and `crossterm` mean
// the shim crates under `crates/`: the JS event loop as executor, a virtual loopback network,
// and crossterm's key/colour types without a terminal. Binding them here, once, at the crate
// root is what lets every `tokio::spawn` and `KeyCode::Char` in the tree compile unchanged.
// See crates/netget-tokio-wasm/src/lib.rs for what is real tokio and what is not.
#[cfg(target_arch = "wasm32")]
extern crate netget_crossterm_wasm as crossterm;
#[cfg(target_arch = "wasm32")]
extern crate netget_tokio_wasm as tokio;

pub mod capture;
pub mod cli;
pub mod client;
pub mod display;
pub mod docs;
pub mod events;
pub mod llm;
pub mod logging;
#[cfg(any(feature = "mcp-stdio", feature = "mcp-http"))]
pub mod mcp_stdio;
pub mod panic_log;
pub mod pipe;
pub mod privilege;
pub mod protocol;
pub mod scripting;
pub mod server;
pub mod settings;
pub mod state;
pub mod system_stats;
pub mod tui;
pub mod ui;
pub mod utils;
