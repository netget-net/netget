//! Event management module
//!
//! Handles all types of events (network, UI, timeout) and coordinates responses

pub mod errors;
pub mod handler;
pub mod types;

pub use errors::ActionExecutionError;
pub use handler::EventHandler;
pub use types::{AppEvent, HttpResponse, UserCommand};
pub mod journal;
