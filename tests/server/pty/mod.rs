//! Pseudo-terminal (PTY) server tests
//!
//! Platform: Unix/Linux/macOS only
#![cfg(unix)]

pub mod e2e_test;
mod startup_cleanup_test;
