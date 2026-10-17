//! Named pipe (POSIX FIFO) server tests
//!
//! Platform: Unix/Linux/macOS only
#![cfg(unix)]

pub mod e2e_test;
pub mod batching_test;
