//! Tor Network Integration Tests
//!
//! This module provides comprehensive E2E tests that integrate all three components:
//! - Official Tor client (or arti-client as fallback)
//! - NetGet Tor Relay
//! - NetGet Tor Directory
//!
//! These tests create a minimal local Tor network and validate end-to-end functionality.

#[cfg(unix)]
pub mod e2e_test;

pub mod consensus_builder;
pub mod helpers;
pub mod tor_client;
