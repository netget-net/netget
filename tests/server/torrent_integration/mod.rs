//! BitTorrent Network Integration Tests
//!
//! This module provides comprehensive E2E tests that integrate all three BitTorrent components:
//! - NetGet Tracker (HTTP tracker for peer coordination)
//! - NetGet DHT (UDP distributed hash table)
//! - NetGet Peer (TCP peer wire protocol seeder)
//!
//! These tests create a minimal local BitTorrent network and validate end-to-end functionality
//! using both Rust client libraries and real BitTorrent clients.

pub mod e2e_test;

pub mod helpers;
pub mod torrent_builder;
