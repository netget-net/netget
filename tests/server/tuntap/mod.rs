//! TUN/TAP interface endpoint tests.
//!
//! Split the way the implementation is: `packet_test` drives the pure decoder, builder and
//! filter against literal packet bytes; `e2e_test` drives the whole event -> handler -> action
//! pipeline over an in-process channel transport, because the real transport needs root and
//! cannot run here. See `tests/server/tuntap/CLAUDE.md`.

#[cfg(unix)]
pub mod e2e_test;

#[cfg(unix)]
pub mod packet_test;
