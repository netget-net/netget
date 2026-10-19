//! NATS client tests.
//!
//! Declared here because `tests/client.rs` compiles only what `tests/client/mod.rs` names — a
//! directory on disk that nothing declares is silently never built and never run.
pub mod batching_test;
pub mod e2e_test;
pub mod jetstream_test;
