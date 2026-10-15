//! SQS protocol E2E tests

pub mod e2e_test;

/// The first-byte deadline, the idle deadline and the connection cap, from the wire.
mod connection_bounds_test;
pub mod real_client_test;
